# v8_fuzzer.py — Adds direct model invocation to hit Product.save()

import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
import django
django.setup()

import json
import random
import hashlib
import logging
from io import BytesIO
from datetime import datetime
from django.test import RequestFactory
from rest_framework.request import Request
from rest_framework.parsers import JSONParser
from rest_framework import serializers
from django.http import Http404
from django.core.exceptions import ValidationError
from api.views import ProductView
from home.models import Product
from django.contrib.auth import get_user_model
import coverage
from rest_framework.renderers import JSONRenderer

# === Setup ===
cov = coverage.Coverage(data_file=".coverage_fuzz", source=["."])
cov.erase()
cov.start()

MAX_TEST_CASES = 100
MAX_INT = 2**31 - 1
MIN_INT = -2**31

INTERESTING_VALUES = [
    "", " ", None, 0, -9999, 1e100, "<script>alert(1)</script>",
    "' OR 1=1 --", "../../etc/passwd", "\ufffd" * 1000,
    True, False, "null", "undefined", "NaN", "Infinity", "A" * 2048,
    -((2**32)-1), 2**16, "0" * 8, "a" * 10**6, "x" * 128, "9" * 1024
]

os.makedirs("logs", exist_ok=True)
os.makedirs("crashes", exist_ok=True)
os.makedirs("semantic_bugs", exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"logs/fuzz_log_{timestamp}.log"
crash_log_file = f"logs/crashes_{timestamp}.log"
semantic_bug_file = f"logs/semantic_bugs_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler(log_file, encoding='utf-8'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

factory = RequestFactory()
view = ProductView()
User = get_user_model()
try:
    test_user = User.objects.get(username="testuser")
except User.DoesNotExist:
    test_user = User.objects.create_user(username="testuser", password="password")

def cleanup_test_products():
    Product.objects.filter(name__startswith="Test").delete()

cleanup_test_products()

def mutate_input(data):
    if not isinstance(data, dict): return data
    mutated = data.copy()
    mutable_fields = [k for k in mutated.keys() if k != "id"]
    if not mutable_fields: return mutated
    field = random.choice(mutable_fields)
    mutation_type = random.choice(["flip", "remove", "insert", "replace", "boundary"])

    if mutation_type == "flip" and isinstance(mutated[field], str) and mutated[field]:
        i = random.randint(0, len(mutated[field]) - 1)
        flipped = chr(ord(mutated[field][i]) ^ 1)
        mutated[field] = mutated[field][:i] + flipped + mutated[field][i + 1:]
    elif mutation_type == "remove":
        del mutated[field]
    elif mutation_type in ("insert", "replace"):
        mutated[field] = random.choice(INTERESTING_VALUES)
    elif mutation_type == "boundary" and isinstance(mutated[field], (int, float)):
        mutated[field] = random.choice([MAX_INT, MIN_INT, 0, 1, -1])
    return mutated

def assign_energy(test_case):
    base = random.randint(1, 3)
    complexity = len(json.dumps(test_case, default=str))
    bonus = min(5, complexity // 50)
    return base + bonus

def log_bug(op, fid, payload, issue, bug_type="crash"):
    bug_hash = hashlib.sha1(str(issue).encode()).hexdigest()[:8]
    folder = "crashes" if bug_type == "crash" else "semantic_bugs"
    path = f"{folder}/product_{op}_{bug_hash}.json"
    with open(path, "w") as f:
        json.dump({"operation": op, "fuzz_id": fid, "payload": payload, "issue": str(issue)}, f, indent=2)
    logger.warning(f"[!] {bug_type.upper()} LOGGED → {path}")
    with open(crash_log_file if bug_type == "crash" else semantic_bug_file, "a") as log_f:
        log_f.write(f"{path}\n")

def snapshot_db():
    return list(Product.objects.values())

def fetch_product_by_id(pid):
    try:
        obj = Product.objects.get(id=pid)
        return {"name": str(obj.name), "info": str(obj.info), "price": float(obj.price) if obj.price is not None else None}
    except Product.DoesNotExist:
        return None

def execute_test(t):
    op = random.choice(["post", "get", "put", "delete"])
    fid = t.get("id", random.randint(1, 999))
    try:
        if op == "post":
            t.pop("id", None)
            try:
                logger.debug("[→] DIRECT MODEL SAVE")
                p = Product(**t)
                p.save()
                class Dummy:
                    status_code = 200
                    content = b"direct"
                return op, fid, Dummy()
            except Exception as e:
                return op, fid, e
        elif op == "put":
            try:
                obj = Product.objects.get(id=fid)
                for k, v in t.items():
                    setattr(obj, k, v)
                obj.save()
                class Dummy:
                    status_code = 200
                    content = b"put"
                return op, fid, Dummy()
            except Exception as e:
                return op, fid, e
        else:
            # Keep old behavior for get/delete
            path = f"/api/product/{fid}/" if op == "get" else f"/api/product/{fid}/"
            req = factory.get(path) if op == "get" else factory.delete(path)
            req = Request(req)
            req.user = test_user
            view_fn = view.get if op == "get" else view.delete
            return op, fid, view_fn(req, pk=str(fid))
    except Exception as e:
        return op, fid, e

SeedQ = [
    {"name": "TestOOM", "info": "x", "price": -((2**32)-1)},
    {"name": "TestKill", "info": "12345678", "price": 16},
    {"name": "TestHugeName", "info": "test", "price": 10},
    {"name": "TestRegex", "info": "a" * 10**6, "price": 10},
    {"name": "ProductA", "info": "Test info", "price": 10.99}
]

seen_hashes = set()
test_cases_run = 0
mutation_stats = {}
FailureQ = []


while test_cases_run < MAX_TEST_CASES:
    seed = random.choice(SeedQ)
    energy = assign_energy(seed)

    for _ in range(energy):
        t = mutate_input(seed)
        mutation_fields = set(t.keys()) ^ set(seed.keys())
        for f in mutation_fields:
            mutation_stats[f] = mutation_stats.get(f, 0) + 1

        before_db = snapshot_db()
        expected_snapshot = {"name": str(t.get("name")), "info": str(t.get("info")), "price": float(t["price"]) if isinstance(t.get("price"), (int, float)) else None} if all(k in t for k in ("name", "info", "price")) else None

        op, fid, response = execute_test(t)
        after_db = snapshot_db()

        try:
            status = getattr(response, 'status_code', None)
            normalized_input = {k: str(v) for k, v in t.items() if k != "id"}
            cov_hash = hash(f"{status}:{json.dumps(normalized_input, sort_keys=True)}")

            if before_db != after_db and (status is None or status >= 400):
                raise AssertionError("BUG: DB state changed after unsuccessful request")

            if op in ["post", "put"] and status == 200 and expected_snapshot:
                actual = fetch_product_by_id(Product.objects.latest("id").id if op == "post" else fid)
                if actual and actual != expected_snapshot:
                    raise ValueError(f"Semantic Mismatch: Expected {expected_snapshot} but got {actual}")

            if cov_hash not in seen_hashes:
                seen_hashes.add(cov_hash)
                SeedQ.append(t)
                logger.info(f"[✓] NEW behavior → Status: {status}| Input: {json.dumps(t)}")
            else:
                logger.info(f"[-] Duplicate → Status: {status}| Input: {json.dumps(t)}")

        except (Http404, serializers.ValidationError, ValidationError) as known:
            logger.warning(f"[!] Known issue: {known}")
            FailureQ.append(("CRASH", t, str(known)))
            log_bug(op, fid, t, known, bug_type="crash")
        except ValueError as semantic:
            logger.warning(f"[!] Semantic mismatch: {semantic}")
            FailureQ.append(("SEMANTIC", t, str(semantic)))
            log_bug(op, fid, t, semantic, bug_type="semantic")
        except Exception as e:
            logger.error(f"[!] Unexpected error: {type(e).__name__}: {e}")
            FailureQ.append(("CRASH", t, str(e)))
            log_bug(op, fid, t, e, bug_type="crash")

        test_cases_run += 1

cleanup_test_products()
cov.stop()
cov.save()

print("\n==== FUZZING COMPLETE ====")
print(f"Total test cases executed: {test_cases_run}")
print(f"[+] Coverage HTML report saved to ./covhtml_fuzz")

print("\n=== MUTATION STATISTICS ===")
for field, count in sorted(mutation_stats.items(), key=lambda x: x[1], reverse=True):
    print(f"Field '{field}' mutated {count} times")

print("\n=== COVERAGE SUMMARY ===")
try:
    cov.report()
    cov.html_report(directory="covhtml_fuzz")
except Exception as e:
    print(f"[!] Could not generate coverage report: {e}")

if FailureQ:
    print("\n==== FAILURE SUMMARY ====")
    for typ, input_data, issue in FailureQ:
        print(f"[{typ}] {json.dumps(input_data)} → {issue}")
