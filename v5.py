# v4_hybrid_fuzzer_final_reporting.py

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
from api.serializers import ProductSerializer
from home.models import Product
from django.contrib.auth import get_user_model
import coverage
from rest_framework.renderers import JSONRenderer

# === Setup ===
cov = coverage.Coverage(data_file=".coverage_fuzz", source=["."])
cov.erase()
cov.start()

MAX_TEST_CASES = 1000
MAX_INT = 2**31 - 1
MIN_INT = -2**31
INTERESTING_VALUES = [
    "", " ", None, 0, -9999, 1e100, "<script>alert(1)</script>",
    "' OR 1=1 --", "../../etc/passwd", "\ufffd" * 1000,
    True, False, "null", "undefined", "NaN", "Infinity", "A" * 2048,
"".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=2048)),

]

# Logging
os.makedirs("logs", exist_ok=True)
os.makedirs("crashes", exist_ok=True)
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
log_file = f"logs/fuzz_log_{timestamp}.log"
crash_log_file = f"logs/crashes_{timestamp}.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Django setup
factory = RequestFactory()
view = ProductView()
User = get_user_model()
try:
    test_user = User.objects.get(username="testuser")
except User.DoesNotExist:
    test_user = User.objects.create_user(username="testuser", password="password")

# === Utilities ===
def mutate_input(data):
    if not isinstance(data, dict):
        return data
    mutated = data.copy()
    if not mutated:
        return mutated
    field = random.choice(list(mutated.keys()))
    mutation_type = random.choice(["flip", "remove", "insert", "replace", "boundary"])
    if mutation_type == "flip" and isinstance(mutated[field], str) and mutated[field]:
        i = random.randint(0, len(mutated[field]) - 1)
        flipped = chr(ord(mutated[field][i]) ^ 1)
        mutated[field] = mutated[field][:i] + flipped + mutated[field][i + 1:]
    elif mutation_type == "remove":
        del mutated[field]
    elif mutation_type in ("insert", "replace"):
        if random.random() < 0.3:  # 30% chance to use long string
            mutated[field] = "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=random.randint(500, 3000)))
        else:
            mutated[field] = random.choice(INTERESTING_VALUES)
    elif mutation_type == "boundary" and isinstance(mutated[field], (int, float)):
        mutated[field] = random.choice([MAX_INT, MIN_INT, 0, 1, -1])
    return mutated

def assign_energy(test_case):
    base = random.randint(1, 3)
    complexity = len(json.dumps(test_case))
    bonus = min(5, complexity // 50)
    return base + bonus

def is_interesting(response):
    if isinstance(response, Exception):
        return False
    if getattr(response, 'status_code', 0) in {201, 202, 204, 301, 302}:
        return True
    try:
        data = json.loads(response.content.decode())
        return isinstance(data, dict) and len(data) > 2
    except:
        return False

def log_bug(op, fid, payload, issue):
    bug_hash = hashlib.sha1(str(issue).encode()).hexdigest()[:8]
    path = f"crashes/product_{op}_{bug_hash}.json"
    with open(path, "w") as f:
        json.dump({
            "operation": op,
            "fuzz_id": fid,
            "payload": payload,
            "issue": str(issue)
        }, f, indent=2)
    logger.warning(f"[!] BUG LOGGED → {path}")
    with open(crash_log_file, "a") as crash_f:
        crash_f.write(f"{path}\n")

def execute_test(t):
    op = random.choice(["post", "get", "put", "delete"])
    fid = t.get("id", random.randint(1, 999))
    try:
        if op == "post":
            req = factory.post("/api/product/", data=json.dumps(t), content_type="application/json")
            req._stream = BytesIO(json.dumps(t).encode())
            req = Request(req)
            req.parsers = [JSONParser()]
            req.user = test_user
            return op, fid, view.post(req)
        elif op == "get":
            path = f"/api/product/{fid}/" if random.random() < 0.5 else "/api/product/"
            req = factory.get(path)
            req = Request(req)
            req.user = test_user
            return op, fid, view.get(req, pk=str(fid)) if "product/" in path and str(fid) in path else view.get(req)
        elif op == "put":
            req = factory.put(f"/api/product/{fid}/", data=json.dumps(t), content_type="application/json")
            req._stream = BytesIO(json.dumps(t).encode())
            req = Request(req)
            req.parsers = [JSONParser()]
            req.user = test_user
            return op, fid, view.put(req, pk=str(fid))
        elif op == "delete":
            req = factory.delete(f"/api/product/{fid}/")
            req = Request(req)
            req.user = test_user
            return op, fid, view.delete(req, pk=str(fid))
    except Exception as e:
        return op, fid, e

def snapshot_db():
    return list(Product.objects.values())

# === Fuzz Loop ===
SeedQ = [
    {"id": 1, "name": "ProductA", "info": "Test info", "price": 10.99},
    {"id": 2, "name": "ProductB", "info": "Another product", "price": 99.99},
    {"id": 3, "name": "", "info": "Empty name test", "price": 5.99},
    {"id": 4, "name": "Price Test", "info": "Negative price", "price": -1.0},
    {"id": 5, "name": "No Info", "info": "", "price": 29.99},
    {"id": 6, "name": "🌟 Unicode Test", "info": "Emoji", "price": 12.34},
    {"id": 7, "name": "Injection Test", "info": "' OR 1=1 --", "price": 9.99},
    {"id": 8, "name": "<script>alert(1)</script>", "info": "XSS attempt", "price": 19.99},
    {"id": 9, "name": "Big JSON", "info": "x" * 5000, "price": 999999.99},
    {"id": 10, "name": None, "info": None, "price": None},
    {"id": 11, "name": {}, "info": [], "price": "NaN"},
    {"id": 12, "name": "Nested", "info": {"a": {"b": {"c": "deep"}}}, "price": 49.99},
    {"id": 13, "name": "", "info": None, "price": -9999999999},
    {"id": 14, "name": "Injection'; DROP TABLE Products;", "info": "<svg/onload=alert(1)>", "price": "undefined"},
    {"id": 15, "name": "🚀" * 500, "info": "🌟" * 1000, "price": 9999999999},
    {"id": 16, "name": "null", "info": "null", "price": "null"},
    {"id": 17, "name": "NaN", "info": "Not a number", "price": "NaN"},
    {"id": 18, "name": {"complex": "dict"}, "info": {"nested": ["list", "inside"]}, "price": [1, 2, 3]},
    {"id": 19, "name": 12345, "info": 67890, "price": "price?"},
    {"id": 20, "info": "Missing name", "price": 20.0},
    {"id": 21, "name": "Missing info"},
    {"id": 22, "name": "", "info": "", "price": ""}
]


seen_hashes = set()
test_cases_run = 0
unique_crashes_count = 0
duplicate_crashes_count = 0
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

        # Take snapshot before test
        before_db = snapshot_db()

        op, fid, response = execute_test(t)

        # Take snapshot after test
        after_db = snapshot_db()

        try:
            if hasattr(response, "render"):
                response.accepted_renderer = JSONRenderer()
                response.accepted_media_type = "application/json"
                response.renderer_context = {}
                response.render()

            status = getattr(response, 'status_code', None)
            content = getattr(response, 'content', b'').decode(errors='ignore')
            cov_hash = hash(f"{status}:{json.dumps(t, sort_keys=True)}")

            # Check for unexpected DB changes on non-success
            if before_db != after_db and (status is None or status >= 400):
                raise AssertionError("BUG: DB state changed after unsuccessful request")

            if cov_hash not in seen_hashes:
                seen_hashes.add(cov_hash)
                SeedQ.append(t)
                logger.info(f"[\u2713] NEW behavior → Status: {status}| Input: {json.dumps(t)}")
            elif is_interesting(response):
                logger.info(f"[+] INTERESTING input → Status: {status}| Input: {json.dumps(t)}")
                SeedQ.append(mutate_input(t))
            else:
                logger.info(f"[-] Duplicate → Status: {status}| Input: {json.dumps(t)}")

            if status and status >= 500:
                failure_hash = hashlib.sha1(str(response).encode()).hexdigest()[:8]
                if failure_hash not in seen_hashes:
                    unique_crashes_count += 1
                    FailureQ.append(("CRASH", t, str(response)))
                else:
                    duplicate_crashes_count += 1
                raise AssertionError(f"BUG: Server 500 Error: {status}")

        except (Http404, serializers.ValidationError, ValidationError) as known:
            logger.warning(f"[!] Known issue: {known}")
            log_bug(op, fid, t, known)
        except Exception as e:
            logger.error(f"[!] Unexpected error: {type(e).__name__}: {e}")
            log_bug(op, fid, t, e)

        test_cases_run += 1

# === Final Summary ===
cov.stop()
cov.save()

print("\n==== FUZZING COMPLETE ====")
print(f"Total test cases executed: {test_cases_run}")
print(f"Unique crashes found: {unique_crashes_count}")
print(f"Duplicate crashes/failures skipped: {duplicate_crashes_count}")
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
    print("\n==== CRASH SUMMARY ====")
    crash_count = sum(1 for f in FailureQ if f[0] == "CRASH")
    print(f"Found {crash_count} unique crashes")
    print(f"See '{crash_log_file}' for full details")
