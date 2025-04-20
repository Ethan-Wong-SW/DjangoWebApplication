import os
import sys
import django
import json
import random
import hashlib
import logging
from datetime import datetime
from django.core.exceptions import ValidationError
from django.test import Client
from django.db import models
import coverage

# === Coverage Setup ===
cov = coverage.Coverage(data_file=".coverage_fuzz", source=["."], branch=True)
cov.erase()
cov.start()

# === Django Setup ===
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from home.models import Product  # Adjust if needed
from api.serializers import ProductSerializer

client = Client()

# === Logging ===
os.makedirs("logs", exist_ok=True)
os.makedirs("bugs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/fuzz_{datetime.now():%Y%m%d%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# === Constants ===
MAX_TEST_CASES = 5000

INTERESTING_VALUES = [
    "", " ", None, 0, -9999, 1e100, "<script>alert(1)</script>",
    "' OR 1=1 --", "../../etc/passwd", "\ufffd" * 1000,
    True, False, "null", "undefined", "NaN", "Infinity", "A" * 2048,
    12345678901234567890, "🤯", {}, [], datetime.now().isoformat()
]

# === Helpers ===
def calculate_hash(obj):
    return hashlib.md5(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

def log_bug(input_data, db_data, bug_type):
    bug_id = calculate_hash({"input": input_data, "db": db_data})
    path = f"bugs/bug_{bug_id}.json"
    with open(path, "w") as f:
        json.dump({
            "type": bug_type,
            "input": input_data,
            "saved_in_db": db_data,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)
    logger.warning(f"[BUG FOUND] Mismatch saved to {path}")

def normalize(val):
    if isinstance(val, float) and (str(val) in ["nan", "inf", "-inf"]):
        return None
    if isinstance(val, (int, float, bool, str)) or val is None:
        return val
    return str(val)

def normalize_dict(d):
    return {k: normalize(v) for k, v in d.items() if k != "id"}

def get_model_fields(model):
    return {
        f.name: f for f in model._meta.get_fields()
        if isinstance(f, (models.CharField, models.TextField, models.FloatField,
                          models.BooleanField, models.IntegerField, models.DateField))
        and not f.auto_created and f.name != 'id'
    }

FIELDS = get_model_fields(Product)

# === Input Generation ===
def generate_seed_from_model():
    seed = {}
    for field_name, field in FIELDS.items():
        if isinstance(field, models.CharField):
            seed[field_name] = "text"
        elif isinstance(field, models.FloatField):
            seed[field_name] = 1.23
        elif isinstance(field, models.IntegerField):
            seed[field_name] = 1
        elif isinstance(field, models.BooleanField):
            seed[field_name] = False
        elif isinstance(field, models.DateField):
            seed[field_name] = datetime.now().date().isoformat()
        else:
            seed[field_name] = "default"
    return seed

def mutate_input(data):
    mutated = data.copy()
    num_fields = random.randint(1, len(FIELDS))
    for field in random.sample(list(FIELDS.keys()), num_fields):
        mutated[field] = random.choice(INTERESTING_VALUES)
    return mutated

# === Save Logic ===
def save_via_model(test_case):
    try:
        product = Product.objects.create(**test_case)
        product.refresh_from_db()
        saved = normalize_dict({k: getattr(product, k, None) for k in FIELDS.keys()})
        expected = normalize_dict(test_case)
        if saved != expected:
            log_bug(expected, saved, "SemanticMismatch (Model)")
        product.delete()
    except (ValidationError, Exception) as e:
        log_bug(test_case, {"error": str(e)}, "Crash (Model)")

def save_via_serializer(test_case):
    try:
        serializer = ProductSerializer(data=test_case)
        if serializer.is_valid():
            instance = serializer.save()
            saved = normalize_dict({k: getattr(instance, k, None) for k in FIELDS.keys()})
            expected = normalize_dict(test_case)
            if saved != expected:
                log_bug(expected, saved, "SemanticMismatch (Serializer)")
            instance.delete()
        else:
            log_bug(test_case, {"errors": serializer.errors}, "ValidationError (Serializer)")
    except Exception as e:
        log_bug(test_case, {"error": str(e)}, "Crash (Serializer)")

def save_via_post(test_case):
    try:
        response = client.post(
            "/datatb/product/add",
            data=json.dumps(test_case),
            content_type="application/json",
            **{"HTTP_HOST": "localhost"}
        )
        if response.status_code >= 400:
            log_bug(test_case, {
                "status": response.status_code,
                "response": response.content.decode()
            }, "Crash (View)")
    except Exception as e:
        log_bug(test_case, {"error": str(e)}, "Crash (View)")

# === Feedback Coverage ===
coverage_hashes = set()

def get_coverage_signature():
    cov.stop()
    cov.save()
    data = cov.get_data()
    lines_covered = []

    for file in data.measured_files():
        lines = data.lines(file)
        if lines:
            for line in lines:
                lines_covered.append((file, line))  # Always append a tuple

    signature = hashlib.md5(str(sorted(lines_covered)).encode()).hexdigest()
    cov.start()
    return signature

# === Main Fuzz Loop ===
executed = 0
seed = generate_seed_from_model()
population = [seed]

logger.info("Starting feedback-driven fuzzing with branch coverage...")

while executed < MAX_TEST_CASES:
    parent = random.choice(population)
    mutated = mutate_input(parent)

    save_via_model(mutated)
    save_via_serializer(mutated)
    save_via_post(mutated)

    signature = get_coverage_signature()
    if signature not in coverage_hashes:
        coverage_hashes.add(signature)
        population.append(mutated)

    executed += 1
    if executed % 100 == 0:
        logger.info(f"{executed} cases | Corpus: {len(population)} | Unique coverage: {len(coverage_hashes)}")

logger.info("Fuzzing complete.")

# === Final Coverage Report ===
cov.stop()
cov.save()
cov.html_report(directory='coverage_html_report')
logger.info("Coverage report saved to ./coverage_html_report/index.html")
