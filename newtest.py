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

# === Logging Setup ===
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
MAX_TEST_CASES = 1000
INTERESTING_VALUES = [
    "", " ", None, 0, -1, 1e100, "<script>alert(1)</script>", "' OR 1=1 --",
    "../../etc/passwd", "\ufffd" * 1000, True, False, "null", "undefined",
    "NaN", "Infinity", "A" * 2048, 12345678901234567890, "🤯", {}, [],
    datetime.now().isoformat()
]

# === Helper Functions ===
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
    logger.warning(f"[BUG FOUND] {bug_type} saved to {path}")

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

# === Seed & Mutation Logic ===
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

def smart_mutate(field, val):
    field_lower = field.lower()
    if "date" in field_lower:
        return "2025-02-31"  # invalid date
    if isinstance(val, str):
        return random.choice([
            "", " ", val + "X", "A" * 256, "<script>", val[::-1],
            val + "\ufffd", "DROP TABLE users;", "🚀", "∞"
        ])
    elif isinstance(val, bool):
        return not val
    elif isinstance(val, int):
        return random.choice([-1, 0, 999999, val + 1])
    elif isinstance(val, float):
        return random.choice([-1e308, 1e308, float('nan'), float('inf')])
    return random.choice(INTERESTING_VALUES)

def mutate_input(data):
    mutated = data.copy()
    for field in random.sample(list(FIELDS.keys()), random.randint(1, len(FIELDS))):
        mutated[field] = smart_mutate(field, mutated.get(field))
    return mutated

# === New Interestingness Function ===
def is_interesting(test_case, result, previous_coverage):
    """
    Determine if a test case is interesting enough to keep in the population.
    
    Args:
        test_case: The input data that was used
        result: A dict containing information about the execution
        previous_coverage: Coverage signature from before this test case was executed
    
    Returns:
        Boolean indicating whether this test case is interesting
    """
    # New coverage is always interesting
    new_coverage = get_coverage_signature()
    if new_coverage != previous_coverage:
        return True
    
    # Cases that produced bugs are interesting
    if result.get("bug_found", False):
        return True
    
    # Cases that produce different serialization vs model behavior are interesting
    if result.get("serializer_model_diff", False):
        return True
    
    # Cases with unexpected validation errors might be interesting
    if result.get("unexpected_validation", False):
        return True
    
    # Edge cases for specific field types are interesting
    for field_name, value in test_case.items():
        field = FIELDS.get(field_name)
        if field and isinstance(field, models.CharField) and len(str(value)) > field.max_length - 10:
            return True  # Near boundary conditions are interesting
    
    # If the case is running through unusual code paths
    if result.get("unusual_path", False):
        return True
        
    return False

# === Energy Assignment Function ===
def assign_energy(test_case, result, history):
    """
    Assign an energy value to a test case to determine its probability of selection.
    Higher energy = higher probability of selection for mutation.
    
    Args:
        test_case: The input data that was used
        result: A dict containing information about the execution
        history: List of past results for this test case
    
    Returns:
        Float indicating the energy/priority of this test case
    """
    energy = 1.0  # Base energy
    
    # Reward test cases that found bugs
    if result.get("bug_found", False):
        energy *= 2.0
    
    # Reward test cases that discovered new coverage
    if result.get("new_coverage", False):
        energy *= 1.5
    
    # Reward test cases with interesting field values
    for field_name, value in test_case.items():
        # High priority for SQL injection attempts
        if isinstance(value, str) and ("'" in value or "--" in value or ";" in value):
            energy *= 1.2
        
        # High priority for XSS attempts
        if isinstance(value, str) and ("<script>" in value.lower() or "javascript:" in value.lower()):
            energy *= 1.2
            
        # Special values handling
        if value in (None, "", 0, -1):
            energy *= 1.1
    
    # Reduce energy for repeatedly uninteresting cases
    if history and not any(h.get("interesting", False) for h in history[-3:]):
        energy *= 0.5
    
    # Age decay - older test cases get less energy over time
    if history:
        age = len(history)
        energy *= max(0.5, 2.0 / (1 + 0.1 * age))
    
    return energy

# === Save Logic ===
def save_via_model(test_case):
    result = {"bug_found": False}
    try:
        product = Product.objects.create(**test_case)
        product.refresh_from_db()
        saved = normalize_dict({k: getattr(product, k, None) for k in FIELDS.keys()})
        expected = normalize_dict(test_case)
        if saved != expected:
            log_bug(expected, saved, "SemanticMismatch (Model)")
            result["bug_found"] = True
        product.delete()
    except (ValidationError, Exception) as e:
        log_bug(test_case, {"error": str(e)}, "Crash (Model)")
        result["bug_found"] = True
    return result

def save_via_serializer(test_case):
    result = {"bug_found": False}
    try:
        serializer = ProductSerializer(data=test_case)
        if serializer.is_valid():
            instance = serializer.save()
            saved = normalize_dict({k: getattr(instance, k, None) for k in FIELDS.keys()})
            expected = normalize_dict(test_case)
            if saved != expected:
                log_bug(expected, saved, "SemanticMismatch (Serializer)")
                result["bug_found"] = True
                result["serializer_model_diff"] = True
            instance.delete()
        else:
            # Check if this is an unusual validation error
            if len(serializer.errors) < len(FIELDS) // 2:
                result["unexpected_validation"] = True
            
            log_bug(test_case, {"errors": serializer.errors}, "ValidationError (Serializer)")
    except Exception as e:
        log_bug(test_case, {"error": str(e)}, "Crash (Serializer)")
        result["bug_found"] = True
    return result

def save_via_post(test_case):
    result = {"bug_found": False}
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
            result["bug_found"] = True
            
            # Check for unusual status codes that might indicate interesting bugs
            if response.status_code not in (400, 404, 500):
                result["unusual_path"] = True
    except Exception as e:
        log_bug(test_case, {"error": str(e)}, "Crash (View)")
        result["bug_found"] = True
    return result

# === Coverage Signature ===
coverage_hashes = set()
def get_coverage_signature():
    cov.stop()
    cov.save()
    data = cov.get_data()
    lines_covered = []
    for file in data.measured_files():
        lines = data.lines(file)
        if lines:
            lines_covered.extend((file, line) for line in lines)
    signature = hashlib.md5(str(sorted(lines_covered)).encode()).hexdigest()
    cov.start()
    return signature

# === Fuzz Loop with Energy-Based Selection ===
executed = 0
seed = generate_seed_from_model()
population = [{"data": seed, "energy": 1.0, "history": []}]
known_exceptions = set()

logger.info("Starting energy-based fuzzing with interestingness classification...")

while executed < MAX_TEST_CASES:
    # Select test case based on energy
    total_energy = sum(item["energy"] for item in population)
    selection_threshold = random.uniform(0, total_energy)
    
    current_sum = 0
    selected_idx = 0
    for idx, item in enumerate(population):
        current_sum += item["energy"]
        if current_sum >= selection_threshold:
            selected_idx = idx
            break
    
    selected = population[selected_idx]
    parent = selected["data"]
    mutated = mutate_input(parent)
    
    # Capture previous coverage
    previous_coverage = get_coverage_signature()
    
    # Execute test case
    model_result = save_via_model(mutated)
    serializer_result = save_via_serializer(mutated)
    post_result = save_via_post(mutated)
    
    # Combine results
    combined_result = {
        "bug_found": any(r.get("bug_found", False) for r in [model_result, serializer_result, post_result]),
        "serializer_model_diff": serializer_result.get("serializer_model_diff", False),
        "unexpected_validation": serializer_result.get("unexpected_validation", False),
        "unusual_path": post_result.get("unusual_path", False),
    }
    
    # Check for new coverage
    new_coverage = get_coverage_signature()
    combined_result["new_coverage"] = (new_coverage != previous_coverage)
    
    if combined_result["new_coverage"]:
        coverage_hashes.add(new_coverage)
    
    # Check if test case is interesting
    interesting = is_interesting(mutated, combined_result, previous_coverage)
    combined_result["interesting"] = interesting
    
    # Update history
    selected["history"].append(combined_result)
    
    # Add to population if interesting
    if interesting:
        test_history = [combined_result]
        energy = assign_energy(mutated, combined_result, test_history)
        population.append({"data": mutated, "energy": energy, "history": test_history})
    
    # Update energy for the parent
    selected["energy"] = assign_energy(parent, combined_result, selected["history"])
    
    # Occasionally prune low-energy test cases to prevent population explosion
    if len(population) > 100:
        population.sort(key=lambda x: x["energy"], reverse=True)
        population = population[:80]  # Keep top 80%
    
    executed += 1
    if executed % 10 == 0:
        logger.info(f"{executed} cases | Corpus: {len(population)} | Unique coverage: {len(coverage_hashes)}")

logger.info("Fuzzing complete.")

# === Final Coverage Report ===
cov.stop()
cov.save()
cov.html_report(directory='coverage_html_report')
logger.info("Coverage report saved to ./coverage_html_report/index.html")