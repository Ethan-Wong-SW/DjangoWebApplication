import os
import sys
import django
import json
import random
import hashlib
import logging
import time
import shutil
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
os.makedirs("crashes", exist_ok=True)  # Create separate directory for crashes
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(f"logs/fuzz_{datetime.now():%Y%m%d%H%M%S}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Django Model Fuzzer')
    parser.add_argument('--max-tests', type=int, default=5000,
                      help='Maximum number of test cases to execute')
    parser.add_argument('--run-indefinitely', action='store_true',
                      help='Run until manually stopped (overrides max-tests)')
    return parser.parse_args()

args = parse_args()

def relaxed_equal(a, b):
    # Treat numerics and string numerics as equal (e.g., 10.09 vs "10.09")
    if isinstance(a, (int, float)) and isinstance(b, str):
        try:
            return str(a) == b or float(b) == a
        except Exception:
            return False
    if isinstance(b, (int, float)) and isinstance(a, str):
        try:
            return str(b) == a or float(a) == b
        except Exception:
            return False
    return a == b


# === Archive and clear bugs/crashes folders before each run ===
def archive_and_clear(folder):
    if os.path.exists(folder):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        archive_name = f"archive_{folder}_{timestamp}"
        shutil.move(folder, archive_name)
        logger.info(f"Archived old {folder} to {archive_name}")
    os.makedirs(folder, exist_ok=True)

archive_and_clear("bugs")
archive_and_clear("crashes")

# === Constants ===
INTERESTING_VALUES = [
    "", " ", None, 0, -1, 1e100, "<script>alert(1)</script>", "' OR 1=1 --",
    "../../etc/passwd", "\ufffd" * 1000, True, False, "null", "undefined",
    "NaN", "Infinity", "A" * 2048, 12345678901234567890, "🤯", {}, [],
    datetime.now().isoformat(), 10.09, 10.999
]

class AdaptiveMutator:
    def __init__(self):
        self.strategies = {
            'boundary': {'weight': 1.0, 'success_count': 0, 'attempt_count': 0},
            'type_conversion': {'weight': 1.0, 'success_count': 0, 'attempt_count': 0},
            'injection': {'weight': 1.0, 'success_count': 0, 'attempt_count': 0},
            'unicode': {'weight': 1.0, 'success_count': 0, 'attempt_count': 0},
            'overflow': {'weight': 1.0, 'success_count': 0, 'attempt_count': 0}
        }
        
    def update_weights(self, strategy, success):
        """Update weights based on success/failure."""
        if strategy not in self.strategies:
            return
            
        self.strategies[strategy]['attempt_count'] += 1
        if success:
            self.strategies[strategy]['success_count'] += 1
            
        # Recalculate weights periodically
        if sum(s['attempt_count'] for s in self.strategies.values()) % 20 == 0:
            self._recalculate_weights()
    
    def _recalculate_weights(self):
        """Adjust weights based on success rates."""
        for strategy, data in self.strategies.items():
            if data['attempt_count'] > 0:
                success_rate = data['success_count'] / data['attempt_count']
                # Apply smoothing to prevent any strategy from being completely ignored
                data['weight'] = 0.2 + (0.8 * success_rate)
    
    def select_strategy(self):
        """Select a mutation strategy based on weights."""
        strategies = list(self.strategies.keys())
        weights = [self.strategies[s]['weight'] for s in strategies]
        return random.choices(strategies, weights=weights)[0]
        
    def mutate(self, field_name, value, field_metadata):
        """Apply a weighted random mutation strategy."""
        strategy = self.select_strategy()
        
        if strategy == 'boundary':
            return self._boundary_mutation(field_metadata)
        elif strategy == 'type_conversion':
            return self._type_conversion(value, field_metadata)
        elif strategy == 'injection':
            return self._injection_mutation(field_metadata)
        elif strategy == 'unicode':
            return self._unicode_mutation(field_metadata)
        elif strategy == 'overflow':
            return self._overflow_mutation(field_metadata)
        
        return value
        
    def _boundary_mutation(self, metadata):
        if metadata['type'] == 'CharField':
            if 'max_length' in metadata:
                # Test exactly at, just below, and just above max_length
                return random.choice([
                    "A" * (metadata['max_length']),
                    "A" * (metadata['max_length'] - 1),
                    "A" * (metadata['max_length'] + 1)
                ])
        elif metadata['type'] in ('IntegerField', 'FloatField'):
            return random.choice([0, -1, 1, 2**31-1, -(2**31)])
        return None
        
    def _type_conversion(self, value, metadata):
        # Implement type conversion mutations
        # For example, convert strings to numbers, numbers to strings, etc.
        return value
        
    def _injection_mutation(self, metadata):
        # Implement SQL/XSS/command injection mutations
        injections = [
            "' OR '1'='1", 
            "'; DROP TABLE products; --",
            "<script>alert(1)</script>",
            "../../etc/passwd",
            "$(cat /etc/passwd)"
        ]
        return random.choice(injections)
        
    def _unicode_mutation(self, metadata):
        # Implement unicode edge cases
        return "\ufffd" * random.randint(1, 1000)
        
    def _overflow_mutation(self, metadata):
        # Implement overflow cases
        if metadata['type'] in ('IntegerField', 'FloatField'):
            return random.choice([
                2**31 - 1,  # Max int32
                -(2**31),   # Min int32
                2**63 - 1,  # Max int64
                -(2**63),   # Min int64
                -((2**32) - 1)  # Your original memory bomb value
            ])
        return "A" * 10000  # String overflow
    
class FuzzSequence:
    def __init__(self, model_class):
        self.model_class = model_class
        self.current_id = None
        self.current_data = None
        
    def generate_sequence(self, length=3):
        """Generate a test sequence of operations."""
        operations = []
        # First operation is always create
        operations.append('create')
        
        # Remaining operations
        for _ in range(length - 1):
            if not self.current_id:
                # Can't update/delete/read if we haven't created yet
                operations.append('create')
            else:
                operations.append(random.choice(['read', 'update', 'delete', 'create']))
                
        return operations
        
    def execute_sequence(self, sequence):
        """Execute a sequence of operations, reporting bugs."""
        issues_found = []
        
        for operation in sequence:
            if operation == 'create':
                # Generate a new test case
                test_case = mutate_input(generate_seed_from_model())
                result = save_via_model(test_case)
                if result.get('issue_found'):
                    issues_found.append(('create', test_case, result))
                else:
                    # Store for future operations
                    self.current_data = test_case
                    try:
                        # Get the ID of the newly created object
                        created_obj = Product.objects.filter(**{k: v for k, v in test_case.items() if v is not None}).first()
                        if created_obj:
                            self.current_id = created_obj.id
                    except Exception:
                        pass
                    
            elif operation == 'read':
                try:
                    instance = self.model_class.objects.get(id=self.current_id)
                    for field, value in self.current_data.items():
                        if normalize(getattr(instance, field)) != normalize(value):
                            issues_found.append(('read', 
                                              {'expected': self.current_data, 'actual': instance.__dict__},
                                              {'issue_type': 'DataInconsistency', 'category': 'bug'}))
                except Exception as e:
                    issues_found.append(('read', {'id': self.current_id}, 
                                        {'error': str(e), 'category': 'crash'}))
                    
            elif operation == 'update':
                try:
                    # Mutate some fields
                    update_data = self.current_data.copy()
                    fields_to_update = random.sample(list(update_data.keys()), 
                                                   min(2, len(update_data)))
                    for field in fields_to_update:
                        update_data[field] = smart_mutate(field, update_data[field])
                        
                    # Perform update
                    instance = self.model_class.objects.get(id=self.current_id)
                    for field, value in update_data.items():
                        setattr(instance, field, value)
                    instance.save()
                    
                    # Check if update worked
                    instance.refresh_from_db()
                    for field, value in update_data.items():
                        if normalize(getattr(instance, field)) != normalize(value):
                            issues_found.append(('update', 
                                             {'expected': update_data, 'actual': instance.__dict__},
                                             {'issue_type': 'UpdateFailure', 'category': 'bug'}))
                            
                    # Update current data
                    self.current_data = update_data
                    
                except Exception as e:
                    issues_found.append(('update', update_data, 
                                       {'error': str(e), 'category': 'crash'}))
                    
            elif operation == 'delete':
                try:
                    instance = self.model_class.objects.get(id=self.current_id)
                    instance.delete()
                    
                    # Verify deletion
                    if self.model_class.objects.filter(id=self.current_id).exists():
                        issues_found.append(('delete', 
                                         {'id': self.current_id},
                                         {'issue_type': 'DeletionFailure', 'category': 'bug'}))
                    
                    # Reset current state
                    self.current_id = None
                    self.current_data = None
                    
                except Exception as e:
                    issues_found.append(('delete', {'id': self.current_id}, 
                                       {'error': str(e), 'category': 'crash'}))
                    
        return issues_found

# === Helper Functions ===
def calculate_hash(obj):
    """Generate a stable hash for deduplication purposes"""
    return hashlib.md5(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()

def log_issue(input_data, result_data, issue_type, issue_category):
    """Log issues with separate directories for crashes and bugs"""
    hash_data = {"input": input_data, "result": result_data, "type": issue_type}
    issue_id = calculate_hash(hash_data)
    
    # Determine target directory based on category
    target_dir = "crashes" if issue_category == "crash" else "bugs"
    timestamp = datetime.now().isoformat()
    
    # Create descriptive filename
    issue_source = issue_type.split(' ')[0] if ' ' in issue_type else "general"
    filename = f"{issue_source}_{issue_id[:8]}_{timestamp.replace(':', '-')}.json"
    path = f"{target_dir}/{filename}"
    
    # Prepare issue data with detailed metadata
    issue_data = {
        "issue_id": issue_id,
        "issue_type": issue_type,
        "category": issue_category,
        "timestamp": timestamp,
        "input_data": input_data,
        "result_data": result_data,
        "reproduction_count": 1  # For tracking how often this issue occurs
    }
    
    # Check if this exact issue was logged before
    existing_file = None
    for f in os.listdir(target_dir):
        if issue_id[:8] in f:
            existing_file = f"{target_dir}/{f}"
            break
    
    if existing_file:
        # Update existing issue entry
        try:
            with open(existing_file, 'r') as f:
                existing_data = json.load(f)
                existing_data["reproduction_count"] += 1
                existing_data["last_seen"] = timestamp
                # Keep track of different inputs that cause the same issue
                if "additional_inputs" not in existing_data:
                    existing_data["additional_inputs"] = []
                if len(existing_data["additional_inputs"]) < 5:  # Limit to prevent huge files
                    existing_data["additional_inputs"].append(input_data)
            
            with open(existing_file, 'w') as f:
                json.dump(existing_data, f, indent=2)
            
            logger.warning(f"[{issue_category.upper()}] {issue_type} seen again (#{existing_data['reproduction_count']}) - {existing_file}")
            return existing_file
        except Exception as e:
            logger.error(f"Error updating existing issue: {e}")
    
    # Write new issue file
    with open(path, "w") as f:
        json.dump(issue_data, f, indent=2)
    
    # Log based on category for better visibility in log files
    if issue_category == "crash":
        logger.error(f"[CRASH] {issue_type} saved to {path}")
    else:
        logger.warning(f"[BUG] {issue_type} saved to {path}")
    
    return path

# def normalize(val):
#     if isinstance(val, float) and (str(val) in ["nan", "inf", "-inf"]):
#         return None
#     if isinstance(val, str):
#         # Try parsing numeric strings to float for fair comparison
#         try:
#             if '.' in val or val.isdigit():
#                 return float(val)
#         except ValueError:
#             pass
#     if isinstance(val, (int, float, bool, str)) or val is None:
#         return val
#     return str(val)
def normalize(val):
    if isinstance(val, float) and (str(val) in ["nan", "inf", "-inf"]):
        return None
    if isinstance(val, (int, float, bool, str)) or val is None:
        return val
    return str(val)

def normalize_dict(d):
    return {k: normalize(v) for k, v in d.items() if k != "id"}

def get_all_models():
    """Get all registered models in the Django application."""
    return django.apps.apps.get_models()

def get_field_metadata(field):
    """Extract metadata about a field for smarter fuzzing."""
    metadata = {
        'type': field.__class__.__name__,
        'null': field.null,
        'blank': getattr(field, 'blank', False),
    }
    
    # Add specific field type constraints
    if hasattr(field, 'max_length'):
        metadata['max_length'] = field.max_length
    if hasattr(field, 'choices') and field.choices:
        metadata['choices'] = [choice[0] for choice in field.choices]
    if hasattr(field, 'validators'):
        metadata['validators'] = [v.__class__.__name__ for v in field.validators]
    if hasattr(field, 'min_value'):
        metadata['min_value'] = field.min_value
    if hasattr(field, 'max_value'):
        metadata['max_value'] = field.max_value
        
    return metadata

def get_model_metadata(model):
    """Get complete metadata for a model to guide fuzzing."""
    fields = {}
    for field in model._meta.get_fields():
        if not field.auto_created and field.name != 'id':
            fields[field.name] = get_field_metadata(field)
    return fields

# Replace hardcoded FIELDS with dynamic resolution
FIELDS = get_model_metadata(Product)

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

# Pull real examples from the database
def generate_seed_from_existing_data(n=5):
    examples = Product.objects.all()[:n]
    return [normalize_dict({k: getattr(p, k) for k in FIELDS}) for p in examples]

# Initialize the adaptive mutator
adaptive_mutator = AdaptiveMutator()
# grammar_fuzzer = GrammarFuzzer()

def smart_mutate(field, val):
    """
    Generate only valid-typed values, but hit deeper model logic
    """
    field = field.lower()
    field_metadata = FIELDS.get(field, {})
    
    # Sometimes use the grammar fuzzer for string fields
    # if isinstance(val, str) and random.random() < 0.3:
    #     return grammar_fuzzer.generate(field)
    if isinstance(val, str) and random.random() < 0.2:
        return random.choice(INTERESTING_VALUES)
        
    # Sometimes use the adaptive mutator
    if random.random() < 0.4:
        return adaptive_mutator.mutate(field, val, field_metadata)
    
    # Otherwise, keep using your existing targeted mutations
    if field == "name":
        return random.choice([
            "a",          # trivial valid
            "aa",         # matches (a+)+$ → validate_name passes
            "bb",         # fails regex → validate_name prints "Invalid name"
        ])

    if field == "info":
        return random.choice([
            "",  # default valid
            "ab",    # passes regex: letters only
            "12",    # numeric → passes shallow serializer but fails validate_info
        ])

    if field == "price":
        return random.choice([
            None,       # test null branch
            0,          # base
            16,         # cheap branch for SIGTERM if info digits
            2**16,      # triggers sleep 60% calls
            -((2**32)-1)  # arms var_flag → memory bomb later
        ])

    # fallback (shouldn't happen)
    return val

def mutate_input(data):
    mutated = data.copy()

    # Occasionally inject full logic bomb combo
    if random.random() < 0.2:
        combo = random.choice([
            {"name": "aa", "info": "12345678", "price": 16},        # SIGTERM combo
            {"name": "a" * 129, "info": "abcdefabcdef", "price": 2**16},  # SIGKILL + sleep
            {"name": "aa", "info": "info", "price": -((2**32) - 1)}       # var_flag
        ])
        mutated.update(combo)
        return mutated

    # Otherwise mutate randomly
    for field in random.sample(list(FIELDS.keys()), random.randint(1, len(FIELDS))):
        mutated[field] = smart_mutate(field, mutated.get(field))
    return mutated

# === Progress Tracking Class ===
class FuzzProgress:
    def __init__(self, window_size=50):
        self.window_size = window_size
        self.bugs_found = []
        self.coverage_points = []
        self.start_time = time.time()
        
    def update(self, bug_found, new_coverage):
        # Add current state
        self.bugs_found.append(1 if bug_found else 0)
        self.coverage_points.append(1 if new_coverage else 0)
        
        # Trim to window size
        if len(self.bugs_found) > self.window_size:
            self.bugs_found.pop(0)
            self.coverage_points.pop(0)
    
    def should_continue(self, max_tests):
        """Determine if fuzzing should continue based on progress"""
        # Always run at least window_size tests
        if len(self.bugs_found) < self.window_size:
            return True
            
        # If we're still finding bugs or new coverage, continue
        bugs_in_window = sum(self.bugs_found)
        coverage_in_window = sum(self.coverage_points)
        
        if bugs_in_window > 0 or coverage_in_window > 0:
            return True
            
        # If we've been running for less than 30 minutes, continue
        running_time = time.time() - self.start_time
        if running_time < 1800:  # 30 minutes in seconds
            return True
            
        # Otherwise, consider diminishing returns
        return False
        
    def get_stats(self):
        """Return current statistics"""
        total_bugs = sum(self.bugs_found)
        total_coverage = sum(self.coverage_points)
        running_time = time.time() - self.start_time
        
        return {
            "bugs_in_window": sum(self.bugs_found[-min(len(self.bugs_found), 10):]),
            "coverage_in_window": sum(self.coverage_points[-min(len(self.coverage_points), 10):]),
            "total_bugs": total_bugs,
            "total_coverage_points": total_coverage,
            "running_time": running_time
        }

# === New Interestingness Function ===
def is_interesting(test_case, result, previous_coverage):
    # New coverage is always interesting
    new_coverage = get_coverage_signature()
    if new_coverage != previous_coverage:
        return True
    
    # Cases that produced issues are interesting
    if result.get("issue_found", False):
        return True
    
    # Cases that produce different serialization vs model behavior are interesting
    if result.get("serializer_model_diff", False):
        return True
    
    # Cases with unexpected validation errors might be interesting
    if result.get("unexpected_validation", False):
        return True
    
    # Edge cases for specific field types are interesting
    for field_name, value in test_case.items():
        field_metadata = FIELDS.get(field_name, {})
        field_type = field_metadata.get('type', '')
        
        if field_type == 'CharField' and isinstance(value, str):
            max_length = field_metadata.get('max_length', 0)
            if max_length > 0 and len(value) > max_length - 10:
                return True  # Near boundary conditions are interesting
    
    # If the case is running through unusual code paths
    if result.get("unusual_path", False):
        return True
        
    return False

# === Energy Assignment Function ===
def assign_energy(test_case, result, history):
    energy = 1.0  # Base energy
    
    # Reward test cases that found issues
    if result.get("issue_found", False):
        energy *= 2.0
    
    # Reward test cases that discovered new coverage
    if result.get("new_coverage", False):
        energy *= 1.5

    if not result.get("unexpected_validation", False):
        energy *= 1.3
    
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
    result = {"issue_found": False, "category": None}
    try:
        product = Product.objects.create(**test_case)
        product.refresh_from_db()
        saved = normalize_dict({k: getattr(product, k, None) for k in FIELDS.keys()})
        expected = normalize_dict(test_case)
        if any(not relaxed_equal(saved.get(k), expected.get(k)) for k in expected):
            log_issue(expected, saved, "SemanticMismatch (Model)", "bug")
            result["issue_found"] = True
            result["category"] = "bug"
        product.delete()
    except ValidationError as e:
        # ValidationErrors are bugs, not crashes
        log_issue(test_case, {"validation_error": str(e)}, "ValidationError (Model)", "bug")
        result["issue_found"] = True
        result["category"] = "bug"
    except Exception as e:
        # Other exceptions are crashes
        log_issue(test_case, {"error": str(e), "error_type": e.__class__.__name__}, "Exception (Model)", "crash")
        result["issue_found"] = True 
        result["category"] = "crash"
    return result

def save_via_serializer(test_case):
    result = {"issue_found": False, "category": None}
    try:
        serializer = ProductSerializer(data=test_case)
        if serializer.is_valid():
            instance = serializer.save()
            saved = normalize_dict({k: getattr(instance, k, None) for k in FIELDS.keys()})
            expected = normalize_dict(test_case)
            if saved != expected:
                log_issue(expected, saved, "SemanticMismatch (Serializer)", "bug")
                result["issue_found"] = True
                result["category"] = "bug"
                result["serializer_model_diff"] = True
            instance.delete()
        else:
            # Check if this is an unusual validation error
            if len(serializer.errors) < len(FIELDS) // 2:
                result["unexpected_validation"] = True
            
            log_issue(test_case, {"errors": serializer.errors}, "ValidationError (Serializer)", "bug")
            result["issue_found"] = True
            result["category"] = "bug"
    except Exception as e:
        log_issue(test_case, {"error": str(e), "error_type": e.__class__.__name__}, "Exception (Serializer)", "crash")
        result["issue_found"] = True
        result["category"] = "crash"
    return result

def save_via_post(test_case):
    result = {"issue_found": False, "category": None}
    try:
        response = client.post(
            "/datatb/product/add",
            data=json.dumps(test_case),
            content_type="application/json",
            **{"HTTP_HOST": "localhost"}
        )
        
        # Handle HTTP error responses (400+ status codes)
        if 400 <= response.status_code < 500:
            # Client errors are typically bugs in input validation
            log_issue(test_case, {
                "status": response.status_code,
                "response": response.content.decode()
            }, f"ClientError_{response.status_code} (View)", "bug")
            result["issue_found"] = True
            result["category"] = "bug"
            
        elif response.status_code >= 500:
            # Server errors are crashes
            log_issue(test_case, {
                "status": response.status_code,
                "response": response.content.decode()
            }, f"ServerError_{response.status_code} (View)", "crash")
            result["issue_found"] = True
            result["category"] = "crash"
            
        # Check for unusual status codes that might indicate interesting bugs
        if response.status_code not in (200, 201, 400, 404, 500):
            result["unusual_path"] = True
            
    except Exception as e:
        log_issue(test_case, {"error": str(e), "error_type": e.__class__.__name__}, "Exception (View)", "crash")
        result["issue_found"] = True
        result["category"] = "crash"
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

def check_stop_conditions():
    """Check if we should stop fuzzing"""
    # Add your custom stop conditions here if needed
    return False

# === Summary Report Generation ===
def generate_summary_report(unique_bugs, unique_crashes):
    """Generate a summary report of all issues found"""
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    summary_path = f"logs/summary_{timestamp}.json"
    
    # Collect bug info
    bug_summary = {}
    for bug_file in os.listdir("bugs"):
        try:
            with open(f"bugs/{bug_file}", 'r') as f:
                bug_data = json.load(f)
                bug_type = bug_data.get('issue_type', 'Unknown')
                if bug_type not in bug_summary:
                    bug_summary[bug_type] = {
                        'count': 0,
                        'examples': []
                    }
                bug_summary[bug_type]['count'] += 1
                if len(bug_summary[bug_type]['examples']) < 3:  # Limit examples
                    bug_summary[bug_type]['examples'].append(bug_file)
        except Exception as e:
            logger.error(f"Error processing bug file {bug_file}: {e}")
    
    # Collect crash info
    crash_summary = {}
    for crash_file in os.listdir("crashes"):
        try:
            with open(f"crashes/{crash_file}", 'r') as f:
                crash_data = json.load(f)
                crash_type = crash_data.get('issue_type', 'Unknown')
                if crash_type not in crash_summary:
                    crash_summary[crash_type] = {
                        'count': 0,
                        'examples': []
                    }
                crash_summary[crash_type]['count'] += 1
                if len(crash_summary[crash_type]['examples']) < 3:  # Limit examples
                    crash_summary[crash_type]['examples'].append(crash_file)
        except Exception as e:
            logger.error(f"Error processing crash file {crash_file}: {e}")
    
    summary = {
        'timestamp': timestamp,
        'tests_executed': executed,
        'unique_bugs': len(unique_bugs),
        'unique_crashes': len(unique_crashes),
        'coverage_points': len(coverage_hashes),
        'runtime_seconds': time.time() - start_time,
        'bug_summary': bug_summary,
        'crash_summary': crash_summary
    }
    
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"Summary report generated: {summary_path}")
    
    # Generate a text report for easier reading
    text_report_path = f"logs/summary_{timestamp}.txt"
    with open(text_report_path, 'w') as f:
        f.write(f"=== Django Fuzzer Summary Report ===\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Tests executed: {executed}\n")
        f.write(f"Runtime: {(time.time() - start_time) / 60:.2f} minutes\n\n")
        
        f.write(f"COVERAGE:\n")
        f.write(f"- Unique code paths: {len(coverage_hashes)}\n\n")
        
        f.write(f"ISSUES FOUND:\n")
        f.write(f"- Unique bugs: {len(unique_bugs)}\n")
        f.write(f"- Unique crashes: {len(unique_crashes)}\n\n")
        
        # Print bug details
        f.write(f"BUG TYPES:\n")
        for bug_type, data in bug_summary.items():
            f.write(f"- {bug_type}: {data['count']} occurrences\n")
            f.write(f"  Examples: {', '.join(data['examples'][:3])}\n")
        f.write("\n")
        
        # Print crash details
        f.write(f"CRASH TYPES:\n")
        for crash_type, data in crash_summary.items():
            f.write(f"- {crash_type}: {data['count']} occurrences\n")
            f.write(f"  Examples: {', '.join(data['examples'][:3])}\n")
    
    logger.info(f"Text summary report generated: {text_report_path}")

def print_summary(executed, start_time, unique_bugs, unique_crashes, seed_corpus, test_corpus):
    print("\n=== FUZZING SUMMARY ===")
    print(f"Total tests executed: {executed}")
    print(f"Runtime: {(time.time() - start_time) / 60:.2f} minutes")
    print(f"Unique bugs found: {len(unique_bugs)}")
    print(f"Unique crashes found: {len(unique_crashes)}")
    print(f"Unique code paths explored: {len(coverage_hashes)}")
    print(f"Final Corpus Summary → Seed Corpus: {len(seed_corpus)} | Test Corpus: {len(test_corpus)} | Total Corpus: {len(seed_corpus) + len(test_corpus)}")
    print(f"Bug reports location: ./bugs/")
    print(f"Crash reports location: ./crashes/")
    print(f"Summary reports: ./logs/")
    print(f"Coverage report: ./coverage_html_report/index.html")
    print("=====================")

def main():
    archive_and_clear("bugs")
    archive_and_clear("crashes")
    
    # === Main Fuzz Loop with Energy-Based Selection ===

    seen_hashes = set()
    executed = 0
    start_time = time.time()
    seeds = generate_seed_from_existing_data() + [generate_seed_from_model() for _ in range(5)]
    seed_corpus = [{"data": s, "energy": 1.0, "history": []} for s in seeds]
    test_corpus = [] 
    population = seed_corpus + test_corpus 
    seen_hashes = {calculate_hash(s) for s in seeds}

    logger.info(f"Seed Corpus: {len(seed_corpus)} entries loaded.")


    known_exceptions = set()

    logger.info("Starting energy-based fuzzing with improved issue logging...")
    logger.info(f"Bugs will be logged to ./bugs/ directory")
    logger.info(f"Crashes will be logged to ./crashes/ directory")

    # Initialize components
    sequence_tester = FuzzSequence(Product)
    progress_tracker = FuzzProgress(window_size=50)

    # Stats tracking
    bugs_found = 0
    crashes_found = 0
    unique_bugs = set()
    unique_crashes = set()

    try:
        while True:
            # Check stop conditions
            if check_stop_conditions():
                break
                
            if not args.run_indefinitely:
                if executed >= args.max_tests:
                    logger.info(f"Completed {args.max_tests} test cases")
                    break
                    
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
            
            # Track issues
            if model_result.get("issue_found", False):
                if model_result.get("category") == "bug":
                    bugs_found += 1
                    hash_key = f"model_bug_{calculate_hash(mutated)}"
                    unique_bugs.add(hash_key)
                else:  # crash
                    crashes_found += 1
                    hash_key = f"model_crash_{calculate_hash(mutated)}"
                    unique_crashes.add(hash_key)
                    
            if serializer_result.get("issue_found", False):
                if serializer_result.get("category") == "bug":
                    bugs_found += 1
                    hash_key = f"serializer_bug_{calculate_hash(mutated)}"
                    unique_bugs.add(hash_key)
                else:  # crash
                    crashes_found += 1
                    hash_key = f"serializer_crash_{calculate_hash(mutated)}"
                    unique_crashes.add(hash_key)
                    
            if post_result.get("issue_found", False):
                if post_result.get("category") == "bug":
                    bugs_found += 1
                    hash_key = f"view_bug_{calculate_hash(mutated)}"
                    unique_bugs.add(hash_key)
                else:  # crash
                    crashes_found += 1
                    hash_key = f"view_crash_{calculate_hash(mutated)}"
                    unique_crashes.add(hash_key)
            
            # Combine results
            combined_result = {
                "issue_found": any(r.get("issue_found", False) for r in [model_result, serializer_result, post_result]),
                "serializer_model_diff": serializer_result.get("serializer_model_diff", False),
                "unexpected_validation": serializer_result.get("unexpected_validation", False),
                "unusual_path": post_result.get("unusual_path", False),
            }

            # Check for new coverage
            new_coverage = get_coverage_signature()
            combined_result["new_coverage"] = (new_coverage != previous_coverage)

            progress_tracker.update(combined_result["issue_found"], combined_result["new_coverage"])
            
            if combined_result["new_coverage"]:
                coverage_hashes.add(new_coverage)
            
            # Check if test case is interesting
            interesting = is_interesting(mutated, combined_result, previous_coverage)
            combined_result["interesting"] = interesting
            
            # Update history
            selected["history"].append(combined_result)
            
            # Add to population if interesting
            if interesting:
                test_hash = calculate_hash(mutated)
                if test_hash not in seen_hashes:
                    test_history = [combined_result]
                    energy = assign_energy(mutated, combined_result, test_history)
                    test_corpus.append({"data": mutated, "energy": energy, "history": test_history})
                    seen_hashes.add(test_hash)
                    logger.info(f"[CORPUS APPEND] New TEST input added | Hash: {test_hash[:8]} | Test Corpus: {len(test_corpus)} | Executed: {executed}")

            
            # Update energy for the parent
            selected["energy"] = assign_energy(parent, combined_result, selected["history"])
            
            # Occasionally prune low-energy test cases to prevent population explosion
            if len(population) > 100:
                population.sort(key=lambda x: x["energy"], reverse=True)
                population = population[:80]  # Keep top 80%
            
            executed += 1
            
            # Periodic logging of progress
            if executed % 10 == 0:
                stats = progress_tracker.get_stats()
                logger.info(
                    f"Tests: {executed} | "
                    f"Test Corpus: {len(test_corpus)} | "
                    f"Coverage: {len(coverage_hashes)} | "
                    f"Bugs: {len(unique_bugs)} | Crashes: {len(unique_crashes)}"
                )

            # Occasionally run sequence tests
            if executed % 20 == 0:
                sequence = sequence_tester.generate_sequence(length=random.randint(3, 5))
                sequence_issues = sequence_tester.execute_sequence(sequence)
                for op, data, result in sequence_issues:
                    issue_category = result.get('category', 'bug') 
                    issue_type = result.get('issue_type', f"SequenceIssue ({op})")
                    log_issue(data, result, issue_type, issue_category)
                    
                    # Track in stats
                    if issue_category == 'bug':
                        bugs_found += 1
                        unique_bugs.add(f"sequence_bug_{calculate_hash(data)}")
                    else:
                        crashes_found += 1
                        unique_crashes.add(f"sequence_crash_{calculate_hash(data)}")

            # Report for indefinite mode
            if args.run_indefinitely and executed % 100 == 0:
                hours_running = (time.time() - start_time) / 3600
                logger.info(
                    f"INDEFINITE MODE: {hours_running:.2f} hours | "
                    f"{executed} tests | {len(coverage_hashes)} paths | "
                    f"{len(unique_bugs)} unique bugs | {len(unique_crashes)} unique crashes"
                )

        print_summary(executed, start_time, unique_bugs, unique_crashes, seed_corpus, test_corpus)

    except KeyboardInterrupt:
        logger.info("Fuzzing manually interrupted. Generating final report...")
        # Generate summary reports
        generate_summary_report(unique_bugs, unique_crashes)
        # Print final statistics
        print_summary(executed, start_time, unique_bugs, unique_crashes, seed_corpus, test_corpus)

    # End of fuzzing loop
    logger.info("Fuzzing complete.")


    # === Final Coverage Report ===
    cov.stop()
    cov.save()
    cov.html_report(directory='coverage_html_report')
    logger.info("Coverage report saved to ./coverage_html_report/index.html")

if __name__ == "__main__":
    main()
