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
MAX_TEST_CASES = 5000
INTERESTING_VALUES = [
    "", " ", None, 0, -1, 1e100, "<script>alert(1)</script>", "' OR 1=1 --",
    "../../etc/passwd", "\ufffd" * 1000, True, False, "null", "undefined",
    "NaN", "Infinity", "A" * 2048, 12345678901234567890, "🤯", {}, [],
    datetime.now().isoformat()
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
        bugs_found = []
        
        for operation in sequence:
            if operation == 'create':
                # Generate a new test case
                test_case = mutate_input(generate_seed_from_model())
                result = save_via_model(test_case)
                if result.get('bug_found'):
                    bugs_found.append(('create', test_case, result))
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
                            bugs_found.append(('read', 
                                              {'expected': self.current_data, 'actual': instance.__dict__},
                                              {'bug_type': 'DataInconsistency'}))
                except Exception as e:
                    bugs_found.append(('read', {'id': self.current_id}, {'error': str(e)}))
                    
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
                            bugs_found.append(('update', 
                                             {'expected': update_data, 'actual': instance.__dict__},
                                             {'bug_type': 'UpdateFailure'}))
                            
                    # Update current data
                    self.current_data = update_data
                    
                except Exception as e:
                    bugs_found.append(('update', update_data, {'error': str(e)}))
                    
            elif operation == 'delete':
                try:
                    instance = self.model_class.objects.get(id=self.current_id)
                    instance.delete()
                    
                    # Verify deletion
                    if self.model_class.objects.filter(id=self.current_id).exists():
                        bugs_found.append(('delete', 
                                         {'id': self.current_id},
                                         {'bug_type': 'DeletionFailure'}))
                    
                    # Reset current state
                    self.current_id = None
                    self.current_data = None
                    
                except Exception as e:
                    bugs_found.append(('delete', {'id': self.current_id}, {'error': str(e)}))
                    
        return bugs_found
    
class FuzzProgress:
    def __init__(self, window_size=50):
        self.window_size = window_size
        self.bug_history = []
        self.coverage_history = []
        
    def update(self, bug_found, coverage_hash):
        """Record progress metrics."""
        self.bug_history.append(1 if bug_found else 0)
        self.coverage_history.append(coverage_hash)
        
    def should_continue(self, max_cases):
        """Determine if fuzzing should continue based on progress."""
        # Always run minimum number of cases
        if len(self.bug_history) < max(100, self.window_size * 2):
            return True
            
        # Check if we've hit the hard limit
        if len(self.bug_history) >= max_cases:
            return False
            
        # Check recent bug discovery rate
        recent = self.bug_history[-self.window_size:]
        previous = self.bug_history[-self.window_size*2:-self.window_size]
        
        recent_bug_rate = sum(recent) / len(recent)
        previous_bug_rate = sum(previous) / len(previous)
        
        # Check recent coverage growth
        recent_coverage = len(set(self.coverage_history[-self.window_size:]))
        previous_coverage = len(set(self.coverage_history[-self.window_size*2:-self.window_size]))
        coverage_growth = recent_coverage - previous_coverage
        
        # Continue if we're finding bugs at a decent rate or coverage is growing
        return recent_bug_rate > 0.01 or recent_bug_rate >= previous_bug_rate * 0.7 or coverage_growth > 0
    
class GrammarFuzzer:
    def __init__(self):
        # Define grammars for different field types/names
        self.grammars = {
            'name': {
                'start': ['<adjective> <noun>', '<brand> <product_type>'],
                'adjective': ['Super', 'Ultra', 'Premium', 'Basic', 'New', 'Classic'],
                'noun': ['Widget', 'Gadget', 'Tool', 'Device', 'Product'],
                'brand': ['TechCo', 'GadgetInc', 'WidgetWorld', 'ProCo'],
                'product_type': ['Pro', 'Lite', 'Max', 'Mini', 'Plus']
            },
            'info': {
                'start': ['<info_type> <info_value>'],
                'info_type': ['id', 'type', 'class', 'value'],
                'info_value': ['12345', 'abc', 'test', 'info', 'value']
            }
        }
        
        # Add SQL injection patterns
        self.sql_patterns = [
            "' OR '1'='1", 
            "'; DROP TABLE products; --",
            "' UNION SELECT username,password FROM users; --"
        ]
        
        # Add XSS patterns
        self.xss_patterns = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)"
        ]
    
    def expand_grammar(self, grammar, symbol, depth=0):
        """Recursively expand a grammar symbol."""
        if depth > 10:  # Prevent infinite recursion
            return "MAX_DEPTH_REACHED"
            
        if not symbol.startswith('<') or not symbol.endswith('>'):
            return symbol
            
        key = symbol[1:-1]  # Remove < and >
        if key not in grammar:
            return symbol
            
        production = random.choice(grammar[key])
        result = []
        
        for part in production.split():
            result.append(self.expand_grammar(grammar, part, depth + 1))
            
        return ' '.join(result)
    
    def generate(self, field_name, include_attacks=True):
        """Generate a string based on grammar rules."""
        # Check if we have a specific grammar for this field
        if field_name in self.grammars:
            grammar = self.grammars[field_name]
            value = self.expand_grammar(grammar, '<start>')
            
            # Sometimes include attack patterns
            if include_attacks and random.random() < 0.2:
                if random.random() < 0.5:
                    return random.choice(self.sql_patterns)
                else:
                    return random.choice(self.xss_patterns)
                    
            return value
        
        # Default to basic string
        return f"value_{random.randint(1, 1000)}"

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
grammar_fuzzer = GrammarFuzzer()


def smart_mutate(field, val):
    """
    Generate only valid-typed values, but hit deeper model logic
    """
    field = field.lower()
    field_metadata = FIELDS.get(field, {})
    
    # Sometimes use the grammar fuzzer for string fields
    if isinstance(val, str) and random.random() < 0.3:
        return grammar_fuzzer.generate(field)
        
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
    energy = 1.0  # Base energy
    
    # Reward test cases that found bugs
    if result.get("bug_found", False):
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

def fuzz_all_models(max_cases_per_model=100):
    """Run the fuzzer on all available models."""
    models = get_all_models()
    results = {}
    
    for model in models:
        # Skip abstract models and Django internal models
        if model._meta.abstract or model._meta.app_label in ('auth', 'admin', 'sessions'):
            continue
            
        logger.info(f"Fuzzing model: {model.__name__}")
        model_bugs = fuzz_model(model, max_cases_per_model)
        results[model.__name__] = model_bugs
        
    return results

def fuzz_model(model_class, max_cases):
    """Run the fuzzing process on a specific model."""
    # Initialize model-specific components
    model_metadata = get_model_metadata(model_class)
    model_seeds = generate_seeds_for_model(model_class, model_metadata)
    model_population = [{"data": s, "energy": 1.0, "history": []} for s in model_seeds]
    model_bugs = []
    
    # Initialize trackers for this model
    model_coverage_hashes = set()
    progress_tracker = FuzzProgress(window_size=min(25, max_cases//4))
    
    # Initialize coverage for this model
    model_cov = coverage.Coverage(
        data_file=f".coverage_fuzz_{model_class.__name__}", 
        source=["."], 
        branch=True
    )
    model_cov.erase()
    model_cov.start()
    
    # Run the fuzzing loop
    executed = 0
    while executed < max_cases and progress_tracker.should_continue(max_cases):
        # Similar logic to your main fuzzing loop but model-specific
        # ...
        
        executed += 1
        
    # Generate report
    model_cov.stop()
    model_cov.save()
    model_cov.html_report(directory=f'coverage_html_report_{model_class.__name__}')
    
    return model_bugs

def generate_seeds_for_model(model_class, metadata):
    """Generate seeds for a specific model."""
    # Get existing data if available
    try:
        examples = model_class.objects.all()[:5]
        if examples:
            return [normalize_dict({k: getattr(p, k) for k in metadata}) for p in examples]
    except Exception:
        pass
    
    # Otherwise generate a seed from the model structure
    seed = {}
    for field_name, field_meta in metadata.items():
        field_type = field_meta.get('type')
        if field_type == 'CharField' or field_type == 'TextField':
            seed[field_name] = "text"
        elif field_type == 'FloatField':
            seed[field_name] = 1.23
        elif field_type == 'IntegerField':
            seed[field_name] = 1
        elif field_type == 'BooleanField':
            seed[field_name] = False
        elif field_type == 'DateField':
            seed[field_name] = datetime.now().date().isoformat()
        else:
            seed[field_name] = "default"
    return [seed]

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
# seed = generate_seed_from_model()
# population = [{"data": seed, "energy": 1.0, "history": []}]
seeds = generate_seed_from_existing_data()
population = [{"data": s, "energy": 1.0, "history": []} for s in seeds]
known_exceptions = set()

logger.info("Starting energy-based fuzzing with interestingness classification...")

# Initialize the sequence tester
sequence_tester = FuzzSequence(Product)
progress_tracker = FuzzProgress(window_size=50)

while executed < MAX_TEST_CASES and progress_tracker.should_continue(MAX_TEST_CASES):    # Select test case based on energy
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

    progress_tracker.update(combined_result["bug_found"], new_coverage)
    
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

    if executed % 20 == 0:
        sequence = sequence_tester.generate_sequence(length=random.randint(3, 5))
        sequence_bugs = sequence_tester.execute_sequence(sequence)
        for op, data, result in sequence_bugs:
            log_bug(data, result, f"SequenceBug ({op})")

logger.info("Fuzzing complete.")

# === Final Coverage Report ===
cov.stop()
cov.save()
cov.html_report(directory='coverage_html_report')
logger.info("Coverage report saved to ./coverage_html_report/index.html")