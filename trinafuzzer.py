import requests
import random
import json
import time
import logging
import hashlib
from urllib.parse import urljoin
from copy import deepcopy
import coverage
from datetime import datetime
import sys
import traceback
import os

# Setup logging immediately to ensure coverage of logging code
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fuzzer.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize coverage
cov = coverage.Coverage(branch=True)
cov.start()

# Configuration
BASE_URL = 'http://127.0.0.1:8000/'
TIMEOUT = 60  # Seconds to run fuzzing
LOG_FILE = 'fuzzer_results.json'
CRASH_LOG_FILE = 'unique_crashes.json'  # New file for storing only unique crashes

# Create more diverse seed data to increase coverage
SeedQ = [
    {"id": 1, "name": "ProductA", "info": "Test info", "price": 10.99},
    {"id": 2, "name": "ProductB", "info": "Another product", "price": 99.99},
    {"id": 3, "name": "", "info": "Empty name test", "price": 5.99},  # Test empty name
    {"id": 4, "name": "Price Test", "info": "Negative price", "price": -1.0},  # Test negative price
    {"id": 5, "name": "No Info", "price": 29.99}  # Missing info field
]

FailureQ = []
# Keep track of unique crashes to avoid duplicates
seen_crashes = set()


def hash_crash(crash_type, response_text):
    """
    Create a hash for a crash to identify duplicates.
    We use the error message/traceback as the key identifier.
    """
    if isinstance(response_text, str):
        # Extract the core error message (first line or first N chars)
        error_text = response_text.split('\n')[0] if '\n' in response_text else response_text[:100]
    else:
        error_text = response_text.text[:100] if hasattr(response_text, 'text') else str(response_text)[:100]
    
    # Create a hash combining the crash type and error message
    crash_signature = f"{crash_type}:{error_text}"
    return hashlib.md5(crash_signature.encode('utf-8')).hexdigest()


def setup_logging():
    global results_logger, crash_logger
    # Setup main results logger
    results_logger = logging.getLogger('results')
    results_logger.setLevel(logging.INFO)
    
    # Setup unique crashes logger - new
    crash_logger = logging.getLogger('crashes')
    crash_logger.setLevel(logging.INFO)
    
    # Ensure the log directories exist
    try:
        for log_file in [LOG_FILE, CRASH_LOG_FILE]:
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir)
    except Exception as e:
        logger.error(f"Failed to create log directory: {str(e)}")
    
    try:
        # Setup main results handler
        handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(message)s'))
        results_logger.addHandler(handler)
        results_logger.propagate = False
        
        # Setup unique crashes handler - new
        crash_handler = logging.FileHandler(CRASH_LOG_FILE, encoding='utf-8')
        crash_handler.setFormatter(logging.Formatter('%(message)s'))
        crash_logger.addHandler(crash_handler)
        crash_logger.propagate = False
        
        logger.info(f"Logging set up successfully to {LOG_FILE} and {CRASH_LOG_FILE}")
    except Exception as e:
        logger.error(f"Failed to setup logging: {str(e)}")


def categorize_response(response):
    """Categorize the response type for analysis"""
    if isinstance(response, str):
        logger.debug(f"Request exception detected: {response[:50]}...")
        return 'REQUEST_EXCEPTION'
    if response.status_code >= 500:
        logger.debug(f"Server error detected: {response.status_code}")
        return 'SERVER_ERROR'
    elif response.status_code >= 400:
        logger.debug(f"Client error detected: {response.status_code}")
        return 'CLIENT_ERROR'
    elif response.status_code >= 300:
        logger.debug(f"Redirection detected: {response.status_code}")
        return 'REDIRECTION'
    elif response.status_code >= 200:
        logger.debug(f"Success response: {response.status_code}")
        return 'SUCCESS'
    else:
        logger.debug(f"Unknown response code: {response.status_code}")
        return 'UNKNOWN'


def log_result(event_type, payload, response):
    """Log test results to the results file"""
    try:
        category = categorize_response(response)
        result = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'category': category,
            'payload': payload,
            'response': str(response)[:1000],
            'status_code': getattr(response, 'status_code', None)
        }
        results_logger.info(json.dumps(result))
        return True
    except Exception as e:
        logger.error(f"Failed to log result: {str(e)}")
        traceback.print_exc()
        return False


def log_unique_crash(event_type, payload, response, crash_hash):
    """Log only unique crashes to a dedicated file"""
    try:
        category = categorize_response(response)
        result = {
            'timestamp': datetime.now().isoformat(),
            'type': event_type,
            'category': category,
            'payload': payload,
            'response': str(response)[:1000],
            'status_code': getattr(response, 'status_code', None),
            'crash_hash': crash_hash
        }
        crash_logger.info(json.dumps(result))
        # Also print to console for immediate visibility
        print(f"\n[UNIQUE {event_type}] - Hash: {crash_hash[:8]}")
        print(f"Payload: {json.dumps(payload, indent=2)}")
        print(f"Response: {str(response)[:200]}...\n")
        return True
    except Exception as e:
        logger.error(f"Failed to log unique crash: {str(e)}")
        traceback.print_exc()
        return False


def is_crash(response):
    """Check if the response indicates a server crash"""
    if isinstance(response, str):
        logger.debug(f"String response detected as crash: {response[:50]}")
        return True
    
    if response.status_code >= 500:
        logger.debug(f"500+ status code detected as crash: {response.status_code}")
        return True
    
    try:
        content = response.text.lower()
        keywords = ['exception', 'traceback', 'error']
        for keyword in keywords:
            if keyword in content:
                logger.debug(f"Keyword '{keyword}' found in response, detected as crash")
                return True
    except Exception as e:
        logger.warning(f"Error checking response content: {str(e)}")
    
    return False


def is_interesting(response):
    """Check if the response is interesting for further exploration"""
    if isinstance(response, str):
        logger.debug("String response not considered interesting")
        return False
    
    interesting_codes = [201, 202, 204, 301, 302]
    if response.status_code in interesting_codes:
        logger.debug(f"Status code {response.status_code} considered interesting")
        return True
    
    # Try to parse response as JSON to see if it's well-formed
    try:
        if hasattr(response, 'json'):
            json_data = response.json()
            if isinstance(json_data, dict) and len(json_data) > 2:
                logger.debug("Complex JSON response considered interesting")
                return True
    except Exception:
        pass
    
    return False


def choose_next(queue):
    """Select the next test case from the queue"""
    if not queue:
        logger.warning("Queue is empty, creating fallback test case")
        return {"id": random.randint(1, 1000), "name": "Fallback", "price": 0.99}
    
    # Choose based on weighted random to favor more complex inputs
    weights = [len(json.dumps(item)) for item in queue]
    total = sum(weights)
    if total == 0:
        return deepcopy(random.choice(queue))
    
    r = random.uniform(0, total)
    upto = 0
    for i, w in enumerate(weights):
        upto += w
        if upto >= r:
            logger.debug(f"Selected item {i} from queue")
            return deepcopy(queue[i])
    
    # Fallback if weighted selection fails
    return deepcopy(random.choice(queue))


def assign_energy(test_case):
    """Assign energy (number of mutations) to a test case"""
    # Base energy is between 1-5
    base_energy = random.randint(1, 5)
    
    # Add bonus energy for complex test cases
    complexity = len(json.dumps(test_case))
    bonus = min(3, complexity // 20)  # Up to 3 bonus points based on complexity
    
    energy = base_energy + bonus
    logger.debug(f"Assigned energy {energy} to test case")
    return energy


def mutate_input(t):
    """Mutate the input to generate a new test case"""
    mutated = deepcopy(t)
    
    # Occasionally add a new field
    if random.random() < 0.1:
        new_field = f"field_{random.randint(1, 100)}"
        mutated[new_field] = random.choice([
            "new value", 
            random.randint(1, 1000), 
            {"nested": "object"},
            ["array", "values"],
            None
        ])
        logger.debug(f"Added new field: {new_field}")
        return mutated
    
    # Get existing keys or use a default if empty
    keys = list(mutated.keys()) 
    if not keys:
        keys = ["id", "name", "price"]
        mutated["id"] = 1
    
    key = random.choice(keys)
    
    mutation_types = [
        'random_str', 'null', 'overflow', 'remove', 'int', 'empty',
        'special_chars', 'boolean', 'array', 'nested_object'
    ]
    mutation_type = random.choice(mutation_types)
    
    # Avoid deleting 'id' to maintain valid structure
    if key == 'id' and mutation_type == 'remove':
        mutation_type = 'int'

    if mutation_type == 'random_str':
        mutated[key] = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(5, 20)))
    elif mutation_type == 'null':
        mutated[key] = None
    elif mutation_type == 'overflow':
        mutated[key] = 'A' * random.randint(100, 2000)
    elif mutation_type == 'remove':
        del mutated[key]
    elif mutation_type == 'int':
        mutated[key] = random.randint(-1000, 1000)
    elif mutation_type == 'empty':
        mutated[key] = ""
    elif mutation_type == 'special_chars':
        mutated[key] = ''.join(random.choices('!@#$%^&*()_+-=[]{}|;:,.<>?', k=random.randint(1, 10)))
    elif mutation_type == 'boolean':
        mutated[key] = random.choice([True, False])
    elif mutation_type == 'array':
        mutated[key] = [random.randint(1, 100) for _ in range(random.randint(1, 5))]
    elif mutation_type == 'nested_object':
        mutated[key] = {"nested_key": random.randint(1, 100), "value": "nested"}

    logger.debug(f"Mutated field '{key}' with type '{mutation_type}'")
    return mutated


def execute_test(t):
    """Execute a test case against the API"""
    url = urljoin(BASE_URL, 'datatb/product/add/')
    headers = {'Content-Type': 'application/json'}

    try:
        # Try to serialize to JSON
        try:
            json_data = json.dumps(t)
        except TypeError as json_error:
            logger.debug(f"JSON serialization failed: {str(json_error)}")
            return f"JSON_ERROR: {str(json_error)}"
            
        logger.debug(f"Testing payload: {json_data[:200]}...")
        
        # Add variable timeout to increase coverage of timeout handling
        timeout = random.uniform(1.0, 3.0)
        
        start_time = time.time()
        response = requests.post(
            url,
            headers=headers,
            data=json_data,
            timeout=timeout
        )
        elapsed = (time.time() - start_time) * 1000
        logger.debug(f"Response ({elapsed:.2f}ms): {response.status_code} - {response.text[:200]}...")
        
        # Occasionally force a sleep to test timeout handling
        if random.random() < 0.01:
            logger.debug("Forcing sleep to test timeout handling")
            time.sleep(3.0)
            
        return response
    except requests.exceptions.Timeout:
        logger.error("Request timed out")
        return "REQUEST_TIMEOUT"
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error: {str(e)}")
        return f"CONNECTION_ERROR: {str(e)}"
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {str(e)}")
        return str(e)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        traceback.print_exc()
        return f"UNEXPECTED_ERROR: {str(e)}"


def is_failure(response, payload):
    """Custom failure check based on business logic"""
    # Handle string responses (connection errors, etc.)
    if isinstance(response, str):
        logger.debug("String response not considered a business logic failure")
        return False
    
    # Track failures during processing
    failures = []
    
    # Check if price is None or negative
    price = payload.get("price")
    if price is not None:
        try:
            price = float(price)
            if price < 0:
                failures.append("Negative price")
        except (ValueError, TypeError):
            failures.append("Invalid price format")
    else:
        failures.append("Missing price")

    # Check if product name is empty or None
    name = payload.get("name")
    if name is None:
        failures.append("Missing name")
    elif isinstance(name, str) and name.strip() == "":
        failures.append("Empty name")
    
    # Check for other invalid field values
    if isinstance(payload.get("id"), str) and not payload["id"].isdigit():
        failures.append("Invalid ID format")
    
    # Log detailed failure info
    if failures:
        logger.debug(f"Business logic failures: {', '.join(failures)}")
        return True
    
    return False


def fuzz():
    """Main fuzzing function"""
    setup_logging()
    start_time = time.time()
    test_count = 0
    unique_crashes_count = 0
    duplicate_crashes_count = 0
    unique_failures_count = 0
    mutation_stats = {}

    # Clear previous crash log file to start fresh
    with open(CRASH_LOG_FILE, 'w') as f:
        f.write("")  # Empty the file

    logger.info(f"Starting fuzzer with {len(SeedQ)} seeds (timeout: {TIMEOUT}s)")
    logger.info(f"Target URL: {urljoin(BASE_URL, 'datatb/product/add/')}")
    print(f"\n==== FUZZER STARTED ====")
    print(f"Only unique crashes will be displayed")
    print(f"Detailed logs: {LOG_FILE}")
    print(f"Unique crashes log: {CRASH_LOG_FILE}\n")

    try:
        # Run some initial tests on the seed queue to establish baseline
        logger.info("Running initial tests on seed data")
        for seed in SeedQ:
            response = execute_test(seed)
            test_count += 1
            log_result('SEED_TEST', seed, response)
        
        # Main fuzzing loop
        while time.time() - start_time < TIMEOUT:
            t = choose_next(SeedQ)
            energy = assign_energy(t)

            for _ in range(energy):
                t_prime = mutate_input(t)
                
                # Track mutation statistics
                mutation_fields = set(t_prime.keys()) - set(t.keys())
                mutation_fields.update(set(t.keys()) - set(t_prime.keys()))
                for field in mutation_fields:
                    mutation_stats[field] = mutation_stats.get(field, 0) + 1
                
                response = execute_test(t_prime)
                test_count += 1

                if is_crash(response):
                    crash_hash = hash_crash("CRASH", response)
                    
                    if crash_hash not in seen_crashes:
                        seen_crashes.add(crash_hash)
                        FailureQ.append(("CRASH", t_prime, str(response)))
                        log_result('CRASH', t_prime, response)
                        log_unique_crash('CRASH', t_prime, response, crash_hash)
                        unique_crashes_count += 1
                    else:
                        logger.debug(f"Duplicate crash skipped: {crash_hash[:8]}")
                        duplicate_crashes_count += 1
                
                elif is_failure(response, t_prime):  # Check if business rule failure
                    failure_hash = hash_crash("FAILURE", response)
                    
                    if failure_hash not in seen_crashes:
                        seen_crashes.add(failure_hash)
                        FailureQ.append(("FAILURE", t_prime, str(response)))
                        log_result('FAILURE', t_prime, response)
                        log_unique_crash('FAILURE', t_prime, response, failure_hash)
                        unique_failures_count += 1
                    else:
                        logger.debug(f"Duplicate failure skipped: {failure_hash[:8]}")
                        duplicate_crashes_count += 1
                
                elif is_interesting(response):
                    SeedQ.append(t_prime)
                    logger.warning(f"Interesting input (HTTP {getattr(response, 'status_code', 'N/A')}): {t_prime}")
                    log_result('INTERESTING', t_prime, response)
                else:
                    log_result('SUCCESS', t_prime, response)

                # Occasionally try to forcibly trigger error handling code paths
                if random.random() < 0.01:
                    try:
                        if random.random() < 0.5:
                            # Try to cause a logging error
                            original_handler = results_logger.handlers[0]
                            results_logger.removeHandler(original_handler)
                            log_result('TEST_ERROR_PATH', t_prime, response)
                            results_logger.addHandler(original_handler)
                        else:
                            # Try an invalid JSON payload
                            execute_test(object())
                    except Exception as e:
                        logger.debug(f"Error path test: {str(e)}")

    except KeyboardInterrupt:
        logger.info("Fuzzing interrupted by user")
        print("\nFuzzing interrupted by user")
    except Exception as e:
        logger.error(f"Fuzzer crashed: {str(e)}", exc_info=True)
        print(f"\nFuzzer crashed: {str(e)}")
    finally:
        cov.stop()
        cov.save()

        # Generate summary report
        logger.info("\n=== Fuzzing Complete ===")
        logger.info(f"Total test cases executed: {test_count}")
        logger.info(f"Unique failures/crashes found: {unique_crashes_count + unique_failures_count}")
        logger.info(f"Duplicate failures/crashes skipped: {duplicate_crashes_count}")
        
        # Print summary to console
        print("\n==== FUZZING COMPLETE ====")
        print(f"Total test cases executed: {test_count}")
        print(f"Unique crashes found: {unique_crashes_count}")
        print(f"Unique logic failures found: {unique_failures_count}")
        print(f"Duplicate crashes/failures skipped: {duplicate_crashes_count}")
        
        # Show mutation statistics
        logger.info("\n=== Mutation Statistics ===")
        for field, count in sorted(mutation_stats.items(), key=lambda x: x[1], reverse=True):
            logger.info(f"Field '{field}' mutated {count} times")

        # Show coverage statistics
        logger.info("\n=== Coverage Summary ===")
        cov.report()
        cov.html_report(directory='coverage_report')
        logger.info("HTML report generated in 'coverage_report/'")
        print(f"HTML coverage report generated in 'coverage_report/'")

        # Show all unique failures found - simplified for console
        if FailureQ:
            print("\n==== CRASH SUMMARY ====")
            crash_count = 0
            failure_count = 0
            
            for failure_type, _, _ in FailureQ:
                if failure_type == "CRASH":
                    crash_count += 1
                else:
                    failure_count += 1
                    
            print(f"Found {crash_count} unique crashes and {failure_count} unique logic failures")
            print(f"See '{CRASH_LOG_FILE}' for complete details")
        
        # Exercise any remaining code paths we might have missed
        try:
            categorize_response("Some string response")
            categorize_response(None)
            is_crash("Some string crash")
            is_crash(None)
            is_interesting("Some string")
            is_interesting(None)
        except Exception:
            pass


if __name__ == "__main__":
    fuzz()
