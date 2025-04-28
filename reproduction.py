import requests
import json

# ========== Configuration ==========

API_ENDPOINT = "http://127.0.0.1:8000/api/product/"  # <-- update this to your actual endpoint
GET_LATEST_PRODUCT_ENDPOINT = "http://127.0.0.1:8000/api/product/"  # <-- Your existing endpoint to retrieve all products
HEADERS = {
    "Content-Type": "application/json"
}

# ========== Payloads for Bugs and Crashes ==========

payloads = [
    # --- Validation Errors ---
    {
        "title": "Validation Error: info field exceeds 2 characters",
        "data": {"name": "a", "info": "12345678", "price": 1}
    },
    {
        "title": "Multiple Validation Errors: info and price malformed",
        "data": {"name": "AA", "info": "text", "price": "<script>alert(1)</script>"}
    },
    {
        "title": "Blank info field and corrupted Unicode price",
        "data": {"name": "aa", "info": "", "price": "\ufffd" * 100}  # fixed here
    },
    {
        "title": "Excessive Unicode garbage in name and info fields",
        "data": {"name": "\ufffd" * 1000, "info": "info", "price": -4294967295}  # fixed here
    },
    {
        "title": "Blank info and edge-case negative price",
        "data": {"name": "bb", "info": "", "price": -2147483648}
    },
    {
        "title": "Long strings + invalid price format",
        "data": {"name": "A" * 3000, "info": "A" * 3000, "price": "\ufffd" * 500}  # fixed here
    },
    {
        "title": "SQL Injection-like input in info field",
        "data": {"name": "bb", "info": "' OR '1'='1", "price": -4294967295}
    },
    {
        "title": "Excessively long name field",
        "data": {"name": "A" * 2000, "info": "ab", "price": 16}
    },
    {
        "title": "Long name + blank info field",
        "data": {"name": "A" * 300, "info": "", "price": 16}
    },
    {
        "title": "Invalid Unicode price + overlong name",
        "data": {"name": "A" * 1000, "info": "12", "price": "\ufffd" * 50}  # fixed here
    },
    {
        "title": "Shell Injection string in price field",
        "data": {"name": "aa", "info": "12", "price": "$(cat /etc/passwd)"}
    },
    {
        "title": "Semantic mismatch: price 10.99 becomes 10.0",
        "data": {"name": "00000000", "info": "Test info", "price": 10.99}
    },
    {
        "title": "Semantic mismatch: malformed price '00000000'",
        "data": {"name": "../../etc/passwd", "info": "Test info", "price": "00000000"}
    }
]

# ========== Test Runner ==========

def run_tests():
    print(f"\nStarting Fuzz Replay on {API_ENDPOINT}\n{'='*60}")
    for idx, case in enumerate(payloads):
        title = case["title"]
        data = case["data"]
        
        print(f"\n[{idx+1}/{len(payloads)}] Test: {title}")
        print("Input Payload:")
        print(json.dumps(data, indent=2))  # <-- print input payload cleanly
        
        try:
            response = requests.post(API_ENDPOINT, headers=HEADERS, data=json.dumps(data), timeout=10)
            print(f"Status Code: {response.status_code}")
            try:
                response_json = response.json()
                print("Response JSON:", json.dumps(response_json, indent=2))
            except json.JSONDecodeError:
                print("Non-JSON response body:", response.text)
        except Exception as e:
            print(f"Error during request: {e}")

if __name__ == "__main__":
    run_tests()
