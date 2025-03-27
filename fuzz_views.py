import atheris
import sys
import json
import coverage
import random
import os
import django
from django.test import RequestFactory
from rest_framework.request import Request  # Added to wrap WSGIRequest correctly
import hashlib
from datetime import datetime

# 1. Input Generation → Setup & Initialization
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

cov = coverage.Coverage(source=["api"], omit=["*/env/*"])
cov.start()

factory = RequestFactory()
logged_bugs = set()  # Track unique crashes

# Crash and bug logger
def log_bug(operation, fuzz_id, payload, issue):
    os.makedirs("crashes", exist_ok=True)
    bug_signature = f"{operation}:{str(issue)}"
    if bug_signature in logged_bugs:
        return
    logged_bugs.add(bug_signature)

    bug_hash = hashlib.sha1(str(issue).encode()).hexdigest()[:8]
    filename = f"crashes/product_{operation}_{bug_hash}.json"

    with open(filename, "w") as f:
        json.dump({
            "operation": operation,
            "fuzz_id": fuzz_id,
            "payload": payload,
            "issue": str(issue)
        }, f, indent=2)

    print(f"[!] Bug or crash logged: {filename}")

# 2. Fuzzing Engine → Generate & Mutate Inputs using Atheris
def fuzz_function(data):
    from api.views import ProductView
    view = ProductView()
    fdp = atheris.FuzzedDataProvider(data)

    operation = fdp.PickValueInList(["post", "get", "put", "delete"])
    fuzz_id = fdp.ConsumeIntInRange(1, 1000)  # Numeric IDs only to match URL regex

    payload = {
        "name": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(8, 128)),
        "info": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(8, 1024)),
        "price": fdp.ConsumeIntInRange(-((2**32)-1), 2**16)
    }

    try:
        if operation == "post":
            request = factory.post("/api/product/", data=json.dumps(payload), content_type="application/json")
            request = Request(request)
            response = view.post(request)
            if response.status_code == 200 and (not isinstance(payload["price"], int) or payload["price"] < 0):
                raise AssertionError("BUG: Invalid price accepted in POST")

        elif operation == "get":
            request = factory.get(f"/api/product/{fuzz_id}/")
            request = Request(request)
            response = view.get(request, pk=str(fuzz_id))

        elif operation == "put":
            request = factory.put(f"/api/product/{fuzz_id}/", data=json.dumps(payload), content_type="application/json")
            request = Request(request)
            response = view.put(request, pk=str(fuzz_id))
            if response.status_code == 200 and payload["name"] == "":
                raise AssertionError("BUG: Empty name accepted in PUT")

        elif operation == "delete":
            request = factory.delete(f"/api/product/{fuzz_id}/")
            request = Request(request)
            response = view.delete(request, pk=str(fuzz_id))

    except Exception as e:
        log_bug(operation, fuzz_id, payload, e)

# Entry point for Atheris Fuzzer
def main():
    atheris.Setup(sys.argv, fuzz_function, enable_python_coverage=True)
    try:
        atheris.Fuzz()
    finally:
        cov.stop()
        cov.save()
        try:
            cov.report()
            cov.html_report(directory='coverage_product_view')
            print("[+] Coverage report saved to ./coverage_product_view")
        except Exception as e:
            print("[!] Coverage generation failed:", str(e))

if __name__ == "__main__":
    main()
