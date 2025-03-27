import atheris
import sys
import json
import coverage
import random
import os
import django
from django.test import RequestFactory
from rest_framework.request import Request
from io import BytesIO
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
    from rest_framework.parsers import JSONParser
    from api.views import ProductView
    from home.models import Product
    view = ProductView()
    fdp = atheris.FuzzedDataProvider(data)

    # Seed a product for testing existing IDs
    if not Product.objects.exists():
        Product.objects.create(name="seed", info="seed", price=10)

    operation = fdp.PickValueInList(["post", "get", "put", "delete"])
    fuzz_id = fdp.ConsumeIntInRange(1, 1000)

    evil_strings = [
        "", " ", None, 0, -9999, 1e100, "<script>alert(1)</script>",
        "' OR 1=1 --", "../../etc/passwd", "\ufffd" * 1000
    ]

    payload = {
        "name": fdp.PickValueInList(evil_strings + [fdp.ConsumeUnicodeNoSurrogates(16)]),
        "info": fdp.PickValueInList(evil_strings + [fdp.ConsumeUnicodeNoSurrogates(32)]),
        "price": fdp.PickValueInList([-99999, 0, 1e9, fdp.ConsumeIntInRange(-100000, 100000)])
    }

    try:
        if operation == "post":
            request = factory.post("/api/product/", data=json.dumps(payload), content_type="application/json")
            request._stream = BytesIO(json.dumps(payload).encode())
            request = Request(request)
            request.parsers = [JSONParser()]
            response = view.post(request)

            if response.status_code == 200:
                if payload["price"] is not None and payload["price"] < 0:
                    raise AssertionError("BUG: Accepted negative price")
                if not payload["name"]:
                    raise AssertionError("BUG: Accepted empty name")
                if "<script>" in str(payload["info"]).lower():
                    raise AssertionError("BUG: XSS payload accepted in info")

        elif operation == "get":
            if fdp.ConsumeBool():
                request = factory.get("/api/product/")
                request = Request(request)
                response = view.get(request)
            else:
                request = factory.get(f"/api/product/{fuzz_id}/")
                request = Request(request)
                response = view.get(request, pk=str(fuzz_id))

        elif operation == "put":
            request = factory.put(f"/api/product/{fuzz_id}/", data=json.dumps(payload), content_type="application/json")
            request._stream = BytesIO(json.dumps(payload).encode())
            request = Request(request)
            request.parsers = [JSONParser()]
            response = view.put(request, pk=str(fuzz_id))

            if response.status_code == 200:
                if not payload["name"]:
                    raise AssertionError("BUG: Empty name accepted in PUT")
                if "<script>" in str(payload["info"]).lower():
                    raise AssertionError("BUG: XSS in PUT accepted")

        elif operation == "delete":
            request = factory.delete(f"/api/product/{fuzz_id}/")
            request = Request(request)
            response = view.delete(request, pk=str(fuzz_id))

        if response.status_code >= 500:
            raise AssertionError(f"BUG: Server error (status {response.status_code})")

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
