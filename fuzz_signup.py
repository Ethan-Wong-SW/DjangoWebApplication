import atheris
import sys
import json
import coverage
import os
import django
from django.test import RequestFactory
import hashlib
from datetime import datetime

# Setup Django environment
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

# Start coverage tracking
cov = coverage.Coverage(source=["admin_datta"], include=["*forms.py"])
cov.start()

factory = RequestFactory()

# Crash logger
def log_crash(payload, exception):
    os.makedirs("crashes", exist_ok=True)
    crash_hash = hashlib.sha1(str(exception).encode()).hexdigest()[:8]
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filename = f"crashes/register_{timestamp}_{crash_hash}.json"

    with open(filename, "w") as f:
        json.dump({
            "payload": payload,
            "error": str(exception)
        }, f, indent=2)

    print(f"[!] Crash logged: {filename}")

# Fuzz function
def fuzz_function(data):
    from admin_datta.forms import RegistrationForm
    from django.http import JsonResponse

    fdp = atheris.FuzzedDataProvider(data)
    payload = {
        "username": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(4, 20)),
        "email": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(4, 20)) + "@test.com",
        "password1": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(8, 32)),
        "password2": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(8, 32)),
    }

    try:
        request = factory.post("/accounts/register/", data=payload)
        request._dont_enforce_csrf_checks = True

        form = RegistrationForm(data=payload)
        if form.is_valid():
            form.save()
            JsonResponse({"success": True})
        else:
            JsonResponse({"success": False, "errors": form.errors})

    except Exception as e:
        log_crash(payload, e)

# Fuzzer entry point
def main():
    atheris.Setup(sys.argv, fuzz_function, enable_python_coverage=True)
    try:
        atheris.Fuzz()
    finally:
        cov.stop()
        cov.save()
        try:
            cov.report()
            cov.html_report(directory='coverage_signup')
            print("[+] Coverage report saved to ./coverage_signup")
        except Exception as e:
            print("[!] Coverage generation failed:", str(e))

if __name__ == "__main__":
    main()
