import os
import importlib
import inspect
import sys

from report import generate_report, start_report
from utils.param_extractor import extract_params

# Scanners
from vulnerabilities.auth_scanner import check_broken_auth
from vulnerabilities.ssrf_scanner import check_ssrf_basic
from vulnerabilities.graphql_scanner import check_graphql_abuse


def load_scanners():
    scanners = []
    vuln_folder = "vulnerabilities"

    for file in os.listdir(vuln_folder):
        if file.endswith(".py") and file != "__init__.py":
            module_name = file[:-3]

            try:
                module = importlib.import_module(f"vulnerabilities.{module_name}")

                if hasattr(module, "scan"):
                    scanners.append(module)
                else:
                    print(f"[!] {module_name} skipped")

            except Exception as e:
                print(f"[!] Error loading {module_name}: {e}")

    return scanners


def run(target):
    print(f"=== Scanning {target} ===\n")

    start_report(target)

    scanners = load_scanners()
    results = []

    print("=== Auto Scan Started ===\n")

    # استخراج parameters
    params = extract_params(target)
    print(f"[+] Detected parameters: {params}")

    # تشغيل scanners
    for scanner in scanners:
        try:
            signature = inspect.signature(scanner.scan).parameters

            if len(signature) == 1:
                result = scanner.scan(target)

            elif len(signature) == 2:
                if params:
                    result = scanner.scan(target, params[0])
                else:
                    result = "No parameters found"

            else:
                result = "Unsupported scan"

        except Exception as e:
            result = f"Error: {str(e)}"

        print(f"{scanner.__name__} -> {result}")
        results.append(f"{scanner.__name__}: {result}")

    # تشغيل Scanners إضافية بدون input
    try:
        check_broken_auth(target, "username", "password")
        results.append("Broken Authentication: Checked")
    except:
        results.append("Broken Authentication: Error")

    try:
        check_ssrf_basic(target, "url")
        results.append("SSRF: Checked")
    except:
        results.append("SSRF: Error")

    try:
        check_graphql_abuse(target)
        results.append("GraphQL: Checked")
    except:
        results.append("GraphQL: Error")

    print("\n=== Scan Finished ===\n")

    generate_report(results, target)

    return results  # 👈 مهم جدًا


# تشغيل من التيرمنال فقط
if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
        run(url)
    else:
        print("Usage: python main.py <url>")