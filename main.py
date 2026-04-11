import os
import importlib
import inspect

from report import generate_report, start_report
from utils.param_extractor import extract_params

# 👇 Scanners بتوعك
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


def main():
    print("=== Advanced Vulnerability Scanner ===\n")

    target = input("Enter target URL: ")
    start_report(target)

    scanners = load_scanners()
    results = []

    print("\n=== Auto Scan Started ===\n")

    # 🔥 استخراج parameters
    params = extract_params(target)
    print(f"[+] Detected parameters: {params}")

    # 🔵 Scanners بتوع التيم
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

    # 🟢 Scanners بتوعك (Manual)
    print("\n=== Custom Scanners ===\n")

    try:
        login_url = input("Login URL: ")
        user = input("Username field: ")
        pwd = input("Password field: ")

        check_broken_auth(login_url, user, pwd)
        results.append("Broken Authentication: Completed")

    except:
        results.append("Broken Authentication: Error")

    try:
        ssrf_url = input("\nSSRF Endpoint: ")
        param = input("Parameter: ")

        check_ssrf_basic(ssrf_url, param)
        results.append("SSRF: Completed")

    except:
        results.append("SSRF: Error")

    try:
        gql = input("\nGraphQL endpoint: ")
        check_graphql_abuse(gql)
        results.append("GraphQL: Completed")

    except:
        results.append("GraphQL: Error")

    print("\n=== Scan Finished ===\n")

    generate_report(results, target)
    generate_pdf("results.txt")

    print("✔ Report + PDF Generated!")


if __name__ == "__main__":
    main()