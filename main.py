import os
import importlib
import inspect
from report import generate_report
from utils.param_extractor import extract_params


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
                    print(f"[!] {module_name} skipped (no scan function)")

            except Exception as e:
                print(f"[!] Error loading {module_name}: {e}")

    return scanners


def main():
    target = input("Enter target URL: ")

    scanners = load_scanners()
    results = []

    print("\n=== Scan Started ===\n")

    # 🔥 استخراج parameters من الموقع
    params = extract_params(target)
    print(f"[+] Detected parameters: {params}")

    for scanner in scanners:
        try:
            signature = inspect.signature(scanner.scan).parameters

            # لو function فيها parameter واحد (url بس)
            if len(signature) == 1:
                result = scanner.scan(target)

            # لو فيها (url + param)
            elif len(signature) == 2:
                if len(params) > 0:
                    param = params[0]  # أول parameter
                    result = scanner.scan(target, param)
                else:
                    result = "[!] No parameters found"

            else:
                result = "[!] Unsupported scan function"

        except Exception as e:
            result = f"[!] Error in {scanner.__name__}: {str(e)}"

        print(f"{scanner.__name__} -> {result}")
        results.append(f"{scanner.__name__}: {result}")

    print("\n=== Scan Finished ===\n")

    generate_report(results, target)


if __name__ == "__main__":
    main()