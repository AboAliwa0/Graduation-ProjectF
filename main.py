import os
import importlib
from report import generate_report


# 🔥 لازم تضيف الفنكشن دي فوق main
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

    for scanner in scanners:
        try:
            result = scanner.scan(target)
        except Exception as e:
            result = f"[!] Error in {scanner.__name__}: {str(e)}"

        print(result)
        results.append(result)

    print("\n=== Scan Finished ===\n")

    generate_report(results, target)


if __name__ == "__main__":
    main()