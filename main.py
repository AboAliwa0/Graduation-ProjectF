import os
import importlib
import inspect
import sys

from report import generate_report, start_report
from utils.param_extractor import extract_params

def load_scanners():
    """
    تحميل جميع وحدات الفحص ديناميكيًا من مجلد vulnerabilities.
    يجب أن تحتوي كل وحدة على دالة scan(url, param=None).
    """
    scanners = []
    vuln_folder = "vulnerabilities"

    if not os.path.exists(vuln_folder):
        print(f"[!] Folder {vuln_folder} not found.")
        return []

    for file in os.listdir(vuln_folder):
        if file.endswith(".py") and file != "__init__.py":
            module_name = file[:-3]

            try:
                module = importlib.import_module(f"vulnerabilities.{module_name}")

                if hasattr(module, "scan"):
                    scanners.append(module)
                else:
                    print(f"[!] {module_name} skipped: No 'scan' function found.")

            except Exception as e:
                print(f"[!] Error loading {module_name}: {e}")

    return scanners


def run(target):
    print(f"=== Starting Scan for: {target} ===\n")

    start_report(target)

    scanners = load_scanners()
    results = []

    # 🔹 استخراج المعاملات (Parameters) من الهدف
    params = extract_params(target)
    print(f"[+] Detected parameters: {params}")

    # 🔹 تشغيل جميع الـ Scanners المحملة
    for scanner in scanners:
        scanner_name = scanner.__name__.split('.')[-1]
        print(f"[*] Running {scanner_name}...")
        
        try:
            # التحقق من عدد المعاملات التي تقبلها دالة scan
            signature = inspect.signature(scanner.scan).parameters
            
            if len(signature) == 1:
                # الـ Scanner لا يحتاج لمعاملات (مثل Directory Listing)
                result = scanner.scan(target)
            
            elif len(signature) == 2:
                # الـ Scanner يحتاج لمعامل (مثل SQLi, XSS)
                if params:
                    # تشغيل الفحص لكل معامل تم اكتشافه
                    scanner_results = []
                    for p in params:
                        res = scanner.scan(target, p)
                        if res:
                            scanner_results.append(f"Param '{p}': {res}")
                    result = scanner_results if scanner_results else "No vulnerabilities found"
                else:
                    result = "Skipped: No parameters found"
            else:
                result = "Error: Unsupported scan signature"

        except Exception as e:
            result = f"Error during execution: {str(e)}"

        print(f"    -> Result: {result}")
        results.append(f"{scanner_name}: {result}")

    print("\n=== Scan Finished ===\n")

    # 🔹 إنشاء التقرير النهائي
    generate_report(results, target)

    return results


if __name__ == "__main__":
    if len(sys.argv) > 1:
        url = sys.argv[1]
        run(url)
    else:
        print("Usage: python3 main.py <url>")
