import os
import importlib

def load_scanners():
    """
    تحميل جميع وحدات الفحص ديناميكيًا من مجلد vulnerabilities
    كل ملف لازم يحتوي على دالة scan()
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
                    print(f"[!] {module_name} skipped: no scan() function")

            except Exception as e:
                print(f"[!] Error loading {module_name}: {e}")

    return scanners