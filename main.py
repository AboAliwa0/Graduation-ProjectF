import os
import importlib
import inspect

from backend.core.plugin import Plugin

# Scanners in this project inherit from BaseScanner -> Plugin.
# No need for any 'Plugins' registry; we discover classes dynamically.




import os
import importlib
import inspect

from backend.core.plugin import Plugin


def load_scanners():
    """
    Load scanners from both the new Plugin Framework and the
    legacy vulnerabilities folder.

    Priority:
        backend/plugins
            ↓
        vulnerabilities
    """

    scanners = []
    loaded = set()

    # =====================================================
    # New Plugin Framework
    # =====================================================

    plugins_folder = os.path.join("backend", "plugins")

    if os.path.isdir(plugins_folder):

        for file in os.listdir(plugins_folder):

            if not file.endswith(".py"):
                continue

            if file.startswith("__"):
                continue

            module_name = file[:-3]

            try:

                module = importlib.import_module(
                    f"backend.plugins.{module_name}"
                )

                for _, cls in inspect.getmembers(module, inspect.isclass):

                   if (
    issubclass(cls, Plugin)
    and cls is not Plugin
    and cls.__module__ == module.__name__
):

                        scanners.append(cls())

                        loaded.add(module_name.lower())

                        print(f"[PLUGIN] Loaded: {module_name}")

            except Exception as ex:

                print(
                    f"[PLUGIN ERROR] {module_name}: {ex}"
                )

    # =====================================================
    # Legacy Framework
    # =====================================================

    legacy_folder = "vulnerabilities"

    if os.path.isdir(legacy_folder):

        for file in os.listdir(legacy_folder):

            if not file.endswith(".py"):
                continue

            if file.startswith("__"):
                continue

            module_name = file[:-3]

            if module_name.lower() in loaded:
                continue

            try:

                module = importlib.import_module(
                    f"vulnerabilities.{module_name}"
                )

                if hasattr(module, "scan"):

                    scanners.append(module)

                    print(f"[LEGACY] Loaded: {module_name}")

            except Exception as ex:

                print(
                    f"[LEGACY ERROR] {module_name}: {ex}"
                )

    print(f"\n[INFO] Total Scanners Loaded: {len(scanners)}\n")

    return scanners