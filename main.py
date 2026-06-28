from __future__ import annotations

import importlib
import pkgutil
from types import ModuleType

import vulnerabilities

EXCLUDED_MODULES = {"common"}


def load_scanners() -> list[ModuleType]:
    """Load each scanner module exactly once from ``vulnerabilities``."""
    scanners: list[ModuleType] = []
    for module_info in sorted(pkgutil.iter_modules(vulnerabilities.__path__), key=lambda item: item.name):
        if module_info.name.startswith("_") or module_info.name in EXCLUDED_MODULES:
            continue
        module = importlib.import_module(f"vulnerabilities.{module_info.name}")
        if callable(getattr(module, "scan", None)):
            scanners.append(module)
    return scanners
