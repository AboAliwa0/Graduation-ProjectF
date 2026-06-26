"""
==========================================================
CyberScan Enterprise
Core Package
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Core framework package.
Version : 1.0
==========================================================
"""


from .plugin import Plugin
from .models import PluginInfo, ScanResult


__all__ = [
    "PluginInfo",
    "ScanResult",
]