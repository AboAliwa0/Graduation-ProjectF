"""
==========================================================
CyberScan Enterprise
Models Package
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Export all core data models.
Version : 1.0
==========================================================
"""

from .plugin import PluginInfo
from .result import ScanResult

__all__ = [
    "PluginInfo",
    "ScanResult",
]