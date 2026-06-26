"""
==========================================================
CyberScan Enterprise
Plugin Information Model
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Defines metadata for all scanner plugins.
Version : 1.0
==========================================================
"""

from dataclasses import dataclass, field
from typing import List


@dataclass(slots=True)
class PluginInfo:
    """
    Metadata describing a CyberScan plugin.
    """

    # Unique plugin ID
    id: str

    # Display name
    name: str

    # Plugin version
    version: str

    # Plugin author
    author: str

    # Short description
    description: str

    # Scanner category
    category: str

    # Default severity if vulnerability exists
    severity: str

    # Execution priority
    priority: int = 100

    # Plugin enabled
    enabled: bool = True

    # Can run in parallel
    supports_parallel: bool = True

    # Requires authentication
    requires_authentication: bool = False

    # Supported protocols
    protocols: List[str] = field(default_factory=lambda: [
        "http",
        "https"
    ])

    # Supported target types
    target_types: List[str] = field(default_factory=lambda: [
        "url"
    ])