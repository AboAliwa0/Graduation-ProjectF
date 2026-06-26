"""
==========================================================
CyberScan Enterprise
Scan Result Model
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Unified scan result returned by all plugins.
Version : 1.1
==========================================================
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(slots=True)
class ScanResult:
    """
    Represents the result of a single scanner.
    """

    # Plugin Information
    plugin_id: str
    plugin_name: str

    # Target Information
    target: str
    final_url: str = ""

    # Scan Result
    vulnerable: bool = False
    severity: str = "Info"
    confidence: str = "High"

    # Finding
    title: str = ""
    description: str = ""
    recommendation: str = ""

    # Technical Information
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)

    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)

    # References
    references: List[str] = field(default_factory=list)

    # Standards
    cwe: str = ""
    cvss: float = 0.0

    # Performance
    execution_time: float = 0.0

    # Extra Information
    metadata: Dict[str, Any] = field(default_factory=dict)