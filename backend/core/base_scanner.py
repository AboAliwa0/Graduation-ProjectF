"""
==========================================================
CyberScan Enterprise
Base Scanner
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Base implementation shared by all scanner plugins.
Version : 1.0
==========================================================
"""

from abc import abstractmethod
from time import perf_counter

from backend.core.http_client import HTTPClient
from backend.core.models import ScanResult
from backend.core.plugin import Plugin


class BaseScanner(Plugin):
    """
    Base implementation for all scanners.
    """

    def __init__(self):
        super().__init__()
        self.client = HTTPClient()

    def validate_target(self, target: str) -> bool:
        """
        Basic target validation.
        """
        return target.startswith(("http://", "https://"))

    def execute(self, target: str) -> ScanResult:
        """
        Execute scanner and measure execution time.
        """

        self.initialize()

        start = perf_counter()

        try:
            result = self.scan(target)
        finally:
            self.cleanup()

        result.execution_time = round(
            perf_counter() - start,
            4
        )

        return result

    @abstractmethod
    def scan(self, target: str) -> ScanResult:
        """
        Scanner implementation.
        """
        raise NotImplementedError