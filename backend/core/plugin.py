"""
==========================================================
CyberScan Enterprise
Plugin Base Interface
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Defines the base contract for all scanner plugins.
Version : 1.0
==========================================================
"""

from abc import ABC, abstractmethod

from backend.core.models import PluginInfo, ScanResult

class Plugin(ABC):
    """
    Base class for every CyberScan plugin.

    Every scanner MUST inherit from this class.
    """

    def __init__(self):
        self.info = self.plugin_info()

    @abstractmethod
    def plugin_info(self) -> PluginInfo:
        """
        Return plugin metadata.
        """
        raise NotImplementedError

    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """
        Validate target before scan.

        Returns:
            bool
        """
        raise NotImplementedError

    @abstractmethod
    def scan(self, target: str) -> ScanResult:
        """
        Execute scanner.

        Returns:
            ScanResult
        """
        raise NotImplementedError

    def initialize(self) -> None:
        """
        Called before scan execution.
        """
        pass

    def cleanup(self) -> None:
        """
        Called after scan execution.
        """
        pass

    @property
    def id(self) -> str:
        return self.info.id

    @property
    def name(self) -> str:
        return self.info.name

    @property
    def version(self) -> str:
        return self.info.version

    @property
    def author(self) -> str:
        return self.info.author

    @property
    def category(self) -> str:
        return self.info.category

    @property
    def enabled(self) -> bool:
        return self.info.enabled

    @property
    def supports_parallel(self) -> bool:
        return self.info.supports_parallel