"""
==========================================================
CyberScan Enterprise
Plugin Loader
----------------------------------------------------------
Author  : Graduation Project Team
Purpose : Load and execute scanner plugins.
Version : 1.0.0
==========================================================
"""

from typing import Dict, List

from core.plugin import Plugin


class PluginLoader:

    def __init__(self):

        self.plugins: Dict[str, Plugin] = {}

    def register(self, plugin: Plugin) -> None:
        """
        Register a scanner plugin.
        """

        self.plugins[plugin.id] = plugin

    def get(self, plugin_id: str) -> Plugin | None:
        """
        Return plugin instance.
        """

        return self.plugins.get(plugin_id)

    def list_plugins(self) -> List[str]:
        """
        Return registered plugin ids.
        """

        return list(self.plugins.keys())

    def run(self, plugin_id: str, target: str):
        """
        Execute a plugin.
        """

        plugin = self.get(plugin_id)

        if plugin is None:
            raise ValueError(f"Plugin '{plugin_id}' not found.")

        return plugin.execute(**kwargs)