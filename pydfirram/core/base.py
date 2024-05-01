"""todo"""

from enum import Enum
from typing import List, Dict, Any
from dataclasses import dataclass

from volatility3 import framework, plugins


class OperatingSystem(Enum):
    """Represents a supported operating system."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "mac"

    @staticmethod
    def to_list() -> List[str]:
        """Returns a list of supported operating systems."""
        return [os.value for os in OperatingSystem]


class PluginType(Enum):
    """Represents a plugin type."""

    GENERIC = 1
    SPECIFIC = 2


@dataclass
class PluginEntry:
    """Represents a plugin entry."""

    type: PluginType
    name: str
    path: str

    def __repr__(self) -> str:
        return f"PluginEntry({self.type}, {self.name}, {self.path})"


class Generic:
    """Represents a generic OS to be parsed by volatility."""

    def __init__(self, os: OperatingSystem):  # , profile: str, image: str):
        self.os = os
        self.plugins: List[PluginEntry] = []

    def __str__(self):
        return f"Generic OS: {self.os.name}"

    def get_plugins_list(self) -> Dict[str, Any]:
        """Returns a list of available plugins for the OS."""
        framework.import_files(plugins, True)
        plugin_list = framework.list_plugins()

        return plugin_list

    def parse_plugins_list(self) -> List[PluginEntry]:
        """
        Parsing of get_plugins
        """
        plugin_list = self.get_plugins_list()

        parsed: List[PluginEntry] = list()

        for plugin in plugin_list:
            elements = plugin.split(".")
            platform = elements[0]
            path = ".".join(elements[1:-1])
            name = elements[-1]

            if platform not in OperatingSystem.to_list():
                plugin = PluginEntry(PluginType.GENERIC, name, platform)

            elif platform == self.os.value:
                plugin = PluginEntry(PluginType.SPECIFIC, name, path)

            else:
                continue

            parsed.append(plugin)  # type: ignore

        return parsed
