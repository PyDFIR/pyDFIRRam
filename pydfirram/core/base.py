"""todo"""

from enum import Enum
from typing import List, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from volatility3 import framework, plugins


class OperatingSystem(Enum):
    """Supported operating system."""

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

    def __init__(self, os: OperatingSystem, dump_file: Path):
        """Initializes a generic OS, automatically getting all available
        Volatility3 plugins for the OS.
        """
        self.os = os
        self.plugins: List[PluginEntry] = self.get_all_plugins()
        self.dump_file = dump_file

    def get_all_plugins(self) -> List[PluginEntry]:
        """Returns all plugins for the OS."""
        plugin_list = self.get_plugins_list()
        parsed_plugins = self.parse_plugins_list(plugin_list)

        return parsed_plugins

    def get_plugins_list(self) -> Dict[str, Any]:
        """Returns a list of available volatility3 plugins for the OS."""
        framework.import_files(plugins, True)
        plugin_list = framework.list_plugins()

        return plugin_list

    def parse_plugins_list(self, plugin_list: Dict[str, Any]) -> List[PluginEntry]:
        """todo
        Parsing of get_plugins
        """
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
