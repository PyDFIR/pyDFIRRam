"""todo"""

from enum import Enum
from typing import List

from volatility3 import framework, plugins

class OperatingSystem(Enum):
    """Represents an operating system."""
    WINDOWS = 1
    LINUX = 2
    MACOS = 3

class Generic:
    """Represents a generic OS to be parsed by volatility."""

    def __init__(self, os: OperatingSystem):#, profile: str, image: str):
        self.os = os

    def __str__(self):
        return f"Generic OS: {self.os.name}"

    # def init_commands(self) -> None:
    #     """Parses the available commands for the OS."""
    #     pass

    def get_plugins_list(self) -> List[str]:
        """Returns a list of available plugins for the OS."""
        failures = framework.import_files(plugins, True)
        plugin_list = framework.list_plugins()

        return plugin_list
