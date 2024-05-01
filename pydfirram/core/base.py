"""todo"""

from enum import Enum
from typing import List, Dict

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
        self.plugins: List

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
    def create_index_plugins(self) -> dict:
        """
            Parsing of get_plugins
        """
        plugin_list : List[str] = self.get_plugins_list()
        for e in plugin_list:
            value : list = e.split(".")
            print("--------------------------------------------------")
            print(e)
            if value[0] == "volatility3":
                #print(f"plateform: {value[4]}\nPlugins: {value[-1]}")
                print(str.lower(self.os))
                if value[4] == str.lower(self.os) :
                    print(f'{e}')
            else:
                if value[4] == str.lower(self.os) :
                    print(f'{e}')