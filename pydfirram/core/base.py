"""todo"""

import os

from enum import Enum
from typing import List, Dict, Any, Type
from dataclasses import dataclass
from pathlib import Path

from pydfirram.core.handler import create_file_handler

from loguru import logger
from volatility3 import framework, plugins
from volatility3.framework import interfaces, contexts, automagic
from volatility3.framework.plugins import construct_plugin


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
    interface: interfaces.plugins.PluginInterface

    def __repr__(self) -> str:
        return f"PluginEntry({self.type}, {self.name}, {self.interface})"


class Context:
    """Represents a context for a plugin."""

    KEY_LAYER_STACKER = "automagic.LayerStacker"
    KEY_STACKERS = f"{KEY_LAYER_STACKER}.stackers"
    KEY_SINGLE_LOCATION = f"{KEY_LAYER_STACKER}.single_location"

    def __init__(
        self,
        operating_system: OperatingSystem,
        dump_file: Path,
        plugin: PluginEntry,
    ):
        """Initializes a context."""
        self.os = operating_system
        self.dump_file = dump_file
        self.context = contexts.Context()
        self.plugin = plugin

    # def __setattr__(self, name: str, value: Any) -> None:
    #     """Set an attribute."""
    #     setattr(self.context, name, value)

    # def __getattr__(self, name: str) -> Any:
    #     """Get an attribute."""
    #     return getattr(self.context, name)

    def build(self) -> interfaces.plugins.PluginInterface:
        """Build the context.
        todo"""
        plugin = self.plugin.interface
        available_automagics = self.get_available_automagics()

        automagics = automagic.choose_automagic(available_automagics, plugin)  # type: ignore

        os_stackers = automagic.stacker.choose_os_stackers(plugin)
        self.context.config[self.KEY_STACKERS] = os_stackers

        dump_file_location = "file://" + self.dump_file.absolute().as_posix()
        self.context.config[self.KEY_SINGLE_LOCATION] = dump_file_location

        base_config_path = "plugins"
        file_handler = create_file_handler(os.getcwd())

        constructed = construct_plugin(
            self.context,
            automagics,
            plugin,
            base_config_path,
            None,  # no progress callback for now
            file_handler,
        )

        return constructed

    def get_available_automagics(self) -> List[interfaces.automagic.AutomagicInterface]:
        """Returns a list of available automagics."""
        return automagic.available(self.context)


class Generic:
    """Represents a generic OS to be parsed by volatility."""

    def __init__(self, operating_system: OperatingSystem, dump_file: Path):
        """Initializes a generic OS, automatically getting all available
        Volatility3 plugins for the OS.
        """
        self.os = operating_system
        self.plugins: List[PluginEntry] = self.get_all_plugins()
        self.dump_file = self.validate_dump_file(dump_file)
        self.context = None

        logger.info(f"Generic OS initialized: {self.os}")

    # def __getattribute__(self, name: str) -> Any:
    #     """Handle attribute acces for plugins."""
    #     # todo

    def run_plugin(self, plugin: PluginEntry, **kwargs: Any) -> Any:
        """
        Run a plugin with the given arguments.
        """
        # Create basic context
        self.context = Context(self.os, self.dump_file, plugin)

        # Extend it with kwargs

        # Run the plugin

    def validate_dump_file(self, dump_file: Path) -> Path:
        """Validates the dump file."""
        if not dump_file.is_file():
            raise FileNotFoundError(f"The file {dump_file} does not exist.")
        # TODO: validate the dump file with volatility handlers
        return dump_file

    def get_all_plugins(self) -> List[PluginEntry]:
        """Returns all plugins for the OS."""
        plugin_list = self.get_plugins_list()
        parsed_plugins = self.parse_plugins_list(plugin_list)

        return parsed_plugins

    def get_plugins_list(self) -> Dict[str, Any]:
        """Returns a list of available volatility3 plugins for the OS."""
        failures = framework.import_files(plugins, True)
        if failures:
            logger.warning(f"Failed to import some plugins: {failures}")

        plugin_list = framework.list_plugins()

        return plugin_list

    def parse_plugins_list(self, plugin_list: Dict[str, Any]) -> List[PluginEntry]:
        """todo
        Parsing of get_plugins
        """
        parsed: List[PluginEntry] = list()

        for plugin in plugin_list:
            interface = plugin_list[plugin]
            elements = plugin.split(".")
            platform = elements[0]
            name = elements[-1]

            if platform not in OperatingSystem.to_list():
                plugin = PluginEntry(PluginType.GENERIC, name, interface)
            elif platform == self.os.value:
                plugin = PluginEntry(PluginType.SPECIFIC, name, interface)
            else:
                continue

            parsed.append(plugin)  # type: ignore

        logger.info(f"Found {len(parsed)} plugins for {self.os}")

        return parsed
