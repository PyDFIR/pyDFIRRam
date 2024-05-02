"""Create generic volatility3 OS wrappers.

This module provides a way to interact with Volatility3 plugins in a more
abstract way. It allows to automatically get all available plugins for a
specific OS and run them with the required arguments.

Classes:
    OperatingSystem
    PluginType
    PluginEntry
    Context
    Generic
"""

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List

from loguru import logger
from volatility3 import framework, plugins
from volatility3.framework import automagic, contexts
from volatility3.framework import exceptions as VolatilityExceptions
from volatility3.framework import interfaces
from volatility3.framework.plugins import construct_plugin

from pydfirram.core.handler import create_file_handler


class OperatingSystem(Enum):
    """Supported operating system.

    Attributes:
        WINDOWS: Windows OS.
        LINUX: Linux OS.
        MACOS: MacOS OS.
    """

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "mac"

    @staticmethod
    def to_list() -> List[str]:
        """Returns a list of supported operating systems.
        Returns:
            List[str]: List of supported operating systems.
        """
        return [os.value for os in OperatingSystem]


class PluginType(Enum):
    """A volatiliry3 plugin type.

    Attributes:
        GENERIC: A generic plugin, can be used with any OS.
        SPECIFIC: An OS-specific plugin.
    """

    GENERIC = 1
    SPECIFIC = 2


@dataclass
class PluginEntry:
    """A plugin entry.

    The interface allows to directly interact with the plugin from volatility3 functions.

    Attributes:
        type: PluginType: The plugin type.
        name: str: The plugin name.
        interface: volatility3.framework.interfaces.plugins.PluginInterface: The plugin interface.
    """

    type: PluginType
    name: str
    interface: interfaces.plugins.PluginInterface

    def __repr__(self) -> str:
        """Returns a string representation of the plugin entry."""
        return f"PluginEntry({self.type}, {self.name}, {self.interface})"


class Context:
    """Context for a volatility3 plugin.

    Attributes:
        os: OperatingSystem: The operating system.
        dump_file: Path: The dump file path.
        context: volatility3.framework.contexts.Context: The volatility3 context.
        plugin: PluginEntry: The plugin entry.

    Constants:
        KEY_LAYER_STACKER: str: The layer stacker key.
        KEY_STACKERS: str: The stackers key.
        KEY_SINGLE_LOCATION: str: The single location key.
    """

    KEY_LAYER_STACKER = "automagic.LayerStacker"
    KEY_STACKERS = f"{KEY_LAYER_STACKER}.stackers"
    KEY_SINGLE_LOCATION = f"{KEY_LAYER_STACKER}.single_location"

    def __init__(
        self,
        operating_system: OperatingSystem,
        dump_file: Path,
        plugin: PluginEntry,
    ):
        """Initializes a context.

        Args:
            operating_system (OperatingSystem): The operating system.
            dump_file (Path): The dump file path.
            plugin (PluginEntry): The plugin entry.
        """
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
        """Build a basic context for the provided plugin.

        Returns:
            interfaces.plugins.PluginInterface: The built plugin interface.

        Raises:
            VolatilityExceptions.UnsatisfiedException: If the plugin cannot be built.
        """
        plugin = self.plugin.interface
        automagics = self.automagics()
        dump_file_location = self.get_dump_file_location()
        base_config_path = "plugins"
        file_handler = create_file_handler(os.getcwd())

        self.context.config[self.KEY_STACKERS] = self.os_stackers()
        self.context.config[self.KEY_SINGLE_LOCATION] = dump_file_location

        try:
            # Construct the plugin, clever magic figures out how to
            # fulfill each requirement that might not be fulfilled
            constructed = construct_plugin(
                self.context,
                automagics,
                plugin,  # type: ignore
                base_config_path,
                None,  # no progress callback for now
                file_handler,
            )
        except VolatilityExceptions.UnsatisfiedException as e:
            logger.error(f"Failed to build plugin: {e}")
            raise e

        return constructed

    def add_arguments(self, kwargs: Dict[str, Any]) -> None:
        """Handle keyword arguments and set them as context config attributes.

        Args:
            kwargs (Dict[str, Any]): The keyword arguments.

        Raises:
            AttributeError: If the attribute does not exist.
        """
        for key, value in kwargs.items():
            setattr(self.context.config, key, value)

    def run(self) -> Any:
        """Run the plugin in the context.

        Returns:
            Any: The result of the plugin.

        Raises:
            VolatilityExceptions.UnsatisfiedException: If the plugin cannot be run.
        """
        try:
            return self.context.run()
        except VolatilityExceptions.UnsatisfiedException as e:
            logger.error(f"Failed to run plugin: {e}")
            raise e

    def get_available_automagics(self) -> List[interfaces.automagic.AutomagicInterface]:
        """Returns a list of available automagics."""
        return automagic.available(self.context)

    def automagics(self) -> List[interfaces.automagic.AutomagicInterface]:
        """Returns a list of automagics."""
        available_automagics = self.get_available_automagics()

        return automagic.choose_automagic(
            available_automagics,  # type: ignore
            self.plugin.interface,  # type: ignore
        )

    def os_stackers(self) -> List[interfaces.automagic.AutomagicInterface]:
        """Returns a list of stackers for the OS."""
        return automagic.stacker.choose_os_stackers(self.plugin.interface)

    def get_dump_file_location(self) -> str:
        """Returns the dump file location."""
        return "file://" + self.dump_file.absolute().as_posix()


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
        self.context.add_arguments(kwargs)

        # Build the context
        context = self.context.build()

        # Run the plugin
        if self.context is None:
            raise ValueError("Context not built.")

        return context.run()

    def validate_dump_file(self, dump_file: Path) -> Path:
        """Validates the dump file."""
        if not dump_file.is_file():
            raise FileNotFoundError(f"The file {dump_file} does not exist.")
        # TODO: validate the dump file with volatility handlers
        return dump_file

    def get_plugin(self, name: str) -> PluginEntry:
        """Returns a plugin by name."""
        for plugin in self.plugins:
            if plugin.name == name:
                return plugin

        raise ValueError(f"Plugin {name} not found for {self.os}")

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
                type_ = PluginType.GENERIC
            elif platform == self.os.value:
                type_ = PluginType.SPECIFIC
            else:
                continue

            plugin = PluginEntry(type_, name, interface)
            parsed.append(plugin)  # type: ignore

        logger.info(f"Found {len(parsed)} plugins for {self.os}")

        return parsed
