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

Example:
    The module can be used as follows:

        $ python3
        >>> from pydfirram.core.base import Generic, OperatingSystem
        >>> from pathlib import Path
        >>> os = OperatingSystem.WINDOWS
        >>> dumpfile = Path("tests/data/dump.raw")
        >>> generic = Generic(os, dumpfile)
        >>> plugin = generic.get_plugin("Banners")
        >>> generic.run_plugin(plugin)

Example:
    Or it can be used as follow :

        $ python3
        >>> from pydfirram.core.base import Generic, OperatingSystem
        >>> from pathlib import Path
        >>> os = OperatingSystem.WINDOWS
        >>> dumpfile = Path("tests/data/dump.raw")
        >>> generic = Generic(dumpfile)
        >>> plugin = generic.pslist().to_df()
        >>> print(plugin)
"""

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Optional, cast
from collections.abc import Callable


from loguru import logger
from volatility3.framework import (                         # type: ignore
    import_files            as v3_framework_import_files,
    list_plugins            as v3_framework_list_plugins,
)

from volatility3 import (
    plugins                 as v3_framework_plugins_mod,

)
from volatility3.framework.contexts import (                # type: ignore
    Context                 as V3Context,
)
from volatility3.framework.interfaces.plugins import (      # type: ignore
    PluginInterface         as V3PluginInterface,
)
from volatility3.framework.exceptions import (              # type: ignore
    UnsatisfiedException    as V3UnsatisfiedException,
)
from volatility3.framework.plugins import (                 # type: ignore
    construct_plugin        as v3_construct_plugin,
)
from volatility3.framework.interfaces.automagic import (    # type: ignore
    AutomagicInterface      as V3AutomagicInterface,
)
from volatility3.framework.automagic import (               # type: ignore
    available               as v3_automagic_available,
    choose_automagic        as v3_automagic_choose,
)
from volatility3.framework.automagic.stacker import (       # type: ignore
    choose_os_stackers      as v3_choose_os_stackers,
)

from pydfirram.core.handler import create_file_handler
from pydfirram.core.renderer import Renderer


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
    def to_list() -> list[str]:
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
class PluginEntry():
    """A plugin entry.

    The interface allows to directly interact with the plugin from
    volatility3 functions.

    Attributes:
        type: PluginType: The plugin type.
        name: str: The plugin name.
        interface: PluginInterface: The (volatility3) plugin interface.
    """

    type: PluginType
    name: str
    interface: V3PluginInterface

    def __repr__(self) -> str:
        """Returns a string representation of the plugin entry."""
        return f"PluginEntry({self.type}, {self.name}, {self.interface})"


class Context():
    """Context for a volatility3 plugin.

    Attributes:
        os: OperatingSystem: The operating system.
        dump_file: Path: The dump file path.
        context: V3Context: The volatility3 context.
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
        self.context = V3Context()
        self.plugin = plugin
        self.automag: Any = None

    def set_context(self) -> None:
        """ setup the current context """
        dump_file_location = self.get_dump_file_location()
        self.context.config[self.KEY_STACKERS] = self.os_stackers()
        self.context.config[self.KEY_SINGLE_LOCATION] = dump_file_location

    def set_automagic(self) -> None:
        """ setup the automagics """
        self.automag = self.automagics()

    def build(self) -> V3PluginInterface:
        """Build a basic context for the provided plugin.

        Returns:
            interfaces.plugins.PluginInterface: The built plugin interface.

        Raises:
            V3UnsatisfiedException: If the plugin cannot be built.
        """
        plugin = self.plugin.interface
        base_config_path = "plugins"
        file_handler = create_file_handler(os.getcwd())
        try:
            # Construct the plugin, clever magic figures out how to
            # fulfill each requirement that might not be fulfilled
            # @notes
            # - As many volatility3 internals, some of the argument mismatch
            # because type awaiting by the framework is, for exemple,
            # `type[PluginInterface]` and we give a `PluginInterface` wich
            # is the same thing...So, lets cast to `Any` to avoid embrouille
            constructed = v3_construct_plugin(
                self.context,
                self.automag,
                cast(Any, plugin),
                base_config_path,
                None,  # no progress callback for now
                file_handler,
            )
        except V3UnsatisfiedException as err:
            logger.error(f"Failed to build plugin: {err}")
            raise err
        return constructed

    def add_arguments(
        self,
        context: V3Context,
        kwargs: dict[str, Any]
    ) -> V3Context:
        """
        Handle keyword arguments and set them as context config attributes.

        Args:
            kwargs (dict[str, Any]): The keyword arguments.

        Raises:
            AttributeError: If the attribute does not exist.
        """
        for k, v in kwargs.items():
            context.config[k] = v
        return context


    def get_available_automagics(self) -> list[V3AutomagicInterface]:
        """Returns a list of available volatility3 automagics.

        Returns:
            List[V3AutomagicInterface]: A list of available automagics.
        """
        return cast(
            list[V3AutomagicInterface],
            v3_automagic_available(self.context),
        )

    def automagics(self) -> list[V3AutomagicInterface]:
        """Returns a list of volatility3 automagics.

        Returns:
            List[V3AutomagicInterface]: A list of automagics.

        Raises:
            V3UnsatisfiedException: If no automagic can be chosen.
        """
        available_automagics = self.get_available_automagics()
        # @notes
        # It seems that `choose_automagic` require weird typing information
        # that should match what we give to this bastard, but it's not
        # since, for example, our `PluginInterface` do not match the
        # `type[PluginInterface]` awaited...even if its the same type :pouce:
        # So, let's cast all argument to Any to avoid typing collision
        return cast(
            list[V3AutomagicInterface],
            v3_automagic_choose(
                cast(Any, available_automagics),
                cast(Any, self.plugin.interface),
            ),
        )

    def os_stackers(self) -> list[V3AutomagicInterface]:
        """Returns a list of stackers for the OS.

        Returns:
            List[V3AutomagicInterface]: A list of (volatility3) stackers.
        """
        return cast(
            list[V3AutomagicInterface],
            v3_choose_os_stackers(cast(Any,self.plugin.interface)),
        )

    def get_dump_file_location(self) -> str:
        """Returns the dump file location.

        Returns:
            str: The dump file location formatted as a URL.
        """
        return "file://" + self.dump_file.absolute().as_posix()


class Generic():
    """Generic OS wrapper to be used with volatility3

    This class provides a way to interact with volatility3 plugins in a more
    abstract way. It allows to automatically get all available plugins for a
    specific OS and run them with the required arguments.

    It aims to be inherited by specific OS wrappers like Windows, Linux or
    MacOS.

    Attributes:
        os (OperatingSystem): The operating system.
        plugins (List[PluginEntry]): The list of plugins.
        dump_file (Path): The dump file path.
        context (Context): The context.
    """

    #---
    # Magic methods
    #---

    def __init__(self, operating_system: OperatingSystem, dump_file: Path):
        """Initializes a generic OS.

        Automatically get all available Volatility3 plugins for the OS.

        Args:
            operating_system (OperatingSystem): The operating system.
            dump_file (Path): The dump file path.

        Raises:
            FileNotFoundError: If the dump file does not exist.
        """
        self.validate_dump_file(dump_file)
        self.os = operating_system
        self.plugins: list[PluginEntry] = self.get_all_plugins()
        self.dump_file = dump_file
        self.context: Optional[Context] = None
        self.temp_data = None
        self.tmp_plugin: Optional[PluginEntry] = None

        logger.info(f"Generic OS initialized: {self.os}")

    def __getattr__(
        self,
        key: str,
        **kwargs: dict[str, Any]
    ) -> Callable[...,Renderer]:
        """
        Handle attribute access for commands.

        This method is called when an attribute that
        matches a command name is accessed. It returns a lambda function
        that calls the __run_commands method with the corresponding key.

        :param key: The attribute name (command name).
        :type key: str
        :param args: Positional arguments for the method call.
        :param kwargs: Keyword arguments for the method call.
        :return: A class of Renderer that is the result of a lambda
        function that executes the __run_commands method for the given key.
        """
        key = key.lower()
        try:
            plugin: PluginEntry = self.get_plugin(key)
        except Exception as exc:
            raise ValueError(f"Unable to handle {key}") from exc
        def parse_data_function(**kwargs: dict[str,Any]) -> Renderer:
            return Renderer(
                data    = self.run_plugin(plugin,**kwargs)
            )
        return parse_data_function

    #---
    # Internals methods
    #---

    def _get_plugins_list(self) -> dict[str,Any]:
        """Get a list of available volatility3 plugins for the OS.

        Returns:
            dict[str,Any]: A dictionary of plugins.
        """
        failures = v3_framework_import_files(
            base_module     = v3_framework_plugins_mod,
            ignore_errors   = True
        )
        if failures:
            logger.warning(f"Failed to import some plugins: {failures}")
        return cast(dict[str,Any], v3_framework_list_plugins())

    def _parse_plugins_list(
        self,
        plugin_list: dict[str, Any],
    ) -> list[PluginEntry]:
        """Parse the list of available volatility3 plugins.

        The plugin list is a dictionary where the key is the plugin name
        and the value is the plugin interface.

        Args:
            plugin_list (Dict[str, Any]): The plugin list.

        Returns:
            List[PluginEntry]: A list of PluginEntry.
        """
        parsed: list[PluginEntry] = []
        for plugin in plugin_list:
            interface = plugin_list[plugin]
            elements = plugin.split(".")
            platform = elements[0]
            name = elements[-1]
            name = name.lower()
            if platform not in OperatingSystem.to_list():
                type_ = PluginType.GENERIC
            elif platform == self.os.value:
                type_ = PluginType.SPECIFIC
            else:
                continue
            parsed.append(
                PluginEntry(type_, name, interface),
            )
        logger.info(f"Found {len(parsed)} plugins for {self.os}")
        return parsed

    #---
    # Public methods
    #---

    # (todo) : more explicit return type
    def run_plugin(
        self,
        plugin: PluginEntry,
        **kwargs: dict[str,Any],
    ) -> Any:
        """Run a volatility3 plugin with the given arguments.

        Args:
            plugin (PluginEntry): The plugin entry.
            **kwargs (Any): The keyword arguments.

        Returns:
            Any: The result of the plugin.

        Raises:
            ValueError: If the context is not built.
        """
        # (todo) : move `context.set_*()` in `Context.__init__()` ?
        self.context = Context(self.os, self.dump_file, plugin) # type: ignore
        self.context.set_automagic()
        self.context.set_context()
        builded_context = self.context.build() # type: ignore
        if kwargs:
            runable_context = self.context.add_arguments(builded_context,kwargs)
        else:
            runable_context = builded_context
        if self.context is None:
            raise ValueError("Context not built.")
        return runable_context.run()

    def validate_dump_file(self, dump_file: Path) -> bool:
        """Validate dump file location.

        Args:
            dump_file (Path): The dump file path.

        Returns:
            bool: True if the file exists.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        if dump_file.is_file():
            return True
        raise FileNotFoundError(f"The file {dump_file} does not exist.")

    def get_plugin(self, name: str) -> PluginEntry:
        """Fetches a plugin by its name from the list of plugins.

        Args:
            name (str): The plugin name.

        Returns:
            PluginEntry: The plugin entry.

        Raises:
            ValueError: If the plugin is not found.
        """
        name = name.lower()
        for plugin in self.plugins:
            if plugin.name == name:
                return plugin
        raise ValueError(f"Plugin {name} not found for {self.os}")

    def get_all_plugins(self) -> list[PluginEntry]:
        """Get all available plugins for the specified OS.

        Returns:
            List[PluginEntry]: A list of plugins for the specified OS
            or all available plugins if the OS is not supported.

        Raises:
            ValueError: If the plugin is not found.
        """
        plugin_list = self._get_plugins_list()
        parsed_plugins = self._parse_plugins_list(plugin_list)
        return parsed_plugins
