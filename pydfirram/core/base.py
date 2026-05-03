"""Create generic volatility3 OS wrappers.

This module provides a way to interact with Volatility3 plugins in a more
abstract way. It allows to automatically get all available plugins for a
specific OS and run them with the required arguments.

Classes:
    OperatingSystem
    PluginType
    PluginEntry
    PluginDescriptor
    PluginRegistry
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
        >>> renderer = generic.run_plugin("windows.pslist")
        >>> # renderer.to_df()

Example (API explicite, recommandée) :

        >>> generic = Generic(os, dumpfile)
        >>> generic.run_plugin("windows.pslist").to_df()

    Compatibilité : l\'accès par attribut (``generic.pslist()``) reste disponible mais
    émet une :exc:`DeprecationWarning`. Voir aussi :meth:`Generic.run_plugin` et
    :meth:`Generic.list_plugins`.
"""

import os
import shutil
import threading
import time
import uuid
import warnings
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

from pydfirram.core.handler import (
    OutputCollisionPolicy,
    create_file_handler,
)
from pydfirram.core.renderer import Renderer
from pydfirram.core.exceptions import (
    PluginNotFoundError,
    PluginTimeoutError,
    VolatilityContextError,
)
from pydfirram.core.workspace import (
    ArtifactManager,
    RunManifest,
    RunStatus,
    RunWorkspacePaths,
    WorkspaceManager,
    _volatility_version,
    relativize_existing_files,
    sanitize_run_identifier,
)


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


@dataclass(frozen=True)
class PluginDescriptor:
    """Métadonnées stables pour un plugin Volatility3 (nom complètement qualifié + entrée runtime).

    Le nom court (suffixe après le dernier ``.``) reste utilisé comme :attr:`PluginEntry.name`
    pour la compatibilité avec l\'API historique (:meth:`Generic.get_plugin`).
    """

    fq_name: str
    type: PluginType
    interface: V3PluginInterface

    @property
    def name(self) -> str:
        """Nom court utilisé comme clé dynamique ``windows.pslist`` → ``pslist``."""
        return self.fq_name.split(".")[-1].lower()

    def as_plugin_entry(self) -> PluginEntry:
        """Construit l\'entrée attendue par :meth:`Generic.run_plugin` / le contexte Volatility3."""
        return PluginEntry(self.type, self.name, self.interface)


class PluginRegistry:
    """Registre des plugins Volatility3 visibles pour un OS, mis en cache par version Volatility3.

    La découverte (import + ``list_plugins``) n\'est exécutée qu\'une fois par couple
    ``(version_volatility, operating_system)`` tant que le cache n\'est pas invalidé.
    """

    _cache: dict[tuple[str, str], PluginRegistry] = {}
    _lock = threading.Lock()

    def __init__(
        self,
        operating_system: OperatingSystem,
        descriptors: tuple[PluginDescriptor, ...],
    ) -> None:
        self._operating_system = operating_system
        self._descriptors = descriptors
        self._entries: tuple[PluginEntry, ...] = tuple(
            d.as_plugin_entry() for d in descriptors
        )

    @property
    def operating_system(self) -> OperatingSystem:
        return self._operating_system

    @property
    def descriptors(self) -> tuple[PluginDescriptor, ...]:
        return self._descriptors

    def to_plugin_entries(self) -> list[PluginEntry]:
        return list(self._entries)

    def list_fq_names(self) -> list[str]:
        """Noms plugins tels que retournés par Volatility (ex. ``windows.pslist``)."""
        return sorted(d.fq_name for d in self._descriptors)

    def resolve(self, name: str) -> PluginDescriptor:
        """Résout par nom court ou par nom qualifié (comparaison insensible à la casse)."""
        key = name.strip()
        lower = key.lower()
        if not lower:
            raise PluginNotFoundError("Nom de plugin vide.")
        if "." in lower:
            for d in self._descriptors:
                if d.fq_name.lower() == lower:
                    return d
            raise PluginNotFoundError(
                f"Plugin '{name}' introuvable pour {self._operating_system.value}.",
            )

        matches = [d for d in self._descriptors if d.name == lower]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            fqs = ", ".join(sorted(m.fq_name for m in matches))
            raise PluginNotFoundError(
                f"Le nom '{name}' est ambigu pour {self._operating_system.value}. "
                f"Préciser le nom qualifié, par ex. parmi : {fqs}",
            )
        raise PluginNotFoundError(f"Plugin '{name}' introuvable pour {self._operating_system.value}.")

    def contains(self, name: str) -> bool:
        try:
            self.resolve(name)
        except PluginNotFoundError:
            return False
        return True

    @classmethod
    def clear_cache(cls) -> None:
        """Vide le cache de découverte (tests / rechargement plugins)."""
        with cls._lock:
            cls._cache.clear()

    @classmethod
    def for_platform(cls, operating_system: OperatingSystem) -> PluginRegistry:
        vol_key = _volatility_version()
        cache_key = (vol_key, operating_system.value)
        with cls._lock:
            existing = cls._cache.get(cache_key)
            if existing is not None:
                return existing
            built = cls._build_for_os(operating_system)
            cls._cache[cache_key] = built
            return built

    @staticmethod
    def _raw_plugin_map() -> dict[str, Any]:
        failures = v3_framework_import_files(
            base_module=v3_framework_plugins_mod,
            ignore_errors=True,
        )
        if failures:
            logger.warning(f"Failed to import some plugins: {failures}")
        return cast(dict[str, Any], v3_framework_list_plugins())

    @classmethod
    def _build_for_os(cls, operating_system: OperatingSystem) -> PluginRegistry:
        plugin_list = cls._raw_plugin_map()
        parsed: list[PluginDescriptor] = []
        for fq_name, interface in plugin_list.items():
            elements = fq_name.split(".")
            platform = elements[0]
            if platform not in OperatingSystem.to_list():
                type_ = PluginType.GENERIC
            elif platform == operating_system.value:
                type_ = PluginType.SPECIFIC
            else:
                continue
            parsed.append(PluginDescriptor(fq_name=fq_name, type=type_, interface=interface))
        logger.info(f"Found {len(parsed)} plugins for {operating_system}")
        return PluginRegistry(operating_system, tuple(parsed))


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
        output_dir: Optional[Path] = None,
        *,
        workspace_paths: Optional[RunWorkspacePaths] = None,
        workspace_run_id: Optional[str] = None,
        collision_policy: OutputCollisionPolicy = "fail",
    ):
        """Initializes a context.

        Args:
            operating_system (OperatingSystem): The operating system.
            dump_file (Path): The dump file path.
            plugin (PluginEntry): The plugin entry.
            workspace_paths (RunWorkspacePaths|None): When set, artefacts are
                        stored under structured ``runs/<run_id>/``. Requires
                        *workspace_run_id*.
        """
        self.os = operating_system
        self.dump_file = dump_file
        self.context = V3Context()
        self.plugin = plugin
        self.automag: Any = None
        self.collision_policy = collision_policy
        self.workspace_paths = workspace_paths
        resolved_output = Path(output_dir).expanduser().resolve() if output_dir else Path.cwd().resolve()

        if workspace_paths is not None:
            if workspace_run_id is None:
                raise VolatilityContextError(
                    "workspace_run_id est requis lorsque workspace_paths est fourni."
                )
            self.run_id = sanitize_run_identifier(workspace_run_id)
            self.output_dir = workspace_paths.root
            self.run_output_dir = workspace_paths.extracted.resolve()
            return

        self.run_id = uuid.uuid4().hex
        self.output_dir = resolved_output
        self.run_output_dir = resolved_output / self.run_id

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
        if self.workspace_paths is None:
            file_handler = create_file_handler(
                str(self.output_dir),
                collision_policy=self.collision_policy,
                run_id=self.run_id,
            )
        else:
            file_handler = create_file_handler(
                str(self.run_output_dir),
                collision_policy=self.collision_policy,
                run_id=self.run_id,
                use_run_subdirectory=False,
                temp_parent=str(self.workspace_paths.tmp.resolve()),
            )
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
            raise
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
        dump_file (Path): The dump file path.
        context (Context): The context.

    Les plugins disponibles sont découverts via :class:`PluginRegistry` (cache par version
    Volatility3) ; :attr:`plugins` est une propriété lecture seule.
    """

    #---
    # Magic methods
    #---

    def __init__(
        self,
        operating_system: OperatingSystem,
        dump_file: Path,
        timeout: Optional[float] = None,
        *,
        workspace_base: Optional[Path] = None,
        output_collision_policy: OutputCollisionPolicy = "fail",
        manifest_include_dump_sha256: bool = False,
    ):
        """Initializes a generic OS.

        Les plugins sont chargés depuis le cache Volatility3 à la première lecture
        de :attr:`plugins`, :meth:`get_plugin`, etc.

        Args:
            operating_system (OperatingSystem): The operating system.
            dump_file (Path): The dump file path.
            timeout (float|None): Default plugin execution deadline in seconds.

        Raises:
            FileNotFoundError: If the dump file does not exist.
        """
        self.validate_dump_file(dump_file)
        self.os = operating_system
        self.dump_file = dump_file
        self.context: Optional[Context] = None
        self.temp_data = None
        self.tmp_plugin: Optional[PluginEntry] = None
        self.timeout = self._validate_timeout(timeout, "timeout")

        resolved_workspace_base = Path(workspace_base).expanduser().resolve() if workspace_base else None
        self.workspace_base = resolved_workspace_base

        self.output_collision_policy = output_collision_policy
        self.manifest_include_dump_sha256 = manifest_include_dump_sha256
        self._run_manifest: Optional[RunManifest] = None
        self._artifact_manager: Optional[ArtifactManager] = None

        logger.info(f"Generic OS initialized: {self.os}")

    @property
    def plugins(self) -> list[PluginEntry]:
        """Entrées plugins pour cet OS (:class:`PluginRegistry` mis en cache)."""
        return self.get_all_plugins()

    def __getattr__(
        self,
        key: str,
        **kwargs: dict[str, Any]
    ) -> Callable[..., Renderer]:
        """
        Compatibilité : accès dynamique au style ``instance.pslist()``.

        Préférer :meth:`run_plugin` avec un nom qualifié (ex. ``"windows.pslist"``).

        Déprécié depuis la couche registre : émet une :exc:`DeprecationWarning`.
        """
        if key.startswith("_"):
            raise AttributeError(key)
        warnings.warn(
            "Accès dynamique aux plugins déprécié (ex. obj.pslist()) ; utilisez "
            "obj.run_plugin(\"windows.pslist\", ...). Voir Generic.run_plugin et la doc du module.",
            DeprecationWarning,
            stacklevel=2,
        )
        key_lc = key.lower()
        try:
            plugin_entry: PluginEntry = self.get_plugin(key_lc)
        except PluginNotFoundError as exc:
            raise ValueError(f"Unable to handle {key_lc}") from exc

        def parse_data_function(**nested_kwargs: Any) -> Renderer:
            merged = {**nested_kwargs}
            return self.run_plugin(plugin_entry, **merged)

        return parse_data_function

    #---
    # Internals methods
    #---

    def _registry(self) -> PluginRegistry:
        return PluginRegistry.for_platform(self.os)

    def _coerce_to_plugin_entry(
        self, plugin: str | PluginEntry | PluginDescriptor
    ) -> PluginEntry:
        if isinstance(plugin, PluginEntry):
            return plugin
        if isinstance(plugin, PluginDescriptor):
            return plugin.as_plugin_entry()
        return self.get_plugin(plugin)

    def _validate_timeout(self, timeout: Optional[float], field_name: str) -> Optional[float]:
        """Validate timeout values for plugin execution."""
        if timeout is None:
            return None
        if timeout <= 0:
            raise ValueError(
                f"La valeur '{field_name}' doit etre un nombre positif en secondes."
            )
        return timeout

    def _effective_timeout(self, timeout: Optional[float]) -> Optional[float]:
        """Resolve run timeout from per-call and instance-level values."""
        return self._validate_timeout(timeout, "timeout") if timeout is not None else self.timeout

    def _cleanup_timeout_artifacts(self, plugin_name: str) -> None:
        """Best-effort cleanup for temporary artifacts after a timeout."""
        if self.context is None:
            return

        scan_dirs = [self.context.run_output_dir]
        wp = getattr(self.context, "workspace_paths", None)
        if wp is not None:
            scan_dirs.insert(0, wp.tmp)

        for run_output_dir in scan_dirs:
            if not run_output_dir.exists():
                continue

            try:
                temp_files = list(run_output_dir.glob("tmp_*.vol3"))
                for temp_file in temp_files:
                    try:
                        temp_file.unlink()
                    except FileNotFoundError:
                        continue
                    except OSError as err:
                        logger.warning(
                            "Unable to remove temp file '{}' after timeout of plugin '{}': {}",
                            temp_file,
                            plugin_name,
                            err,
                        )

                if wp is None and run_output_dir == self.context.run_output_dir:
                    remaining = list(run_output_dir.iterdir())
                    if not remaining:
                        shutil.rmtree(run_output_dir, ignore_errors=True)
            except OSError as err:
                logger.warning(
                    "Timeout cleanup failed for plugin '{}' in '{}': {}",
                    plugin_name,
                    run_output_dir,
                    err,
                )

    def _run_with_timeout(
        self,
        run_callable: Callable[[], Any],
        plugin_name: str,
        timeout: Optional[float],
    ) -> Any:
        """Execute plugin run callable with an optional thread-level timeout."""
        effective_timeout = self._effective_timeout(timeout)
        if effective_timeout is None:
            return run_callable()

        result: dict[str, Any] = {"value": None, "error": None}

        def runner() -> None:
            try:
                result["value"] = run_callable()
            except BaseException as exc:
                result["error"] = exc

        worker = threading.Thread(
            target=runner,
            name=f"volatility-run-{plugin_name}",
            daemon=True,
        )
        started_at = time.monotonic()
        worker.start()
        worker.join(timeout=effective_timeout)

        if worker.is_alive():
            elapsed = time.monotonic() - started_at
            logger.error(
                "Volatility plugin '{}' timed out after {:.2f}s (configured timeout: {:.2f}s).",
                plugin_name,
                elapsed,
                effective_timeout,
            )
            logger.warning(
                "Thread-level timeout cannot interrupt underlying Volatility execution immediately. "
                "A future process-isolated runner should be used for hard kills."
            )
            self._cleanup_timeout_artifacts(plugin_name)
            raise PluginTimeoutError(
                f"Le plugin '{plugin_name}' a depasse le delai ({effective_timeout:.2f}s)."
            )

        if result["error"] is not None:
            raise result["error"]

        return result["value"]

    def _build_runable_context(
        self,
        plugin: PluginEntry,
        kwargs: dict[str, Any],
        *,
        workspace_paths: Optional[RunWorkspacePaths] = None,
        workspace_run_id: Optional[str] = None,
    ) -> Any:
        """Build and configure runnable Volatility context for a plugin."""
        self.context = Context(  # type: ignore[arg-type]
            self.os,
            self.dump_file,
            plugin,
            workspace_paths=workspace_paths,
            workspace_run_id=workspace_run_id,
            collision_policy=self.output_collision_policy,
        )
        self.context.set_automagic()
        self.context.set_context()
        builded_context = self.context.build()  # type: ignore[assignment]
        if kwargs:
            return self.context.add_arguments(builded_context, kwargs)
        return builded_context

    def _finalize_run_workspace(
        self,
        ws_paths: RunWorkspacePaths,
        status: RunStatus,
        errors: list[str],
    ) -> None:
        manifest = self._run_manifest
        if manifest is None:
            return
        if self.manifest_include_dump_sha256:
            manifest.compute_dump_sha256()

        artifact_refs: list[str] = []
        if self._artifact_manager is not None:
            artifact_refs = self._artifact_manager.outputs()

        discovered = relativize_existing_files(
            ws_paths.root,
            (ws_paths.logs, ws_paths.tables, ws_paths.extracted, ws_paths.tmp),
        )
        combined = sorted(set(discovered).union(artifact_refs))

        manifest.finalize(
            status=status,
            errors=errors or None,
            output_files=combined if combined else None,
        )
        manifest.write_json(ws_paths.manifest)

    #---
    # Public methods
    #---

    # (todo) : more explicit return type
    def run_plugin(
        self,
        plugin: str | PluginEntry | PluginDescriptor,
        timeout: Optional[float] = None,
        **plugin_kwargs: Any,
    ) -> Renderer:
        """Exécute un plugin Volatility3 et retourne un :class:`Renderer`.

        Permet la chaîne explicite ``instance.run_plugin(\"windows.pslist\").to_df()``.

        Args:
            plugin: Nom qualifié (ex. ``\"windows.pslist\"``), nom court (ex. ``\"pslist\"``),
                    :class:`PluginEntry` ou :class:`PluginDescriptor`.
            timeout: Éventuel délai d\'exécution (secondes).
            **plugin_kwargs: Arguments transmis au contexte/config du plugin.

        Returns:
            :class:`Renderer` enveloppant le résultat Volatility brut (``renderer.data``).

        Raises:
            PluginNotFoundError: Si aucun plugin ne correspond.
            VolatilityContextError: Si le contexte n\'a pas été construit.
        """
        plugin = self._coerce_to_plugin_entry(plugin)
        self._run_manifest = None
        self._artifact_manager = None

        tracked_workspace: Optional[RunWorkspacePaths] = None
        tracked_run_uuid: Optional[str] = None

        if self.workspace_base is not None:
            workspace_manager = WorkspaceManager(self.workspace_base)
            tracked_run_uuid, tracked_workspace = workspace_manager.create_run_workspace()
            self._run_manifest = RunManifest.start_shell(
                run_id=tracked_run_uuid,
                plugin_name=plugin.name,
                dump_path=self.dump_file,
                kwargs=dict(plugin_kwargs),
            )
            self._artifact_manager = ArtifactManager(
                run_root=tracked_workspace.root,
                collision_policy=self.output_collision_policy,
            )

        exec_status = RunStatus.SUCCESS
        exec_errors: list[str] = []
        result: Optional[Any] = None

        try:
            runnable_context = self._build_runable_context(
                plugin,
                dict(plugin_kwargs),
                workspace_paths=tracked_workspace,
                workspace_run_id=tracked_run_uuid,
            )

            if self.context is None:
                raise VolatilityContextError(
                    "Le contexte Volatility n'a pas ete construit correctement."
                )

            logger.debug(
                "Running plugin '{}' with timeout={}s and args={}",
                plugin.name,
                self._effective_timeout(timeout),
                list(plugin_kwargs.keys()),
            )
            result = self._run_with_timeout(runnable_context.run, plugin.name, timeout)
        except PluginTimeoutError as exc:
            exec_status = RunStatus.TIMEOUT
            exec_errors.append(str(exc))
            raise
        except BaseException as exc:
            exec_status = RunStatus.FAILED
            exec_errors.append(repr(exc))
            raise
        finally:
            if self.workspace_base is not None and tracked_workspace is not None:
                self._finalize_run_workspace(tracked_workspace, exec_status, exec_errors)

        return Renderer(data=result)

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
        """Résout un plugin par nom court ou nom qualifié Volatility.

        Raises:
            PluginNotFoundError: Si le nom est inconnu ou ambigu (plusieurs fq identiques courts).
        """
        return self._registry().resolve(name).as_plugin_entry()

    def get_all_plugins(self) -> list[PluginEntry]:
        """Liste des entrées disponibles pour l\'OS du wrapper (cache Volatility par version)."""
        return self._registry().to_plugin_entries()

    def list_plugins(self, os_filter: Optional[OperatingSystem] = None) -> list[str]:
        """Noms qualifiés des plugins disponibles pour un OS (:class:`OperatingSystem`)."""
        target = os_filter if os_filter is not None else self.os
        return PluginRegistry.for_platform(target).list_fq_names()

    def has_plugin(self, plugin_name: str) -> bool:
        """Indique si ``plugin_name`` est résoluble (court ou fq) pour l\'OS courant."""
        return self._registry().contains(plugin_name)

    def plugin_info(self, plugin_name: str) -> PluginDescriptor:
        """Métadonnées :class:`PluginDescriptor` pour un nom court ou qualifié."""
        return self._registry().resolve(plugin_name)
