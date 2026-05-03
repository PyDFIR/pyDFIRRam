"""Create generic volatility3 OS wrappers.

This module provides a way to interact with Volatility3 plugins in a more
abstract way. It allows to automatically get all available plugins for a
specific OS and run them with the required arguments.

Classes:
    Windows

Example (API recommandée) :

        $ python3
        >>> from pydfirram.modules.windows import Windows
        >>> from pathlib import Path
        >>> dumpfile = Path("tests/data/dump.raw")
        >>> windows = Windows(dumpfile)
        >>> windows.run_plugin(\"windows.pslist\").to_df()

    Migration depuis l\'API dynamique :
        **Avant** : ``windows.pslist().to_df()``
        **Après** : ``windows.run_plugin(\"windows.pslist\").to_df()``

        L\'accès par attribut conserve le même comportement mais émet un
        :exc:`DeprecationWarning` et doit être évité dans le code pérenne vers un SDK stable.

Legacy / compatibilité :

        >>> windows.pslist(pid=[...]).to_list()
"""
from typing import Any, Optional

from pydfirram.core.handler import OutputCollisionPolicy
from pathlib import Path

from pydfirram.core.base import Generic, OperatingSystem


class Windows(Generic):
    """
    A wrapper class for utilizing Windows-specific functionalities around
    the base methods.

    This class serves as a simplified interface for interacting with
    Windows operating system dumps. It inherits from the Generic class and
    initializes with Windows as the operating system.

    Attributes:
    -----------
    dumpfile : str
        The path to the memory dump file.

    Methods:
    --------
    __init__(dumpfile)
        Initializes the Windows class with the given dump file.
    """
    def __init__(
        self,
        dumpfile: str | Path,
        timeout: Optional[float] = None,
        *,
        workspace_base: Optional[str | Path] = None,
        output_collision_policy: OutputCollisionPolicy = "fail",
        manifest_include_dump_sha256: bool = False,
    ) -> None:
        """
        Initializes the Windows class.

        Parameters:
        -----------
        dumpfile : str
            The path to the memory dump file.

        Example:
        --------
        >>> windows = Windows("path/to/dump.raw": Path)
        """
        if isinstance(dumpfile, str):
            dumpfile = Path(dumpfile)
        self.dump_files = dumpfile
        resolved_workspace = (
            Path(workspace_base).expanduser().resolve() if workspace_base is not None else None
        )
        super().__init__(
            operating_system=OperatingSystem.WINDOWS,
            dump_file=dumpfile,
            timeout=timeout,
            workspace_base=resolved_workspace,
            output_collision_policy=output_collision_policy,
            manifest_include_dump_sha256=manifest_include_dump_sha256,
        )

    # (todo) : seems to be a boilerplate from `Context`
    # (todo) : add typing information
    def _set_argument(self, context, prefix, kwargs):
        for k, v in kwargs.items():
            print(k,v)
            context.config[prefix+k] = v
        return context

    def dumpfiles(
        self,
        timeout: Optional[float] = None,
        **_kwargs: dict[str,Any],
    ) -> None:
        """
            Dump memory files based on provided parameters.

            This method utilizes the "dumpfiles" plugin to create memory
            dumps from a Windows operating system context. The memory dumps
            can be filtered based on the provided arguments. If no
            parameters are provided, the method will dump the entire
            system by default.

            Parameters:
            -----------
            physaddr : int, optional
                The physical address offset for the memory dump.
            virtaddr : int, optional
                The virtual address offset for the memory dump.
            pid : int, optional
                The process ID for which the memory dump should be
                generated.

            Notes:
            ------
            - The method sets up the context with the operating system
                and dump files.
            - Automagic and context settings are configured before
                building the context.
            - If additional keyword arguments are provided, they are
                added as arguments to the context.
            - The resulting context is executed and rendered to a file
                using the Renderer class.
            - If no parameters are provided, the method will dump the
                entire system by default.

            Returns:
            --------
            None
            """
        self.run_plugin("dumpfiles", timeout=timeout, **_kwargs).file_render()
