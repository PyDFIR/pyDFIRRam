"""Create generic volatility3 OS wrappers.

This module provides a way to interact with Volatility3 plugins in a more
abstract way. It allows to automatically get all available plugins for a
specific OS and run them with the required arguments.

Classes:
    Windows

Example:
    The module can be used as follows:

        $ python3
        >>> from pydfirram.modules.windows import Windows
        >>> from pathlib import Path
        >>> dumpfile = Path("tests/data/dump.raw")
        >>> generic = Windows(dumpfile)
        >>> plugin = generic.pslist().to_list()

    OR :
        $ python3
        >>> from pydfirram.modules.windows import Windows
        >>> from pathlib import Path
        >>> dumpfile = Path("tests/data/dump.raw")
        >>> generic = Windows(dumpfile)
        >>> plugin = generic.pslist(pid=[4]).to_df()
        >>> print(plugin)
"""

from pydfirram.core.base import Generic, OperatingSystem,Context
from pydfirram.core.renderer import Renderer


class Windows(Generic):
    """
    A wrapper class for utilizing Windows-specific functionalities around the base methods.

    This class serves as a simplified interface for interacting with Windows operating system dumps. 
    It inherits from the Generic class and initializes with Windows as the operating system.

    Attributes:
    -----------
    dumpfile : str
        The path to the memory dump file.

    Methods:
    --------
    __init__(dumpfile)
        Initializes the Windows class with the given dump file.
    """
    def __init__(self, dumpfile):
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
        self.dump_files = dumpfile
        super().__init__(OperatingSystem.WINDOWS, dumpfile)

    def _set_argument(self,context, prefix, kwargs):
        for k, v in kwargs.items():
            print(k,v)
            context.config[prefix+k] = v
        return context

    def dumpfiles(self,**kwargs) -> None:
        """
            Dump memory files based on provided parameters.

            This method utilizes the "dumpfiles" plugin to create memory dumps from a 
            Windows operating system context. The memory dumps can be filtered based 
            on the provided arguments. If no parameters are provided, the method will
            dump the entire system by default.

            Parameters:
            -----------
            physaddr : int, optional
                The physical address offset for the memory dump.
            virtaddr : int, optional
                The virtual address offset for the memory dump.
            pid : int, optional
                The process ID for which the memory dump should be generated.

            Notes:
            ------
            - The method sets up the context with the operating system and dump files.
            - Automagic and context settings are configured before building the context.
            - If additional keyword arguments are provided, they are added as arguments to the context.
            - The resulting context is executed and rendered to a file using the Renderer class.
            - If no parameters are provided, the method will dump the entire system by default.

            Returns:
            --------
            None
            """
        plugin = self.get_plugin("dumpfiles")
        context = Context(OperatingSystem.WINDOWS, self.dump_files, plugin) # type: ignore
        context.set_automagic()
        context.set_context()
        builded_context = context.build()
        if kwargs:
            runable_context = context.add_arguments(builded_context,kwargs)
        else:
            runable_context = builded_context
        Renderer(runable_context.run()).file_render()
