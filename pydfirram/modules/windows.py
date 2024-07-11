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
            context.config[prefix+k] = int(v)
        return context

    def dumpfile(self,**kwargs) -> None:
        plugin = self.get_plugin("dumpfiles")
        context = Context(OperatingSystem.WINDOWS, self.dump_files, plugin) # type: ignore
        context.set_automagic()
        context.set_context()
        runable_context = context.build()
        if kwargs:
            context.add_arguments(context,kwargs)
            #self._set_argument(context.context,"plugins.DumpFiles.",kwargs)
        Renderer(runable_context.run()).file_render()

    def dumpfile_pid(self,**kwargs) -> None:
        plugin = self.get_plugin("dumpfiles")
        context = Context(OperatingSystem.WINDOWS, self.dump_files, plugin) # type: ignore
        
        runable_context =context.build()
        runable_context.config["plugins.DumpFiles.pid"] = 4
        #if kwargs:
        #    self._set_argument(runable_context,"plugins.DumpFiles.",kwargs)
        Renderer(runable_context.run()).file_render()
