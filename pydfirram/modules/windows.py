from pydfirram.core.base import Generic, OperatingSystem


class Windows(Generic):
    """todo: add docstring here"""

    def __init__(self, dumpfile):
        super().__init__(OperatingSystem.WINDOWS, dumpfile)
