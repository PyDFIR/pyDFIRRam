from pathlib import Path

from pydfirram.core.base import Generic, OperatingSystem


def test_generic():
    os = OperatingSystem.WINDOWS
    dumpfile = Path("data/dump.raw")

    generic = Generic(os, dumpfile)

    assert len(generic.plugins) > 0
