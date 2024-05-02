from pathlib import Path

from pydfirram.core.base import Generic, OperatingSystem

DUMP_FILE = Path("tests/data/dump.raw")


def test_generic():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)

    generic = Generic(os, dumpfile)

    assert len(generic.plugins) > 0


def test_generic_build():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)

    generic = Generic(os, dumpfile)

    plugin = generic.plugins[0]  # random plugin

    generic.run_plugin(plugin)
    assert generic.context is not None

    generic.context.build()
