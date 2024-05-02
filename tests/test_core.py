from pathlib import Path

from volatility3.cli import text_renderer

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

    # This plugin is very generic and doesn't
    # require any additional parameters
    plugin = generic.get_plugin("Banners")
    assert plugin.name == "Banners"

    print("Running plugin: ", plugin)

    output = generic.run_plugin(plugin)
    text_renderer.PrettyTextRenderer().render(output)
