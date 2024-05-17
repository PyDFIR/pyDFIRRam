from pathlib import Path
from volatility3.cli import text_renderer
from pydfirram.core.base import Generic, OperatingSystem
import pytest

DUMP_FILE = Path("/home/braguette/dataset_memory/ch2.dmp")


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


def test_get_attr():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)

    generic = Generic(os, dumpfile)
    output = generic.PsList()
    assert output

def test_get_unknow_attribute_():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    with pytest.raises(ValueError):
        generic.aaaaa()


## Rendering
def test_prettytextRenderer():
    Ellipsis

def test_csv_renderer():
    Ellipsis

## Faut que je fasse le test de toutes les fonctions ici.
# def test_pslist():
#   s = OperatingSystem.WINDOWS
#   dumpfile = Path(DUMP_FILE)
#   generic = Generic(os, dumpfile)
#   output = generic.PsList()
#   text_renderer.CSVRenderer().render(output)
#   assert...

