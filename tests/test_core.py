from pathlib import Path
from volatility3.cli import text_renderer
from pydfirram.core.base import Generic, OperatingSystem
import pytest

DUMP_FILE = Path("/home/remnux/2600/ch2.dmp")


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

import json
def test_pslist_filter_pid():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)

    generic = Generic(os, dumpfile)
    output = generic.PsList(pid=[4]).to_dict()
    assert output["PID"] == 4

def test_rendering_to_json():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.PsList(pid=[4]).to_json()
    try:
        json.loads(output)
    except ValueError:
        pytest.fail("Not a Json")
   

