import pytest
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem
from pydfirram.modules.windows import Windows
from loguru import logger
DUMP_FILE = Path("/home/remnux/2600/ch2.dmp")

logger.opt(colors=True).info("<b><magenta> TEST PYDFIRRAM BASE FUNCTIONS </magenta></b>")


@pytest.fixture
def generic_instance():
    os = OperatingSystem.WINDOWS
    dumpfile = DUMP_FILE
    return Generic(os, dumpfile)

@pytest.fixture
def windows_instance():
    return Windows(DUMP_FILE)

def test_generic(generic_instance):
    assert len(generic_instance.plugins) > 0

def test_generic_build(generic_instance):
    plugin = generic_instance.get_plugin("Banners")
    assert plugin.name == "banners"
    output = generic_instance.run_plugin(plugin)
    assert output

def test_get_attr(generic_instance):
    output = generic_instance.pslist()
    assert output

def test_get_unknown_attribute(generic_instance):
    with pytest.raises(ValueError):
        generic_instance.aaaaa()

def test_lowercase_function_call(generic_instance):
    output = generic_instance.pslist(pid=[4]).to_list()[0]
    assert output["PID"] == 4

def test_easy_import_pydfir(windows_instance):
    try:
        windows_instance.pslist()
    except Exception as e:
        pytest.fail(f"Windows import from pydfir fails:: {str(e)}")
