from pathlib import Path
import json
import pytest
from volatility3.cli import text_renderer
from pydfirram.core.base import Generic, OperatingSystem


DUMP_FILE = Path("/home/braguette/dataset_memory/ch2.dmp")


def test_generic():
    """
        Function to test the Generic()
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    assert len(generic.plugins) > 0


def test_generic_build():
    """
        Function use to test the build of pydfir
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    plugin = generic.get_plugin("Banners")
    assert plugin.name == "banners"
    print("Running plugin: ", plugin)
    output = generic.run_plugin(plugin)
    text_renderer.PrettyTextRenderer().render(output)


def test_get_attr():
    """
        Test the function to see if __getattr__ works good in base.py
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.PsList()
    assert output

def test_get_unknow_attribute_():
    """
        Check error handling in case of bad function calls
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    with pytest.raises(ValueError):
        generic.aaaaa()

def test_pslist_filter_pid():
    """
        Tests the function pslist with a parameters
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.PsList(pid=[4]).to_dict()
    assert output["PID"] == 4

def test_rendering_to_json():
    """
        Check if the rendering fonction to_json return a valid JSON
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.PsList(pid=[4]).to_json()
    try:
        json.loads(output)
    except ValueError:
        pytest.fail("Not a Json")

def test_plugin_with_parameter_pslist():
    """
        Check the return value if wrong parametres is send
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.PsList(pid=[44444444]).to_dict()
    assert output == ValueError


def test_lowercase_function_call():
    """
        Check case insesitive functions calls
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.pslist(pid=[4]).to_dict()
    assert output["PID"] == 4