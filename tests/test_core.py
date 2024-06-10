from pathlib import Path
from volatility3.cli import text_renderer
from pydfirram.core.base import Generic, OperatingSystem
from volatility3.framework import exceptions as VolatilityExceptions
import pytest
import json

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
    plugin = generic.get_plugin("Banners")
    assert plugin.name == "banners"
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

def test_pslist_filter_pid():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.PsList(pid=[4]).to_list()[0]
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

def test_plugin_with_parameter_pslist():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    try:
        generic.PsList(pid=[44444444]).to_list()
    except VolatilityExceptions:
        pytest.skip("Volatility Execption raised")

def test_lowercase_function_call():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.pslist(pid=[4]).to_list()[0]
    assert output["PID"] == 4

#Celui ci fonctionne en theorie, il faut juste import l'ISF et le dump
# Perso j'ai DL celui de la CI de Volatility et pas de problems
#def test_bad_operating_system_referenced():
#    os = OperatingSystem.LINUX
#    dumpfile = Path(DUMP_FILE)
#    generic = Generic(os, dumpfile)
#    output = generic.pslist().to_list()
#    assert  output == []

# A faire plus tard, checker quelques strings pour valider que c'est bien l'os Selectionné
#def test_bad_path_referenced():
#    os = OperatingSystem.LINUX
#    dumpfile = Path("/home/remnx/ch2.dmp")
#    generic = Generic(os, dumpfile)