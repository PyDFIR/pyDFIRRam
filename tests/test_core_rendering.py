import json
import pytest
import pandas as pd
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem
from pydfirram.core.renderer import Renderer
from loguru import logger

DUMP_FILE = Path("/home/remnux/2600/ch2.dmp")

logger.opt(colors=True).info("<b><magenta> TEST PYDFIRRAM CORE RENDERING </magenta></b>")


@pytest.fixture
def generic_instance() -> Renderer :
    logger.info("Create a generic instance for all tests")
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    return Generic(os, dumpfile)

def test_rendering_to_json(generic_instance):
    output = generic_instance.PsList()
    res = output.to_json()
    assert json.loads(res), "La sortie n'est pas un JSON valide."

def test_to_dataframe():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.pslist().to_dataframe()
    assert isinstance(output, pd.DataFrame)

def test_to_list():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.pslist().to_list()
    assert isinstance(output,list) 