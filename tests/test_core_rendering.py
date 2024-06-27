from json import loads
import pytest
import pandas as pd
from pathlib import Path
from pydfirram.modules.windows import Windows
from pydfirram.core.renderer import Renderer
from loguru import logger
from .config import DUMP_FILE

logger.opt(colors=True).info("<b><magenta> TEST PYDFIRRAM CORE RENDERING </magenta></b>")


@pytest.fixture
def generic_instance() -> Renderer :
    logger.info("Create a generic instance for all tests")
    dumpfile = Path(DUMP_FILE)
    return Windows(dumpfile)

def test_rendering_to_json(generic_instance):
    output = generic_instance.PsList()
    res = output.to_json()
    assert loads(res), "The output is not a valid JSON."

def test_to_dataframe(generic_instance):
    output = generic_instance.pslist().to_df()
    assert isinstance(output, pd.DataFrame)

def test_to_list(generic_instance):
    output = generic_instance.pslist().to_list()
    assert isinstance(output,list) 
