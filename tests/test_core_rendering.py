from json import loads
import pytest
import pandas as pd
from pathlib import Path
from pydfirram.modules.windows import Windows
from pydfirram.core.renderer import Renderer
from loguru import logger
from .config import DUMP_FILE

pytestmark = pytest.mark.requires_dump

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


def test_to_df_does_not_mutate_pandas_global_options(monkeypatch):
    renderer = Renderer(data=None)
    records = [
        {f"col_{index}": f"value_{row}_{index}" for index in range(6)}
        for row in range(20)
    ]
    monkeypatch.setattr(renderer, "to_list", lambda: records)

    with pd.option_context("display.max_rows", 5, "display.max_columns", 3):
        max_rows_before = pd.get_option("display.max_rows")
        max_columns_before = pd.get_option("display.max_columns")

        dataframe = renderer.to_df(max_row=True)
        rendered_dataframe = repr(dataframe)

        assert pd.get_option("display.max_rows") == max_rows_before
        assert pd.get_option("display.max_columns") == max_columns_before
        assert "..." not in rendered_dataframe
        assert "19" in rendered_dataframe
        assert "col_5" in rendered_dataframe
