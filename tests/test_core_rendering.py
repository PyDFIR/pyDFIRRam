import json
import pytest
import pandas as pd
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem

DUMP_FILE = Path("/home/remnux/2600/ch2.dmp")

def test_rendering_to_json(generic_instance):
    output = generic_instance.PsList(pid=[4]).to_json()
    assert json.loads(output), "La sortie n'est pas un JSON valide."

def test_to_dataframe():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.pslist().to_dataframe()
    assert isinstance(output, pd.DataFrame)

def test_to_dict():
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    generic = Generic(os, dumpfile)
    output = generic.pslist().to_dict()
    assert isinstance(output,dict) 