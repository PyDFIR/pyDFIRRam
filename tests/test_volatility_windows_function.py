import json
import pytest
import pandas as pd
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem
from pydfirram.core.renderer import Renderer
from loguru import logger

DUMP_FILE = Path("/home/remnux/2600/ch2.dmp") # Assurez-vous de remplacer "votre_fichier_de_dump.dump" par le chemin réel vers votre fichier de dump

@pytest.fixture
def generic_instance():
    logger.info("Create a generic instance for all tests")
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    return Generic(os, dumpfile)


def test_volatilty_pslist(generic_instance):
    logger.opt(colors=True).info("<blue>pslist</blue> from volatility is running")
    output = generic_instance.pslist()
    assert isinstance(output, Renderer), "Not working"
    logger.success("TEST PASSED !")
def test_volatilty_pslist_with_args_pid(generic_instance):
    logger.opt(colors=True).info("<blue>pslist</blue> with args pid = 4 from volatility is running")
    output = generic_instance.pslist(pid=[4])
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_volatility_banners(generic_instance):
    logger.opt(colors=True).info("<blue>banners</blue> from volatility is running")
    output = generic_instance.banners(pid=[4])
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_volatility_cmdline(generic_instance):
    logger.opt(colors=True).info("<blue>cmdline</blue> from volatility is running")
    output = generic_instance.cmdline()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_volatility_dlllist(generic_instance):
    logger.opt(colors=True).info("<blue>dlllist</blue> from volatility is running")
    output = generic_instance.dlllist()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_bigpools(generic_instance):
    logger.opt(colors=True).info("<blue>bigpools</blue> from volatility is running")
    output = generic_instance.bigpools()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_callbacks(generic_instance):
    logger.opt(colors=True).info("<blue>callbacks</blue> from volatility is running")
    output = generic_instance.callbacks()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_certificates(generic_instance):
    logger.opt(colors=True).info("<blue>certificate</blue> from volatility is running")
    output = generic_instance.certificates()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_configwriter(generic_instance):
    logger.opt(colors=True).info("<blue>configwriter</blue> from volatility is running")
    output = generic_instance.configwriter()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_crashinfo(generic_instance):
    logger.opt(colors=True).info("<blue>crashinfo</blue> from volatility is running")
    with pytest.raises(Exception):
        generic_instance.crashinfo()
    logger.success("TEST PASSED !")

def test_devicetree(generic_instance):
    logger.opt(colors=True).info("<blue>devicetree</blue> from volatility is running")
    output = generic_instance.devicetree()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_driverirp(generic_instance):
    logger.opt(colors=True).info("<blue>driverirp</blue> from volatility is running")
    output = generic_instance.driverirp()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_drivermodule(generic_instance):
    logger.opt(colors=True).info("<blue>drivermodule</blue> from volatility is running")
    output = generic_instance.drivermodule()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_driverscan(generic_instance):
    logger.opt(colors=True).info("<blue>driverscan</blue> from volatility is running")
    output = generic_instance.driverscan()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_envars(generic_instance):
    logger.opt(colors=True).info("<blue>envars</blue> from volatility is running")
    output = generic_instance.envars()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_hivelist(generic_instance):
    logger.opt(colors=True).info("<blue>hivelist</blue> from volatility is running")
    output = generic_instance.hivelist()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_hivescan(generic_instance):
    logger.opt(colors=True).info("<blue>hivescan</blue> from volatility is running")
    output = generic_instance.hivescan()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_iat(generic_instance):
    logger.opt(colors=True).info("<blue>iat</blue> from volatility is running")
    output = generic_instance.iat()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_info(generic_instance):
    logger.opt(colors=True).info("<blue>info</blue> from volatility is running")
    output = generic_instance.info()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

def test_pstree(generic_instance):
    logger.opt(colors=True).info("<blue>pstree</blue> from volatility is running")
    output = generic_instance.pstree()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")