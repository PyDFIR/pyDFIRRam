import pytest
from pathlib import Path
from pydfirram.core.base import Generic, OperatingSystem
from pydfirram.modules.windows import Windows
from pydfirram.core.renderer import Renderer
from loguru import logger
from .config import DUMP_FILE
from typing import List, Any

logger.opt(colors=True).info("<b><magenta> TEST PYDFIRRAM WINDOWS FUNCTIONS </magenta></b>")

@pytest.fixture
def generic_instance() -> Generic:
    """
        Create A generic fixture for test
    """
    os = OperatingSystem.WINDOWS
    dumpfile = Path(DUMP_FILE)
    return Generic(os, dumpfile)

@pytest.fixture
def windows_instance() -> Windows :
    dumpfile = Path(DUMP_FILE)
    return Windows(dumpfile)


@pytest.mark.pslist
def test_volatility_pslist(generic_instance: Generic) -> None:
    """
    Test the volatility PsList function
    """
    logger.opt(colors=True).info("<b><cyan>pslist</cyan></b> from volatility is running")
    output: Renderer = generic_instance.pslist()
    assert isinstance(output, Renderer), "Output is not an instance of Renderer"
    pslist_content: List[Any] = output.to_list()
    assert isinstance(pslist_content, list), "Output content is not a list"
    assert len(pslist_content) > 0, "Output list is empty"
    logger.success("TEST PASSED!")

@pytest.mark.pslist
@pytest.mark.pslist_pid
def test_volatilty_pslist_with_args_pid(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>pslist</cyan></b> with args from volatility is running")
    output : Renderer = generic_instance.pslist(pid=[4])
    assert isinstance(output, Renderer), "Error during function execution"
    pslist_content : list = output.to_list()
    assert isinstance(pslist_content,list),"Not a list"
    assert len(pslist_content) == 1
    logger.success("TEST PASSED !")

@pytest.mark.banners
def test_volatility_banners(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>banners</cyan></b> from volatility is running")
    output : Renderer = generic_instance.banners(pid=[4])
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.cmdline
def test_volatility_cmdline(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>cmdline</cyan></b> from volatility is running")
    output : Renderer = generic_instance.cmdline()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")
    cmdline_content : list = output.to_list()
    assert isinstance(cmdline_content,list),"Not a list"
    assert len(cmdline_content) > 0

# Add tests for cmdline(pid)


@pytest.mark.dlllist
def test_volatility_dlllist(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>dlllist</cyan></b> from volatility is running")
    output : Renderer = generic_instance.dlllist()
    assert isinstance(output, Renderer), "Error during function execution"
    dllist_content : list = output.to_list()
    assert isinstance(dllist_content,list),"Not a list"
    assert len(dllist_content) > 0
    logger.success("TEST PASSED !")
# add tests for dlllist with these args
# --pid [PID ...]  Process IDs to include (all other processes are excluded)
#  --offset OFFSET  Process offset in the physical address space
#  --name NAME      Specify a regular expression to match dll name(s)
#  --base BASE      Specify a base virtual address in process memory
#  --ignore-case    Specify case insensitivity for the regular expression name matching
#  --dump           Extract listed DLLs


@pytest.mark.bigpools
def test_bigpools(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>bigpools</cyan></b> from volatility is running")
    output : Renderer = generic_instance.bigpools()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

# add tests for dlllist with these args
# --tags TAGS Comma separated list of pool tags to filter pools returned 
# --show-free Show freed regions (otherwise only show allocations in use)


@pytest.mark.callbacks
def test_callbacks(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>callbacks</cyan></b> from volatility is running")
    output : Renderer = generic_instance.callbacks()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.certificates
def test_certificates(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>certificate</cyan></b> from volatility is running")
    output : Renderer = generic_instance.certificates()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

# add tests for certificates with these args
# dump

@pytest.mark.configwriter
def test_configwriter(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>configwriter</cyan></b> from volatility is running")
    output : Renderer = generic_instance.configwriter()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

# add tests for configwriter with these args
# extra

@pytest.mark.crashinfo
def test_crashinfo(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>crashinfo</cyan></b> from volatility is running")
    with pytest.raises(Exception):
        generic_instance.crashinfo()
    logger.success("TEST PASSED !")

@pytest.mark.devicetree
def test_devicetree(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>devicetree</cyan></b> from volatility is running")
    output : Renderer = generic_instance.devicetree()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.driverirp
def test_driverirp(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>driverirp</cyan></b> from volatility is running")
    output : Renderer = generic_instance.driverirp()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.drivermodules
def test_drivermodule(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>drivermodule</cyan></b> from volatility is running")
    output : Renderer = generic_instance.drivermodule()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.driverscan
def test_driverscan(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>driverscan</cyan></b> from volatility is running")
    output : Renderer = generic_instance.driverscan()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.envars
def test_envars(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>envars</cyan></b> from volatility is running")
    output : Renderer = generic_instance.envars()
    assert isinstance(output, Renderer), "Error during function execution"
    envars_content : list = output.to_list()
    assert isinstance(envars_content,list),"Not a list"
    assert len(envars_content) > 0
    logger.success("TEST PASSED !")

# add tests for envars with these args
# pid
# slient


@pytest.mark.hivelist
def test_hivelist(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>hivelist</cyan></b> from volatility is running")
    output : Renderer = generic_instance.hivelist()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

# add tests for hivelist with these args
# filter
# dump

@pytest.mark.hivescan
def test_hivescan(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>hivescan</cyan></b> from volatility is running")
    output : Renderer = generic_instance.hivescan()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.iat
def test_iat(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>iat</cyan></b> from volatility is running")
    output : Renderer = generic_instance.iat()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")
# add tests for iat with these args
# pid

@pytest.mark.info
def test_info(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>info</cyan></b> from volatility is running")
    output : Renderer = generic_instance.info()
    assert isinstance(output, Renderer), "Error during function execution"
    logger.success("TEST PASSED !")

@pytest.mark.pstree
def test_pstree(generic_instance : Generic) -> None :
    logger.opt(colors=True).info("<b><cyan>pstree</cyan></b> from volatility is running")
    output : Renderer = generic_instance.pstree()
    assert isinstance(output, Renderer), "Error during function execution"
    cmdline_content : list = output.to_list()
    assert isinstance(cmdline_content,list),"Not a list"
    assert len(cmdline_content) > 0
    logger.success("TEST PASSED !")
# add tests for pstree with these args
# pid
# physical


@pytest.mark.dumpfile_pid
@pytest.mark.dumpfiles
def test_dumpfile_with_args_pid(windows_instance : Windows):
    current_directory = Path.cwd()
    initial_files = set(current_directory.glob("file.*"))
    new_files = set()

    try:
        result = windows_instance.dumpfiles(pid=4)
        assert result is None, "The dumpfile method should return a non-null result"
        new_files = set(current_directory.glob("file.*")) - initial_files
        assert len(new_files) >= 1, f"Expected exactly one new file starting with 'file.', but found {len(new_files)}"
        logger.opt(colors=True).info(f"number of file dumped {len(new_files)}")
    except Exception as e:
        pytest.fail(f"An exception should not be raised: {e}")
    finally:
        for new_file in new_files:
            try:
                new_file.unlink()
            except Exception as cleanup_error:
                print(f"Failed to delete {new_file}: {cleanup_error}")

@pytest.mark.dumpfile_physaddr
@pytest.mark.dumpfiles
def test_dumpfile_with_args_physaddr(windows_instance : Windows):
    current_directory = Path.cwd()
    initial_files = set(current_directory.glob("file.*"))
    new_files = set()

    try:
        result = windows_instance.dumpfiles(physaddr=533517296)
        assert result is None, "The dumpfile method should return a non-null result"
        # Check if new files starting with 'file.' are created
        new_files = set(current_directory.glob("file.*")) - initial_files
        assert len(new_files) == 1, f"Expected exactly one new file starting with 'file.', but found {len(new_files)}"
    except Exception as e:
        pytest.fail(f"An exception should not be raised: {e}")

    finally:
        # Clean up any new files created during the test
        for new_file in new_files:
            try:
                new_file.unlink()
            except Exception as cleanup_error:
                print(f"Failed to delete {new_file}: {cleanup_error}")

#Not able to test virtaddr locally 
#@pytest.mark.dumpfiles
#@pytest.mark.dumpfile_virtaddr
#def test_dumpfile_with_args_virtaddr(windows_instance : Windows):
#    current_directory = Path.cwd()
#    initial_files = set(current_directory.glob("file.*"))
#    new_files = set()
#    value = 2274855800
#    try:
#        result = windows_instance.dumpfiles(virtaddr=value)
#        # Check if new files starting with 'file.' with the value in hex are created
#        file_created = "file." + hex(value)
#        new_files = set(current_directory.glob(file_created)) - initial_files
#        assert len(new_files) == 1, f"Expected exactly one new file starting with 'file.', but found {len(new_files)}"
#
#    except Exception as e:
#        pytest.fail(f"An exception should not be raised: {e}")
#
#    finally:
#        # Clean up any new files created# windows.crashinfo.Crashinfo during the test
#        for new_file in new_files:
#            try:
#                new_file.unlink()
#            except Exception as cleanup_error:
#                print(f"Failed to delete {new_file}: {cleanup_error}")

# windows.filescan.FileScan
@pytest.mark.filescan
def test_filescan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>filescan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.pstree()
    assert isinstance(output, Renderer), "Error during function execution"
    cmdline_content : list = output.to_list()
    assert isinstance(cmdline_content,list),"Not a list"
    assert len(cmdline_content) > 0
    logger.success("TEST PASSED !")

# windows.getservicesids.GetServiceSIDs
@pytest.mark.getservicesids
def test_getservicesids(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>getservicesids</cyan></b> from volatility is running")
    output : Renderer = windows_instance.getservicesids()
    assert isinstance(output, Renderer), "Error during function execution"
    getservicesids : list = output.to_list()
    assert isinstance(getservicesids,list),"Not a list"
    assert len(getservicesids) > 0
    logger.success("TEST PASSED !")

# windows.getsids.GetSIDs
@pytest.mark.getstids
def test_getsids(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>getsids</cyan></b> from volatility is running")
    output : Renderer = windows_instance.getsids()
    assert isinstance(output, Renderer), "Error during function execution"
    getsids : list = output.to_list()
    assert isinstance(getsids,list),"Not a list"
    assert len(getsids) > 0
    logger.success("TEST PASSED !")

# windows.joblinks.JobLinks
@pytest.mark.joblinks
def test_joblinks(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>joblinks</cyan></b> from volatility is running")
    output : Renderer = windows_instance.joblinks()
    assert isinstance(output, Renderer), "Error during function execution"
    joblinks : list = output.to_list()
    assert isinstance(joblinks,list),"Not a list"
    assert len(joblinks) > 0
    logger.success("TEST PASSED !")

@pytest.mark.new
@pytest.mark.handles
def test_handles(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>handles</cyan></b> from volatility is running")
    output : Renderer = windows_instance.handles()
    assert isinstance(output, Renderer), "Error during function execution"
    handles : list = output.to_list()
    assert isinstance(handles,list),"Not a list"
    assert len(handles) > 0
    logger.success("TEST PASSED !")

# ----- NEW 

# windows.malfind.Malfind
@pytest.mark.new
@pytest.mark.malfind
def test_malfind(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>malfind</cyan></b> from volatility is running")
    output : Renderer = windows_instance.malfind()
    assert isinstance(output, Renderer), "Error during function execution"
    malfind : list = output.to_list()
    assert isinstance(malfind,list),"Not a list"
    assert len(malfind) > 0
    logger.success("TEST PASSED !")

@pytest.mark.new
@pytest.mark.memmap
def test_memmap(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>memmap</cyan></b> from volatility is running")
    output : Renderer = windows_instance.memmap()
    assert isinstance(output, Renderer), "Error during function execution"
    memmap : list = output.to_list()
    assert isinstance(memmap,list),"Not a list"
    assert len(memmap) > 0
    logger.success("TEST PASSED !")

@pytest.mark.new
@pytest.mark.modules
def test_modules(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>modules</cyan></b> from volatility is running")
    output : Renderer = windows_instance.modules()
    assert isinstance(output, Renderer), "Error during function execution"
    modules : list = output.to_list()
    assert isinstance(modules,list),"Not a list"
    assert len(modules) > 0
    logger.success("TEST PASSED !")

# windows.mbrscan.MBRScan
@pytest.mark.new
@pytest.mark.mbrscan
def test_mbrscan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>mbrscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.mbrscan()
    assert isinstance(output, Renderer), "Error during function execution"
    mbrscan : list = output.to_list()
    assert isinstance(mbrscan,list),"Not a list"
    assert len(mbrscan) > 0
    logger.success("TEST PASSED !")


# windows.modscan.ModScan
@pytest.mark.new
@pytest.mark.modscan
def test_modscan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>modscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.modscan()
    assert isinstance(output, Renderer), "Error during function execution"
    modscan : list = output.to_list()
    assert isinstance(modscan,list),"Not a list"
    assert len(modscan) > 0
    logger.success("TEST PASSED !")

# windows.mutantscan.MutantScan
@pytest.mark.new
@pytest.mark.mutantscan
def test_mutantscan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>mutantscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.mutantscan()
    assert isinstance(output, Renderer), "Error during function execution"
    mutantscan : list = output.to_list()
    assert isinstance(mutantscan,list),"Not a list"
    assert len(mutantscan) > 0
    logger.success("TEST PASSED !")

# windows.netscan.NetScan
@pytest.mark.new
@pytest.mark.netscan
def test_netscan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>netscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.netscan()
    assert isinstance(output, Renderer), "Error during function execution"
    netscan : list = output.to_list()
    assert isinstance(netscan,list),"Not a list"
    assert len(netscan) > 0
    logger.success("TEST PASSED !")

# windows.netstat.NetStat
@pytest.mark.new
@pytest.mark.netstat
def test_netstat(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>netscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.netstat()
    assert isinstance(output, Renderer), "Error during function execution"
    netstat : list = output.to_list()
    assert isinstance(netstat,list),"Not a list"
    assert len(netstat) > 0
    logger.success("TEST PASSED !")

# windows.poolscanner.PoolScanner
@pytest.mark.new
@pytest.mark.poolscanner
def test_poolscanner(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>poolscanner</cyan></b> from volatility is running")
    output : Renderer = windows_instance.poolscanner()
    assert isinstance(output, Renderer), "Error during function execution"
    poolscanner : list = output.to_list()
    assert isinstance(poolscanner,list),"Not a list"
    assert len(poolscanner) > 0
    logger.success("TEST PASSED !")


# windows.privileges.Privs
@pytest.mark.new
@pytest.mark.privs
def test_privs(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>privs</cyan></b> from volatility is running")
    output : Renderer = windows_instance.privs()
    assert isinstance(output, Renderer), "Error during function execution"
    privs : list = output.to_list()
    assert isinstance(privs,list),"Not a list"
    assert len(privs) > 0
    logger.success("TEST PASSED !")


# windows.psscan.PsScan
@pytest.mark.new
@pytest.mark.psscan
def test_psscan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>psscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.psscan()
    assert isinstance(output, Renderer), "Error during function execution"
    psscan : list = output.to_list()
    assert isinstance(psscan,list),"Not a list"
    assert len(psscan) > 0
    logger.success("TEST PASSED !")

# windows.registry.printkey.PrintKey
@pytest.mark.new
@pytest.mark.printkey
def test_printkey(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>printkey</cyan></b> from volatility is running")
    output : Renderer = windows_instance.printkey()
    assert isinstance(output, Renderer), "Error during function execution"
    printkey : list = output.to_list()
    assert isinstance(printkey,list),"Not a list"
    assert len(printkey) > 0
    logger.success("TEST PASSED !")

# windows.statistics.Statistics
@pytest.mark.new
@pytest.mark.statistics
def test_statistics(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>statistics</cyan></b> from volatility is running")
    output : Renderer = windows_instance.statistics()
    assert isinstance(output, Renderer), "Error during function execution"
    statistics : list = output.to_list()
    assert isinstance(statistics,list),"Not a list"
    assert len(statistics) > 0
    logger.success("TEST PASSED !")

# windows.sessions.Sessions
@pytest.mark.new
@pytest.mark.sessions
def test_sessions(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>sessions</cyan></b> from volatility is running")
    output : Renderer = windows_instance.sessions()
    assert isinstance(output, Renderer), "Error during function execution"
    sessions : list = output.to_list()
    assert isinstance(sessions,list),"Not a list"
    assert len(sessions) > 0
    logger.success("TEST PASSED !")

# windows.ssdt.SSDT   Lists the system call table.
@pytest.mark.new
@pytest.mark.ssdt
def test_ssdt(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>ssdt</cyan></b> from volatility is running")
    output : Renderer = windows_instance.ssdt()
    assert isinstance(output, Renderer), "Error during function execution"
    ssdt : list = output.to_list()
    assert isinstance(ssdt,list),"Not a list"
    assert len(ssdt) > 0
    logger.success("TEST PASSED !")

# windows.thrdscan.ThrdScan
@pytest.mark.new
@pytest.mark.thrdscan
def test_thrdscan(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>thrdscan</cyan></b> from volatility is running")
    output : Renderer = windows_instance.thrdscan()
    assert isinstance(output, Renderer), "Error during function execution"
    thrdscan : list = output.to_list()
    assert isinstance(thrdscan,list),"Not a list"
    assert len(thrdscan) > 0
    logger.success("TEST PASSED !")

# windows.threads.Threads
@pytest.mark.new
@pytest.mark.threads
def test_threads(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>threads</cyan></b> from volatility is running")
    output : Renderer = windows_instance.threads()
    assert isinstance(output, Renderer), "Error during function execution"
    threads : list = output.to_list()
    assert isinstance(threads,list),"Not a list"
    assert len(threads) > 0
    logger.success("TEST PASSED !")

# windows.vadinfo.VadInfo
@pytest.mark.new
@pytest.mark.vadinfo
def test_vadinfo(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>vadinfo</cyan></b> from volatility is running")
    output : Renderer = windows_instance.vadinfo()
    assert isinstance(output, Renderer), "Error during function execution"
    vadinfo : list = output.to_list()
    assert isinstance(vadinfo,list),"Not a list"
    assert len(vadinfo) > 0
    logger.success("TEST PASSED !")

# windows.verinfo.VerInfo
@pytest.mark.new
@pytest.mark.verinfo
def test_verinfo(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>verinfo</cyan></b> from volatility is running")
    output : Renderer = windows_instance.verinfo()
    assert isinstance(output, Renderer), "Error during function execution"
    verinfo : list = output.to_list()
    assert isinstance(verinfo,list),"Not a list"
    assert len(verinfo) > 0
    logger.success("TEST PASSED !")

# windows.virtmap.VirtMap
@pytest.mark.new
@pytest.mark.virtmap
def test_virtmap(windows_instance: Windows):
    logger.opt(colors=True).info("<b><cyan>virtmap</cyan></b> from volatility is running")
    output : Renderer = windows_instance.virtmap()
    assert isinstance(output, Renderer), "Error during function execution"
    virtmap : list = output.to_list()
    assert isinstance(virtmap,list),"Not a list"
    assert len(virtmap) > 0
    logger.success("TEST PASSED !")


# NOT ABLE TO TEST AT THIS TIME 
# windows.registry.getcellroutine.GetCellRoutine 
# windows.registry.userassist.UserAssist
# windows.symlinkscan.SymlinkScan
# windows.skeleton_key_check.Skeleton_Key_Check
# windows.strings.Strings
# windows.suspicious_threads.SupsiciousThreads
# windows.truecrypt.Passphrase
## windows.cachedump.Cachedump


#@pytest.mark.new
#@pytest.mark.cachedump
#def test_cachedump(windows_instance: Windows):
#    logger.opt(colors=True).info("<b><cyan>cachedump</cyan></b> from volatility is running")
#    output : Renderer = windows_instance.cachedump()
#    assert isinstance(output, Renderer), "Error during function execution"
#    cache_content : list = output.to_list()
#    assert isinstance(cache_content,list),"Not a list"
#    assert len(cache_content) > 0
#    logger.success("TEST PASSED !")
#
## windows.hashdump.Hashdump
## Not able to test this functionnality at this time
#@pytest.mark.new
#@pytest.mark.hashdump
#def test_hashdump(windows_instance: Windows):
#    logger.opt(colors=True).info("<b><cyan>hashdump</cyan></b> from volatility is running")
#    output : Renderer = windows_instance.hashdump()
#    assert isinstance(output, Renderer), "Error during function execution"
#    hashdump : list = output.to_list()
#    assert isinstance(hashdump,list),"Not a list"
#    assert len(hashdump) > 0
#    logger.success("TEST PASSED !")
#
#
## windows.hollowprocesses.HollowProcesses
## Not able to test this functionnality at this time
#@pytest.mark.new
#@pytest.mark.hollowprocesses
#def test_hollowprocesses(windows_instance: Windows):
#    logger.opt(colors=True).info("<b><cyan>hollowprocess</cyan></b> from volatility is running")
#    output : Renderer = windows_instance.hollowprocesses()
#    assert isinstance(output, Renderer), "Error during function execution"
#    hollowprocesses : list = output.to_list()
#    assert isinstance(hollowprocesses,list),"Not a list"
#    assert len(hollowprocesses) > 0
#    logger.success("TEST PASSED !")
#