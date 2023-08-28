from pyDFIRRam import windows
import threading

def run_function(func, *args, **kwargs):
    try:
        result = func(*args, **kwargs)
        print(func+ ": Success")
        print(result)
    except Exception as e:
        print(func + ": Failed")
        print("Error:", e)
    finally:
        print()

winobj = "/home/remnux/Desktop/project/2600/memdump.mem"
obj = windows(winobj, Outputformat="dataframe")

functions_to_run = [
    obj.PsList,
    obj.HiveList,
    obj.Envars,
    obj.MutantScan,
    obj.BigPools,
    obj.HiveScan,
    obj.skeleton_key_check,
    obj.Sessions,
    obj.GetSetviceSids,
    obj.Info,
    obj.DllList,
    obj.NetScan,
    obj.NetStat,
    obj.PoolScanner,
    obj.SSDT,
    obj.LsaDump,
    obj.ModScan,
    obj.SymLinkScan,
    obj.PsScan,
    obj.PsTree,
    obj.FileScan,
    obj.CacheDump,
    obj.DriverScan,
    obj.DeviceTree,
    obj.HashDump,
    obj.DriverIrp,
    obj.CallBacks,
    obj.Modules,
    obj.Malfind,
    obj.mftscan,
    obj.Memmap,
    obj.Privs,
    obj.UserAssist,
    obj.Hivescan,
    obj.PrintKey
]

threads = []

for func in functions_to_run:
    thread = threading.Thread(target=run_function, args=(func,))
    thread.start()
    threads.append(thread)

for thread in threads:
    thread.join()
