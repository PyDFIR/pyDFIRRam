#from pyDFIRLogs import *
from pyDFIRRam import windows
import pandas
file = "/home/remnux/Desktop/project/2600/memdump.mem"
windows_obj = windows(file,showConfig=True,Outputformat="dataframe")
c= windows_obj.PsTree()
print(c)
#def unique(data):
#    ret = []
#    for e in data:
#        if not e["ForeignAddr"] in ret:
#            ret.append(e["ForeignAddr"])
#    return ret
#
#### Create an object
#file = "/home/remnux/Desktop/project/2600/memdump.mem"
#ns = windows_obj.NetScan()
#print(pandas.DataFrame(ns).head())
##print(unique(ns))
#print(windows_obj.CmdLine())
#print(windows_obj.Info())
#print(windows_obj.NetScan)
#t =windows_obj.FileScan()
#pd = pandas.DataFrame(t)
#print(pd)
#value_to_find = "Mft"
#print(pd[pd['Name'].str.contains(value_to_find)])
#l = windows_obj.DumpFiles([0xcf0c25ee2210])


### test Function ok
#print("Verinfo",windows_obj.VerInfo())
#print("MutantScan",windows_obj.MutantScan())
#print("BigPools",windows_obj.BigPools())
#print("HiveScan",windows_obj.HiveScan())
#print("getSids",windows_obj.getSids())
#print("VADinfo",windows_obj.VADinfo())
#print("Sessions",windows_obj.Sessions())
#print("GetSetviceSids",windows_obj.GetSetviceSids())
#print("WindowsInfo",windows_obj.WindowsInfo())
#print("DllList",windows_obj.DllList())
#print("SSDT",windows_obj.SSDT())
#print("ModScan",windows_obj.ModScan())
#print("SymLinkScan",windows_obj.SymLinkScan())
#print("MBRScan",windows_obj.MBRScan())
#print("VirtMap",windows_obj.VirtMap())
#print("VadInfo",windows_obj.VadInfo())
#print("DriverScan",windows_obj.DriverScan())
#print("DeviceTree",windows_obj.DeviceTree())
#print("SvcScan",windows_obj.SvcScan())
#print("DriverIrp",windows_obj.DriverIrp())
#print("CallBacks",windows_obj.CallBacks())
#print("Modules",windows_obj.Modules())
#print("Malfind",windows_obj.Malfind())
#print("MFTscan",windows_obj.MFTscan())
#print("Privs",windows_obj.Privs())
#print("UserAssist",windows_obj.UserAssist())
#print("Hivescan",windows_obj.Hivescan())
#print("PoolScanner",windows_obj.PoolScanner())


#### Function not OK
#print("LsaDump",windows_obj.LsaDump())
#print("skeleton_key_check",windows_obj.skeleton_key_check())
#print("Memmap",windows_obj.Memmap())
#print("CacheDump",windows_obj.CacheDump())
#print("YaraScan",windows_obj.YaraScan())
#print("LdrModules",windows_obj.LdrModules())
#print("VadYaraScan",windows_obj.VadYaraScan())
#print("HashDump",windows_obj.HashDump())
#print("PrintKey",windows_obj.PrintKey())
