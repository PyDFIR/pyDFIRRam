from pyDFIRRam import windows
import os,json
winobj = "/home/remnux/Desktop/project/2600/memdump.mem"
obj = windows(winobj,Outputformat="dataframe")
#Test PsList
print(json.dumps(obj.PsTree(),indent=2))
#print("HiveList:")
#print(obj.HiveList())
#print("Envars:")
#print(obj.Envars())
#print("MutantScan:")
#print(obj.MutantScan())
#print("BigPools:")
#print(obj.BigPools())# Prends des arguments {tags, show-free}
#print("HiveScan:")
#print(obj.HiveScan())
#print("skeleton_key_check:")
#print(obj.skeleton_key_check())
#print("Sessions:")
#print(obj.Sessions())# Prends des arguments {pid}
#print("GetSetviceSids:")
#print(obj.GetSetviceSids())
#print("WindowsInfo:")
#print(obj.Info())
#print("DllList:")
#print(obj.DllList())# Prends des arguments {pid, dump}
#print("NetScan:")
#print(obj.NetScan())# Prends des arguments {include-corrupt}
#print("NetStat:")
#print(obj.NetStat())# Prends des arguments {include-corrupt}
#print("PoolScanner:")
#print(obj.PoolScanner())
#print("SSDT:")
#print(obj.SSDT())
#print("ModScan:")
#print(obj.ModScan())# Prends des arguments {dump}
#print("SymLinkScan:")
#print(obj.SymLinkScan())
#print("PsScan:")
#print(obj.PsScan())# Prends des arguments {physical, pid, dump}
#print("PsTree:")
#print(obj.PsTree())# Prends des arguments {physical, pid}
#print("FileScan:")
#print(obj.FileScan())
#print("DriverScan:")
#print(obj.DriverScan())
#print("DeviceTree:")
#print(obj.DeviceTree())
#print("DriverIrp:")
#print(obj.DriverIrp())
#print("CallBacks:")
#print(obj.CallBacks())
#print("Modules:")
#print(obj.Modules())
#print("Malfind:")
#print(obj.Malfind())

#print("Privs:")
#print(obj.Privs())
#print("UserAssist:")
#print(obj.UserAssist())
#print("Hivescan:")
#print(obj.Hivescan())
#print("PrintKey:")
#print(obj.PrintKey())
#OK

print("Memmap:")
print(obj.Memmap())

# Pris en charge mais prends des Arguments
#print(obj.DumpFiles())# Prends des arguments {physaddr, virtaddr, pid}

#
#
## Non pris en charge
##print(obj.Strings())# Prends des arguments {pid, string-file}
##print(obj.MBRScan())# Prends des arguments {full}
##print(obj.CmdLine())# Prends des arguments {pid}
##print(obj.LdrModules())# Prends des arguments {pid}
##print(obj.Handles())# Prends des arguments {pid}
##print(obj.VadInfo())# Prends des arguments {address, pid, dump,maxsize}
##print(obj.YaraScan())#idk
##print(obj.VadYaraScan())#idk
##print(obj.SvcScan())#idk
##print(obj.getSids())# Prends des arguments {pid}
##print(obj.VADinfo())# Prends des arguments {address, pid, dump,maxsize}
##print(obj.VirtMap())
#print("VerInfo:")
#print(obj.VerInfo())
#print(obj.LsaDump())#idk
#print("CacheDump:")
#print(obj.CacheDump())
#print("HashDump:")
#print(obj.HashDump())
#print("mftscan:")
#print(obj.mftscan())