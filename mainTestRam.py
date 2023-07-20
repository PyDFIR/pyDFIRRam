#from pyDFIRLogs import *
from pyDFIRRam import windows
import pandas
"""
pyDFIRStrings Example
t = pyDFIRRam().ram_PsTree("ram.raw",savelogs=True,namefile="LogsSave")
print(t["insmod_PsTree"])
df = t["logs_dataframe"] 
print(df)
"""
"""
#PyDFIRLogs Example on auditd
import json

logs = pyDFIRLogs().auditd().parse_linux_system_logs(logfiles="./audit.log",logtype="auditd")
print(json.dumps(logs,indent=2))
"""
"""
pyDFIR Example on nginx logs
logs = pyDFIRLogs.WebLog.nginx().parse_linux_system_logs("./logsfiles_test/auth.log","auth")
print(json.dumps(logs,indent=2))
"""

"""
pyDFIR Windows Logs Evtx
import json
logs = pyDFIRLogs.windowsEVTX().evtxToJson("logsfiles_test/windowsEVTX/Event/6524-f2859648.evtx")
print(logs)"""

def unique(data):
    ret = []
    for e in data:
        if not e["ForeignAddr"] in ret:
            ret.append(e["ForeignAddr"])
    return ret

### Create an object
file = "/home/remnux/Desktop/project/2600/memdump.mem"

windows_obj = windows(file,showConfig=True,Outputformat="dataframe")
ns = windows_obj.NetScan()
print(pandas.DataFrame(ns).head())
print(unique(ns))
print(windows_obj.CmdLine())
print(windows_obj.Info())
print(windows_obj.NetScan)
#
#### Get Hash of file
hash = windows_obj.get_hash(file)
print(hash)
#
t =windows_obj.FileScan()
pd = pandas.DataFrame(t)
print(pd)
value_to_find = "Mft"
result = pd[pd['Name'].str.contains(value_to_find)]
print(result)
l = windows_obj.DumpFiles([0xcf0c25ee2210])
#fo = "./myFile.parquet"
#t.to_parquet(fo,index=False,engine="pyarrow",compression="gzip")
#print(pandas.read_parquet(fo))


