#from pyDFIRLogs import *
from pyDFIRRam import windows
import pandas
file = "/home/remnux/Desktop/project/2600/memdump.mem"
windows_obj = windows(file,showConfig=True,Outputformat="dataframe")
c= windows_obj.Envars()
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
#windows_obj = windows(file,showConfig=True,Outputformat="dataframe")
#ns = windows_obj.NetScan()
#print(pandas.DataFrame(ns).head())
#print(unique(ns))
#print(windows_obj.CmdLine())
#print(windows_obj.Info())
#print(windows_obj.NetScan)
#hash = windows_obj.get_hash(file)
#print(hash)
#t =windows_obj.FileScan()
#pd = pandas.DataFrame(t)
#print(pd)
#value_to_find = "Mft"
#print(pd[pd['Name'].str.contains(value_to_find)])
#l = windows_obj.DumpFiles([0xcf0c25ee2210])


