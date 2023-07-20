#from pyDFIRLogs import *
from pyDFIRRam import windows
import pandas
import os
file = "/home/remnux/Desktop/project/2600/memdump.mem"
windows_obj = windows(file,showConfig=True,Outputformat="dataframe",outpath=os.getcwd(),savefile=False)
print(windows_obj.CmdLine)
