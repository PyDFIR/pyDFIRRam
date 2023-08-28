from pyDFIRRam import windows
import os,json
winobj = "/home/remnux/Desktop/project/2600/memdump.mem"
obj = windows(winobj,Outputformat="dataframe")

print(obj.PsList())