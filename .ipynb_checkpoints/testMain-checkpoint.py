from pyDFIRRam import windows
import os,json
winobj = os.getcwd()+"/"+"memdump.mem"
obj = windows(winobj,Outputformat="dataframe")

print(obj.PsList())