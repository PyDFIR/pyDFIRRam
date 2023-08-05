from pyDFIRRam import windows
import os,json
winobj = os.getcwd()+"/"+"memdump.mem"
obj = windows(winobj)

print(json.dumps(obj.PsList(),indent=2))
