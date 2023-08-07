from pyDFIRRam import windows
import os,json
winobj = os.getcwd()+"/"+"memdump.mem"
obj = windows(winobj)

obj.PsList(pid=6192)
