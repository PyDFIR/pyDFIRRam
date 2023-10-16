from pyDFIRRam import windows
import os,json
winobj = "/home/br4guette/pydfir/DESKTOP-GJ0TUAM-20231010-172704.raw"
obj = windows(winobj,Outputformat="dataframe")
print(obj.NetScan(include_corrupt=True))
