from pyDFIRRam import linux

l = linux()

t = l.printAllPLugins()
dic = []
for e in t.keys():
    if "linux" in e:
        val = e.split(".")[-1]
        dic.append({val:{
            'plugin':e
        }})
for e in dic:
    print(str(e)+",")