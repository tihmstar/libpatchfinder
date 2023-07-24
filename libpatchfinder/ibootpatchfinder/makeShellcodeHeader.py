#!/usr/bin/env python3
import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode.bin>"%(sys.argv[0]))
    exit(1)

varname = sys.argv[1].split(".")[0]
fname = sys.argv[1].replace(".h","")
fout = fname + ".h"
print("Reading file '%s'"%fname)

fr = open(fname,"rb")
r = fr.read()
fr.close()

outdata = "const unsigned char "+varname+"[] = {"

for c in r:
    outdata += hex(c) + ","

outdata = outdata[0:-1] + "};"
print("Writing file '%s' size=0x%s"%(fout,len(outdata)))
fw = open(fout,"wb")
fw.write(bytes(outdata+"\n","utf-8"))
fw.close()
print("Done!")
