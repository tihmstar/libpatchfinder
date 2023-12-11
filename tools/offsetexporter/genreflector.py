#!/usr/bin/env python3

import sys

if len(sys.argv) < 3:
    print("Usage: %s <class header file> <output file>")
    exit(1)

infile = sys.argv[1]
outfile = sys.argv[2]
print("infile=%s"%(infile))
print("outfile=%s"%(outfile))

with open(infile, "r") as f:
    r = f.read()

classname = r.split("class")[1].split("{")[0].split(":")[0].replace(" ","")
print("class=%s"%(classname))
toparse = "{".join(r.split("class")[1].split("{")[1:])

funcdefs=""
argtypes = {}

def getStrForFunction(rettype, funcname, args):
    template = """
static %s reflect_%s_%s(%s){
    return kpf->%s(%s);
}
"""
    fsps = funcname.split(" ")
    if len(fsps) > 1:
        rettype+= " " + " ".join(fsps[0:-1])
        funcname = fsps[-1]

    while len(funcname) and ( funcname[0] == "*" or funcname[0] == "&"):
        rettype += funcname[0]
        funcname = funcname[1:]

    print("Got function '%s' '%s' args: "%(rettype,funcname),args)
    argtypelist = [rettype]
    nargs = []
    mmargs = ["%s *kpf"%classname]
    if len(args):
        if len(args[0]) == 0:
            args.pop(0)
    mmargs += args
    argsstr = ",".join(mmargs)
    if (len(args)):
        for a in args:
            while (len(a) and a[0] == " "):
                a = a[1:]
            if len(a):
                a = a.split("=")[0]
                asps = a.split(" ")
                while (len(asps) and len(asps[-1]) == 0):
                    asps.pop(-1)
                aarg = asps[-1]
                atype = " ".join(asps[0:-1])
                while len(aarg) and ( aarg[0] == "*" or aarg[0] == "&"):
                    atype += aarg[0]
                    aarg = aarg[1:]
                nargs.append(aarg)
                argtypelist.append(atype)
    fillargsstr = ",".join(nargs)


    out = template %(rettype,classname,funcname,argsstr,funcname,fillargsstr)
    return out,funcname,argtypelist

def handleFunction(rettype, funcname, args):
    global funcdefs
    out,funcname,types = getStrForFunction(rettype, funcname, args)
    funcdefs += out
    argtypes[funcname] = types

print("Started parsing:\n")
i = -1
isPublic = False
while i+1 < len(toparse):
    i+=1
    curs=toparse[i:]
    match curs[0]:
        case ' ':
            #ignore whitespace char
            continue
        case '\n':
            #ignore whitespace char
            continue
        case '}':
            #ignore whitespace char
            continue
        case _:
            pass
    if (curs.startswith("public:")):
        isPublic = True
        i += len("public:")
        continue
    elif (curs.startswith("protected:")):
        isPublic = False
        i += len("protected:")
        continue
    elif (curs.startswith("private:")):
        isPublic = False
        i += len("private:")
        continue
    elif (curs.startswith("virtual")):
        isPublic = False
        i += len("virtual")
        continue
    elif (curs.startswith("#pragma")):
        i += curs.find("\n")
        continue
    elif (curs.startswith("#ifdef")):
        i += curs.find("#endif")+len("#endif")
        continue
    elif (curs.startswith("using ")):
        i += curs.find(";")
        continue
    elif (curs.startswith("enum")):
        p =  curs.find(";")
        assert(p != -1)
        i += p
        continue
    elif (curs.startswith("/*")):
        i += curs.find("*/")+1
        continue
    else:
        match curs[0]:
            case '#':
                i += curs.find("\n")
                continue

        isValidFunction = False
        semicolonpos = curs.find(";")
        if (semicolonpos != -1):
            action = curs[0:semicolonpos]
            if action.find("(") == -1 or action.find(")") == -1:
                #this is not a function
                i+=semicolonpos
                continue
            elif (action.find("~") != -1):
                #skipping destructor
                i+=semicolonpos
                continue
            sps = action.split(" ")
            if len(sps) >= 2:
                rettype = sps[0]
                action = " ".join(sps[1:])

                sps = action.split("(")
                if len(sps) == 2:
                    funcname = sps[0]
                    args = sps[1].split(")")[0].split(",")
                    isValidFunction = True

        if rettype.startswith("static"):
            i += curs.find(";")
        elif isValidFunction:
            handleFunction(rettype,funcname,args)
            i += semicolonpos
            continue
        elif (curs.startswith(classname)):
            i += curs.find("\n")
        else:
            print("-------FAIL-----")
            print(curs)
            exit(1)

#print(funcdefs)
#print(argtypes)

template_p1 = """
#include <vector>
#include <iostream>


"""
template_p2 = """
#ifndef HAVE_STRUCT_FUNCDEF
#define HAVE_STRUCT_FUNCDEF
struct funcdef {
    std::string funcname;
    void *func;
    std::string rettype;
    std::vector<std::string> typeinfo;
};
#endif

static const std::vector<funcdef> gFuncLookup_%s={
""" %classname

template_p3 = """
};
"""

outtxt = ""

outtxt += template_p1

outtxt += funcdefs

elems = []
for key,val in argtypes.items():
    svals = []
    for v in val:
        svals.append("\"%s\""%v)
    elems.append("{\"%s\",(void*)&reflect_%s_%s,%s,{%s}}" %(key,classname,key,svals[0],",".join(svals[1:])))

outtxt += template_p2
outtxt += ",".join(elems)
outtxt += template_p3

with open(outfile,"w") as f:
    f.write(outtxt)
print("Written to '%s'"%outfile)