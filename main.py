from elf import *
from gadget import *
from execveChain import *

def getAllGadgets(e):
    return [g for t in e.getTextSegments() for cb in t.getCodeBlocks() for g in extractAllGadgets(cb)]

def printAllGadgets(s):
    e = Elf(s)
    gs = getAllGadgets(e)
    gdict = {}
    for g in gs:
        gstr = str(g).split(':')
        gdict[gstr[0]] = gstr[1]
        
        sort_gadgets = sorted(gdict.items(), key=lambda x: x[1])
        gcnt = 0
        temp = []
        for i in sort_gadgets:
            if i[1] not in temp:
                temp.append(i[1])
                gcnt = gcnt + 1
                print(i[0], i[1])
        print(str(gcnt) + " unique gadgets found..")

def ROPchainBinary(s, null_ok):
    elf = Elf(s)
    gadgets = getAllGadgets(elf)
    execveROPChain(gadgets, elf, null_ok)

helpstring = '''Usage: python3 main.py <path-to-binary> [mode]
To display this help text, execute:
python3 main.py --help

mode can be one of the following:
    --ropchain [--null-ok]
        execute the full ropchain exploit, and output a python script to
        execveROPChain.py that generates a payload.
        If --null-ok is passed, no attempt to avoid null bytes is made.
        This can reduce the size of the payload.
    --gadget
        extracts all gadgets from the binary and prints them to stdout.
    
    If no mode is provided, the tool is run in --gadget mode.
'''

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if len(sys.argv) > 2:
            if sys.argv[2] == "--ropchain":
                if len(sys.argv) > 3 and sys.argv[3] == "--null-ok":
                    null_ok = True
                else:
                    null_ok = False
                ROPchainBinary(sys.argv[1], null_ok)
            elif sys.argv[2] == "--gadget":
                printAllGadgets(sys.argv[1])
            else:
                print(helpstring)
        else:
            if sys.argv[1] == "--help":
                print(helpstring)
            else:
                printAllGadgets(sys.argv[1])
    else:
        print(helpstring)

