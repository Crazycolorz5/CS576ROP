from elf import *
from gadget import *
from execveChain import *

def getAllGadgets(e):
    return [g for t in e.getTextSegments() for cb in t.getCodeBlocks() for g in extractAllGadgets(cb)]

def printAllGadgets(s):
    e = Elf(s)
    gs = getAllGadgets(e)
    for g in gs:
        print(g)

def ROPchainBinary(s):
    elf = Elf(s)
    gadgets = getAllGadgets(elf)
    execveROPChain(gadgets, elf)

helpstring = '''Usage: python3 main.py <path-to-binary> [mode]
To display this help text, execute:
python3 main.py --help

mode can be one of the following:
    --ropchain
        execute the full ropchain exploit, and output a python script to
        execveROPChain.py that generates a payload.
    --gadget
        extracts all gadgets from the binary and prints them to stdout.
    
    If no mode is provided, the tool is run in --gadget mode.
'''

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if len(sys.argv) == 3:
            if sys.argv[2] == "--ropchain":
                ROPchainBinary(sys.argv[1])
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

