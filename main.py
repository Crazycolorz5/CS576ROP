from elf import *
from gadget import *
from execveChain import *

def getAllGadgets(e):
    return [g for t in e.getTextSegments() for cb in t.getCodeBlocks() for g in extractAllGadgets(cb)]

def ROPchainBinary(s):
    elf = Elf(s)
    gadgets = getAllGadgets(elf)
    execveROPChain(gadgets, elf)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if len(sys.argv) == 3:
            if sys.argv[2] == "--ropchain":
                ROPchainBinary(sys.argv[1])
            elif sys.argv[2] == "--gadget":
                printAllGadgets(sys.argv[1])
            else:
                print("Unknown operation.")
        else:
            printAllGadgets(sys.argv[1])
