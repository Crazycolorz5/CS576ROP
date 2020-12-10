# Utility functions for testing
from arch import md
from elf import *
from gadget import *
from execveChain import *

def printCode(c):
    for (address, size, mnemonic, op_str) in md.disasm_lite(c, 0):
        print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

def printAll(s):
    elf = Elf(s)
    texts = elf.getTextSegments()
    for t in texts:
        printCode(t.data)
        print()

def printAllGadgets(s):
    e = Elf(s)
    gs = getAllGadgets(e)
    for g in gs:
        print(g)

def getAllGadgets(e):
    return [g for t in e.getTextSegments() for cb in t.getCodeBlocks() for g in extractAllGadgets(cb)]

def printGadgetsInSegments(ts):
    for t in ts:
        for g in t:
            print(g)

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
