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

    gdict = {}
    for g in gs:
        #print(g)
        gstr = str(g).split(':')
        gdict[gstr[0]] = gstr[1]
        #print(gstr[0].strip())
        #print(gstr[1].strip())

    sort_gadgets = sorted(gdict.items(), key=lambda x: x[1])
    gcnt = 0
    temp = []
    for i in sort_gadgets:
        if i[1] not in temp:
            temp.append(i[1])
            gcnt = gcnt + 1
            print(i[0], i[1])
    print(str(gcnt) + " unique gadgets found..")

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
