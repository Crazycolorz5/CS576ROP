# Utility functions for testing
from capstone import *
from elf import *
from gadget import *

def printCode(c):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for (address, size, mnemonic, op_str) in md.disasm_lite(c, 0):
        print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

def printAll(s):
    elf = Elf(s)
    texts = elf.getTextSegments()
    for t in texts:
        printCode(t.data)
        print()

def getAllGadgets(s):
    return [extractAllGadgets(t.getCode()) for t in Elf(s).getTextSegments()]

def printGadgetsInSegments(ts):
    for t in ts:
        for g in t:
            print(g.prettyPrint())
