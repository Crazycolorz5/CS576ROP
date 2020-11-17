# Utility functions for testing
from capstone import *
from elf import *

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
