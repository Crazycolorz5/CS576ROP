from capstone import *

def format_bytes(bs):
    return ' '.join([hex(b) for b in bs])

class Gadget():
    # Fields
    # self.insns: array of capstone CsInsn's that represent the gadget
    def __init__(self, insns):
        self.insns = insns
        
    def prettyPrint(self):
        acc = ''
        for insn in self.insns:
            acc += '{}: {} {} {}\n'.format(insn.address, format_bytes(insn.bytes), insn.mnemonic, insn.op_str)
        return acc

# In code segments locate ret's or indirect calls and search preceeding instructions for useful behaviors (movs, pushes, pops, incs)
# [CsInsn] -> [Int] (indices of terminators)
def findGadgetTerminators(code):
    pass
