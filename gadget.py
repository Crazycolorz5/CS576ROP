from arch import md
from functools import reduce

def format_bytes(bs):
    return ' '.join([hex(b) for b in bs])

class Gadget():
    # Fields
    # self.insns: array of capstone CsInsn's that represent the gadget
    def __init__(self, insns):
        self.insns = insns
        
    def __getitem__(self, idx):
        return self.insns[idx]
        
    def __len__(self):
        return len(self.insns)
        
    def __str__(self):
        return '{0:#018x} : {1:}'.format(self.insns[0].address, reduce(lambda acc, e: acc + " ; " + e, [insn.mnemonic + ((" " + insn.op_str) if insn.op_str else "") for insn in self.insns]))
        
# In code segments locate ret's or indirect calls and search preceeding instructions for useful behaviors (movs, pushes, pops, incs, syscall)
usefulOperations = ['pop', 'add', 'mov', 'xor', 'inc', 'nop', 'endbr64', 'syscall'] # Other potentially useful instructions: sub
gadgetTerminators = ['ret', 'syscall'] # Other potential terminators: 'call', 'jmp' (validate that they're indirect?)

# [CsInsn] -> [Int] (indices of terminators)
def findGadgetTerminators(code):
    return [x for (x, y) in zip(range(len(code)), code) if y.mnemonic in gadgetTerminators]

# Traverse backwards from the given index while we see useful instructions and find a maximal gadget.
# Then, return a list of all subgadgets.
# [CsInsn] -> Int -> [Gadget]
def extractGadgets(code, idx):
    start_idx = idx - 1
    while start_idx > 0 and code[start_idx].mnemonic in usefulOperations:
        start_idx -= 1
    # start_idx now points to the instruction preceding the last useful instruction for the gadget.
    # Now extract all subgadgets.
    supergadget_bytes = reduce(lambda acc, e: acc + e.bytes, code[start_idx:idx+1], b'')
    acc = []
    base_offs = code[start_idx].address
    for i in range(len(supergadget_bytes) - len(code[idx].bytes), 0, -1):
        insns = tuple(md.disasm(supergadget_bytes[i:], base_offs + i))
        if len(insns) >= 1 and insns[-1].mnemonic in gadgetTerminators and all(map(lambda insn: insn.mnemonic in usefulOperations, insns[:-1])):
            acc.append(Gadget(insns))
    return acc

# [CsInsn] -> [Gadget]
def extractAllGadgets(code):
    terminators = findGadgetTerminators(code)
    gadgets = map(lambda i: extractGadgets(code, i), terminators)
    return [x for y in gadgets for x in y]
