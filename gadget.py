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

# In code segments locate ret's or indirect calls and search preceeding instructions for useful behaviors (movs, pushes, pops, incs, syscall)
usefulOperations = ['push', 'pop', 'add', 'sub', 'mov', 'xor', 'inc']
gadgetTerminators = ['ret', 'call', 'jmp', 'syscall']

# [CsInsn] -> [Int] (indices of terminators)
def findGadgetTerminators(code):
    return [x for (x, y) in zip(range(len(code)), code) if y.mnemonic in gadgetTerminators]

# Traverse backwards from the given index while we see useful instructions and extract a maximal gadget
# [CsInsn] -> [Int] -> Gadget
def extractGadget(code, idx):
    start_idx = idx - 1
    while start_idx >= 0 and code[start_idx].mnemonic in usefulOperations:
        start_idx -= 1
    return Gadget(code[start_idx+1:idx+1])

# [CsInsn] -> [Gadget]
def extractAllGadgets(code):
    return map(lambda i: extractGadget(code, i), findGadgetTerminators(code))
