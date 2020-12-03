from arch import md

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

# Traverse backwards byte-by-byte within the last instruction to find usable sub-instructions.
# If we need more gadgets, we can apply this process to every successful postfix of a gadget.
# [CsInsn] -> [Int] -> [Gadget]
def extractPartialInstructionGadget(code, idx):
    if idx == 0: return []
    prevInsn = code[idx-1].bytes
    prevInsn_offset = code[idx-1].address
    terminatorOffset = len(prevInsn)
    allBytes = prevInsn + code[idx].bytes
    acc = []
    for i in range(terminatorOffset - 1, 1, -1):
        insns = tuple(md.disasm(allBytes[i:], prevInsn_offset + i))
        if len(insns) > 1 and insns[-1].mnemonic in gadgetTerminators and all(map(lambda insn: insn.mnemonic in usefulOperations, insns[:-1])):
            acc.append(Gadget(insns))
    return acc

# [CsInsn] -> [Gadget]
def extractAllGadgets(code):
    terminators = findGadgetTerminators(code)
    wholeGadgets = list(map(lambda i: extractGadget(code, i), terminators))
    partialGadgets = map(lambda i: extractPartialInstructionGadget(code, i), terminators)
    return wholeGadgets + [x for y in partialGadgets for x in y]
