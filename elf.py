from struct import pack, unpack
from arch import md

def unpack_single(f, d):
    return unpack(f, d)[0]

def readcstr(data, offs):
    lastchar = data[offs]
    ret = b''
    while lastchar != 0:
        ret += pack('B', lastchar)
        offs += 1
        lastchar = data[offs]
    return ret.decode('utf-8')

class Elf():
    # String -> Elf
    def __init__(self, fname):
        # Read all of the data of the file in binary.
        file_descriptor = open(fname, 'rb')
        self.data = file_descriptor.read()
        file_descriptor.close()
        
        # Now process the binary to extract useful information
        
        # For now we can make some assumptions, such as
        # 64 bit, x64 architecture, little endian
        self.section_header_table_offset = unpack_single('<q', self.data[0x28:0x30])
        self.section_header_length = unpack_single('<h', self.data[0x3A:0x3C])
        # For 64-bit, this should be a constant. Sanity check ourselves
        assert self.section_header_length == 0x40
        self.section_header_table_size = unpack_single('<h', self.data[0x3C:0x3E])
        
        # Read shstrtab
        e_shstrndx = unpack_single('<h', self.data[0x3E:0x40])
        shstrtab_header_offset = self.section_header_table_offset + self.section_header_length * e_shstrndx
        shstrtab_offset = unpack_single('<q', self.data[shstrtab_header_offset+0x18:shstrtab_header_offset+0x20])
        self.shstrtab_offset = shstrtab_offset
        
    # Elf -> [Segment]
    def getTextSegments(self):
        acc = []
        
        header_offset = self.section_header_table_offset
        next_header_offset = header_offset
        for i in range(self.section_header_table_size):
            header_offset = next_header_offset
            next_header_offset += self.section_header_length
            
            section_flags = unpack_single('<q', self.data[header_offset+0x8:header_offset+0x10])
            # Only proceed if the section is executable.
            if section_flags & 0x4 == 0:
                continue
            section_address = unpack_single('<q', self.data[header_offset+0x10:header_offset+0x18])
            section_offset = unpack_single('<q', self.data[header_offset+0x18:header_offset+0x20])
            section_size = unpack_single('<q', self.data[header_offset+0x20:header_offset+0x28])
            acc.append(TextSegment( \
                section_offset, self.data[section_offset:section_offset+section_size], section_address))
        return acc
    
    # Elf -> [Segment]
    def getDataSegment(self):
        acc = []
        
        header_offset = self.section_header_table_offset
        next_header_offset = header_offset
        for i in range(self.section_header_table_size):
            header_offset = next_header_offset
            next_header_offset += self.section_header_length
            
            sh_name = unpack_single('<i', self.data[header_offset:header_offset+4])
            name = readcstr(self.data, self.shstrtab_offset + sh_name)
            if name != ".data": continue
            
            section_address = unpack_single('<q', self.data[header_offset+0x10:header_offset+0x18])
            section_offset = unpack_single('<q', self.data[header_offset+0x18:header_offset+0x20])
            section_size = unpack_single('<q', self.data[header_offset+0x20:header_offset+0x28])
            return(DataSegment( \
                section_offset, self.data[section_offset:section_offset+section_size], section_address))
        raise Exception("No .data segment found.")

class Segment():
    def __init__(self, offset_in_elf, data, address):
        self.offset_in_elf = offset_in_elf
        self.data = data
        self.address = address
        
    def getData(self):
        return self.data

class TextSegment(Segment):
    def __init__(self, offset_in_elf, data, address):
        super().__init__(offset_in_elf, data, address)
        
    def getCodeBlocks(self):
        offs = 0
        total_len = len(self.data)
        blocks = []
        while offs < total_len:
            temp = list(md.disasm(self.data[offs:], self.address + offs))
            if temp == []:
                offs += 1
                continue
            blocks.append(temp)
            offs = temp[-1].address + temp[-1].size
        return blocks

class DataSegment(Segment):
    pass
