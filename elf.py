from struct import pack, unpack

def unpack_single(f, d):
    return unpack(f, d)[0]

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
            section_offset = unpack_single('<q', self.data[header_offset+0x18:header_offset+0x20])
            section_size = unpack_single('<q', self.data[header_offset+0x20:header_offset+0x28])
            acc.append(TextSegment( \
                section_offset, self.data[section_offset:section_offset+section_size]))
        return acc

class Segment():
    def __init__(self, offset_in_elf, data):
        self.offset_in_elf = offset_in_elf
        self.data = data

class TextSegment(Segment):
    def __init__(self, offset_in_elf, data):
        super().__init__(offset_in_elf, data)
        
    def getCode(self):
        pass
