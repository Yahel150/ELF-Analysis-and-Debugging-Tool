
.section .data
msg: .ascii "Hello World\n"
msg_len: .quad msg_len - msg

.section .text
.global _start
_start:
	# write(1, msg, msg_len) 
	movq $1, %rax
	movq $1, %rdi
	movq $msg, %rsi
	movq (msg_len), %rdx
	syscall

	movq $60, %rax
	movq $0, %rdi
	syscall
