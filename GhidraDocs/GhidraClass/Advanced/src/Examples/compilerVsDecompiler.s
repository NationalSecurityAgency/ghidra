	.file	"compilerVsDecompiler.c"
	.intel_syntax noprefix
	.text
	.p2align 4,,15
	.globl	calls_memcmp
	.type	calls_memcmp, @function
calls_memcmp:
.LFB3:
	.cfi_startproc
	mov	rax, rdi
	mov	rcx, rdx
	mov	rdi, rsi
	cmp	rdx, rdx
	mov	rsi, rax
	repz cmpsb
	seta	al
	setb	dl
	sub	al, dl
	movsx	eax, al
	ret
	.cfi_endproc
.LFE3:
	.size	calls_memcmp, .-calls_memcmp
	.p2align 4,,15
	.globl	calls_memcmp_fixed_len
	.type	calls_memcmp_fixed_len, @function
calls_memcmp_fixed_len:
.LFB4:
	.cfi_startproc
	mov	rax, rdi
	mov	ecx, 8
	mov	rdi, rsi
	mov	rsi, rax
	repz cmpsb
	seta	al
	setb	dl
	sub	al, dl
	movsx	eax, al
	ret
	.cfi_endproc
.LFE4:
	.size	calls_memcmp_fixed_len, .-calls_memcmp_fixed_len
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align 8
.LC0:
	.string	"\nUsage: %s string1 string2 len\n\n"
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC1:
	.string	"\nres1: %d res2: %d\n\n"
	.section	.text.startup,"ax",@progbits
	.p2align 4,,15
	.globl	main
	.type	main, @function
main:
.LFB2:
	.cfi_startproc
	push	r12
	.cfi_def_cfa_offset 16
	.cfi_offset 12, -16
	cmp	edi, 4
	push	rbp
	.cfi_def_cfa_offset 24
	.cfi_offset 6, -24
	push	rbx
	.cfi_def_cfa_offset 32
	.cfi_offset 3, -32
	mov	rbx, rsi
	je	.L4
	mov	rsi, QWORD PTR [rsi]
	mov	edi, OFFSET FLAT:.LC0
	xor	eax, eax
	call	printf
.L5:
	pop	rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 24
	pop	rbp
	.cfi_def_cfa_offset 16
	xor	eax, eax
	pop	r12
	.cfi_def_cfa_offset 8
	ret
.L4:
	.cfi_restore_state
	mov	rdi, QWORD PTR [rsi+24]
	mov	edx, 10
	xor	esi, esi
	call	strtoul
	mov	rbp, QWORD PTR [rbx+16]
	mov	rbx, QWORD PTR [rbx+8]
	mov	rdx, rax
	mov	rsi, rbp
	mov	rdi, rbx
	call	calls_memcmp
	mov	rsi, rbp
	mov	r12d, eax
	mov	rdi, rbx
	call	calls_memcmp_fixed_len
	mov	esi, r12d
	mov	edx, eax
	mov	edi, OFFSET FLAT:.LC1
	xor	eax, eax
	call	printf
	jmp	.L5
	.cfi_endproc
.LFE2:
	.size	main, .-main
	.ident	"GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-28)"
	.section	.note.GNU-stack,"",@progbits
