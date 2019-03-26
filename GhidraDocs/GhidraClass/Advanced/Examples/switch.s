	.file	"switch.c"
	.intel_syntax noprefix
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"\nUsage: %s switch_var input\n\n"
.LC1:
	.string	"Returning %ld\n"
	.section	.text.startup,"ax",@progbits
	.p2align 4,,15
	.globl	main
	.type	main, @function
main:
.LFB20:
	.cfi_startproc
	push	rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	push	rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	mov	rbx, rsi
	sub	rsp, 8
	.cfi_def_cfa_offset 32
	cmp	edi, 3
	je	.L12
	mov	rsi, QWORD PTR [rsi]
	mov	edi, OFFSET FLAT:.LC0
	xor	eax, eax
	call	printf
	xor	eax, eax
.L13:
	add	rsp, 8
	.cfi_remember_state
	.cfi_def_cfa_offset 24
	pop	rbx
	.cfi_def_cfa_offset 16
	pop	rbp
	.cfi_def_cfa_offset 8
	ret
.L12:
	.cfi_restore_state
	mov	rdi, QWORD PTR [rsi+8]
	mov	edx, 10
	xor	esi, esi
	call	strtoul
	mov	rdi, QWORD PTR [rbx+16]
	mov	rbp, rax
	mov	edx, 10
	xor	esi, esi
	call	strtol
	mov	ecx, 10
	mov	rbx, rax
	xor	edx, edx
	mov	rax, rbp
	div	rcx
	jmp	[QWORD PTR array[0+rdx*8]]
.L2:
	lea	rbx, [rbx+rbx*4]
	add	rbx, 17
.L14:
	mov	rsi, rbx
	mov	edi, OFFSET FLAT:.LC1
	xor	eax, eax
	call	printf
	mov	eax, ebx
	jmp	.L13
.L11:
	imul	rbx, rbx, 14
	add	rbx, 53
	jmp	.L14
.L10:
	imul	rbx, rbx, 13
	add	rbx, 47
	jmp	.L14
.L9:
	imul	rbx, rbx, 12
	add	rbx, 43
	jmp	.L14
.L8:
	imul	rbx, rbx, 11
	add	rbx, 41
	jmp	.L14
.L7:
	imul	rbx, rbx, 10
	add	rbx, 37
	jmp	.L14
.L6:
	lea	rbx, [rbx+rbx*8]
	add	rbx, 31
	jmp	.L14
.L5:
	lea	rbx, [29+rbx*8]
	jmp	.L14
.L4:
	imul	rbx, rbx, 7
	add	rbx, 23
	jmp	.L14
.L3:
	imul	rbx, rbx, 6
	add	rbx, 19
	jmp	.L14
	.cfi_endproc
.LFE20:
	.size	main, .-main
	.globl	array
	.data
	.align 32
	.type	array, @object
	.size	array, 80
array:
	.quad OFFSET FLAT:.L2
	.quad OFFSET FLAT:.L3
	.quad OFFSET FLAT:.L4
	.quad OFFSET FLAT:.L5
	.quad OFFSET FLAT:.L6
	.quad OFFSET FLAT:.L7
	.quad OFFSET FLAT:.L8
	.quad OFFSET FLAT:.L9
	.quad OFFSET FLAT:.L10
	.quad OFFSET FLAT:.L11
	.ident	"GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-28)"
	.section	.note.GNU-stack,"",@progbits
