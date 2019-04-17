	.file	"inline.c"
	.intel_syntax noprefix
	.section	.rodata
.LC0:
	.string	"\nUsage: %s arg1 arg2\n\n"
.LC1:
	.string	"\nSum of %lu and %lu: %lu\n\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB2:
	sub	rsp, 40
.LCFI0:
	mov	DWORD PTR [rsp+12], edi
	mov	QWORD PTR [rsp], rsi
	cmp	DWORD PTR [rsp+12], 3
	je	.L2
	mov	rax, QWORD PTR [rsp]
	mov	rax, QWORD PTR [rax]
	mov	rsi, rax
	mov	edi, OFFSET FLAT:.LC0
	mov	eax, 0
	call	printf
	mov	eax, 0
	jmp	.L3
.L2:
	mov	rax, QWORD PTR [rsp]
	add	rax, 8
	mov	rax, QWORD PTR [rax]
	mov	edx, 10
	mov	esi, 0
	mov	rdi, rax
	call	strtoul
	mov	QWORD PTR [rsp+24], rax
	mov	rax, QWORD PTR [rsp]
	add	rax, 16
	mov	rax, QWORD PTR [rax]
	mov	edx, 10
	mov	esi, 0
	mov	rdi, rax
	call	strtoul
	mov	QWORD PTR [rsp+16], rax
	call	adjustStack
	mov	rax, QWORD PTR [rsp+32]
	mov	rdx, QWORD PTR [rsp+40]
	lea	rcx, [rdx+rax]
	mov	rdx, QWORD PTR [rsp+32]
	mov	rax, QWORD PTR [rsp+40]
	mov	rsi, rax
	mov	edi, OFFSET FLAT:.LC1
	mov	eax, 0
	call	printf
	call	restoreStack
	mov	eax, 0
.L3:
	add	rsp, 40
.LCFI1:
	ret
.LFE2:
	.size	main, .-main
	.globl	adjustStack
	.type	adjustStack, @function
adjustStack:
.LFB3:
        pop rdi
        sub rsp, 0x10
        push rdi
	ret
.LFE3:
	.size	adjustStack, .-adjustStack
	.globl	restoreStack
	.type	restoreStack, @function
restoreStack:
.LFB4:
        pop rdi
        add rsp, 0x10
        push rdi
	ret
.LFE4:
	.size	restoreStack, .-restoreStack
	.section	.eh_frame,"a",@progbits
.Lframe1:
	.long	.LECIE1-.LSCIE1
.LSCIE1:
	.long	0
	.byte	0x3
	.string	"zR"
	.uleb128 0x1
	.sleb128 -8
	.uleb128 0x10
	.uleb128 0x1
	.byte	0x3
	.byte	0xc
	.uleb128 0x7
	.uleb128 0x8
	.byte	0x90
	.uleb128 0x1
	.align 8
.LECIE1:
.LSFDE1:
	.long	.LEFDE1-.LASFDE1
.LASFDE1:
	.long	.LASFDE1-.Lframe1
	.long	.LFB2
	.long	.LFE2-.LFB2
	.uleb128 0
	.byte	0x4
	.long	.LCFI0-.LFB2
	.byte	0xe
	.uleb128 0x30
	.byte	0x4
	.long	.LCFI1-.LCFI0
	.byte	0xe
	.uleb128 0x8
	.align 8
.LEFDE1:
.LSFDE3:
	.long	.LEFDE3-.LASFDE3
.LASFDE3:
	.long	.LASFDE3-.Lframe1
	.long	.LFB3
	.long	.LFE3-.LFB3
	.uleb128 0
	.align 8
.LEFDE3:
.LSFDE5:
	.long	.LEFDE5-.LASFDE5
.LASFDE5:
	.long	.LASFDE5-.Lframe1
	.long	.LFB4
	.long	.LFE4-.LFB4
	.uleb128 0
	.align 8
.LEFDE5:
	.ident	"GCC: (GNU) 4.8.5 20150623 (Red Hat 4.8.5-28)"
	.section	.note.GNU-stack,"",@progbits
