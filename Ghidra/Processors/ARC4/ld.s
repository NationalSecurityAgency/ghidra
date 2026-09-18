; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	ld r0, [r1, 1]
	;; ld r0, [5,4] to (sic) many shimms in load
	ld r0, [5,5]
	ld r0, [5]
	ld r0, [r3]
	ld r0, [r3, r4]
	ld r0, [r3, 0x0fffffff]
	ld r0, [0x0fffffff]
	;; ld r0, [0x0fffffff, 0x12] ld operand error
	;; ld.a r0, [5] write-back not permitted
	ld.a r0, [r1,5]
	ld.a r0, [r1,-1]
	ld.a r0, [r1,r2]
	ld.x r0, [r1]
	ldw.x  r0, [r1]
	ldb.x  r0, [r1]
	.WORD 0x081f000e	; ld r0, [0x1234, 0xe]
	.WORD 0x1234 		; supported by objdump but not as
	.WORD 0x0f126339

