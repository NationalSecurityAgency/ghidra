; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	add r2, 0, 0
	add r3, 1, 1
	add r4, 2, 2
	add r6, 3, 3
	add r0, r1, r5
	nop
	add ilink1, 4, 4
	add blink, 5, 5
	add sp, 6, 6
	add r1,r2,32
	add r3,r4,32
	add r5,r6,32
	add r1,ilink1,32
	add r1,blink,32
	add r1,sp,32
	add fp,sp,sp
	add sp,r1,sp
	add r1,r1,32
	add r1,r1,32
	add r1,r1,0x1FFFFFFF
	add 0x1FFFFFFF,r1,r2

	ADD r1,r2,r3
	ADD.NZ r1,r2,r3
	ADD.F r1,r2,r3
	ADD.NZ.F r1,r2,r3
	ADD r1,r2,34
	ADD.F r1,r2,34
	ADD r1,34,r2
	ADD r1,255,255
	ADD.F 0,r1,r2
	ADD.F 0,r1,34
	ADD.F 0,34,r1
	ADD 0,0,0
	ADD r3,1,2
	ADD.F r3,1,2
	;; A is shimmflags			
.WORD 0x47c08500
	;; A is limm 
.WORD 0x47a08500	
	;; register register
	;; conditional
	;; setting flags
	;;conditional and conditionally set flags
	;;register immediate
	;;immediate register
	;;immediate immediate (shimms MUST match)
	;;test
	;;test with immediate
	;;test with immediate
	;;null instruction, NOP

	
