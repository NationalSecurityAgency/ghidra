; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	sub r1,r2,32
	sub r3,r4,32
	sub r5,r6,32
	sub r1,ilink1,32
	sub r1,blink,32
	sub r1,sp,32
	sub fp,sp,sp
	sub sp,r1,sp
	sub r1,r1,32
	sub r1,r1,32
	sub r1,r1,0x1FFFFFFF
	sub 0x1FFFFFFF,r1,r2

	SUB r1,r2,r3
	SUB.NZ r1,r2,r3
	SUB.F r1,r2,r3
	SUB.NZ.F r1,r2,r3
	SUB r1,r2,34
	SUB.F r1,r2,34
	SUB r1,34,r2
	SUB r1,255,255
	SUB.F 0,r1,r2
	SUB.F 0,r1,34
	SUB.F 0,34,r1
	SUB 0,0,0
	SUB r3,1,2
	SUB.F r3,1,2
	
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

	
