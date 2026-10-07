; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	add r0, r1, r2
	j blink
	nop
	sub r0, r1, 10
	j 0xFFFF
	j blink
	nop
	add r1, r1, 5
	sub r0, r1, 10
	jz 0x10120
	j blink
