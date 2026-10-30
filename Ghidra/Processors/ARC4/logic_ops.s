; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	asl r0,r1
	asl r0,42
	asl r0,0xffffff
	nop
	asl 0,r0
	asl 0,42
	asl 0,0xfffffff
	nop
	and r0,r1,r2
	and r0,r1,r1
	and r0,r1,42
	and r0,r1,0xffffffff
	and r0,1,4
	and r0,0xffffffff,r1
	and r0,1,r1
	nop
	and 0,r1,r2
	and 0,r1,r1
	and 0,r1,42
	and 0,r1,0xffffffff
	and 0,1,4
	and 0,0xffffffff,r1
	and 0,1,r1
	
