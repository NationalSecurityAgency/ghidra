; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	extw r0,r0
	extw r1,r0
	extw r0,r1
	extw r1,r1
	extb r0,r0
	extb r1,r0
	extb r0,r1
	extb r1,r1
	nop
	nop
	sexw r0,r0
	sexb r0,r0
	flag r0
.WORD 0x18000000|(0<<9) ; flag
.WORD 0x18000000|(1<<9) ; asr
.WORD 0x18000000|(2<<9) ; lsr
.WORD 0x18000000|(3<<9) ; ror
.WORD 0x18000000|(4<<9) ; rrc
.WORD 0x18000000|(5<<9) ; sexb
.WORD 0x18000000|(6<<9) ; sexw
.WORD 0x18000000|(7<<9) ; extb
.WORD 0x18000000|(8<<9) ; extw
;.WORD 0x18000000|(9<<9) ; illegal instruction
;.WORD 0x18000000|(10<<9) ; illegal instruction
;.WORD 0x18000000|(11<<9) ; illegal instruction
;.WORD 0x18000000|(12<<9) ; illegal instruction
;.WORD 0x18000000|(13<<9) ; illegal instruction
;.WORD 0x18000000|(14<<9) ; illegal instruction
;.WORD 0x18000000|(15<<9) ; illegal instruction
;.WORD 0x18000000|(16<<9) ; illegal instruction
;.WORD 0x18000000|(17<<9) ; illegal instruction
;.WORD 0x18000000|(18<<9) ; illegal instruction
;.WORD 0x18000000|(19<<9) ; illegal instruction
