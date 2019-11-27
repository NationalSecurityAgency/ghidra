.hc05

.area	DIRECT (PAG)
;.setdp	0, DIRECT

;low_data1:
;.ds	1

.area PROGRAM	(ABS)
.org	0x80

LOW_SUB_TEST:
	RTS


.org	0x2000

HIGH_SUB_TEST:
	RTS


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ADC OP1                 is (op=0xA9 | op=0xB9 | op=0xC9 | op=0xD9 | op=0xE9 | op=0xF9) ... & OP1

	ADC #0xFE
	ADC *0xFE
	ADC 0xFEDC
	ADC 0xFEDC,X
	ADC 0xFE,X
	ADC ,X


; @if defined(HCS08) || defined(HC08)
; : ADC oprx16_8_SP                 is (op16=0x9ED9); oprx16_8_SP

;	ADC 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : ADC oprx8_8_SP                 is (op16=0x9EE9); oprx8_8_SP

;	ADC 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ADD OP1                 is (op=0xAB | op=0xBB | op=0xCB | op=0xDB | op=0xEB | op=0xFB) ... & OP1

	ADD #0xFE
	ADD *0xFE
	ADD 0xFEDC
	ADD 0xFEDC,X
	ADD 0xFE,X
	ADD ,X


; @if defined(HCS08) || defined(HC08)
; : ADD oprx16_8_SP                 is (op16=0x9EDB); oprx16_8_SP

;	ADD 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : ADD oprx8_8_SP                 is (op16=0x9EEB); oprx8_8_SP

;	ADD 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : AIS iopr8is                 is op=0xA7; iopr8is

;	AIS #0x7F
;	AIS #-0x7F

; @if defined(HCS08) || defined(HC08)
; : AIX iopr8is                 is op=0xAF; iopr8is

;	AIX #0x7F
;	AIX #-0x7F


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : AND OP1                 is (op=0xA4 | op=0xB4 | op=0xC4 | op=0xD4 | op=0xE4 | op=0xF4) ... & OP1

	AND #0xFE
	AND *0xFE
	AND 0xFEDC
	AND 0xFEDC,X
	AND 0xFE,X
	AND ,X


; @if defined(HCS08) || defined(HC08)
; : AND oprx16_8_SP                 is (op16=0x9ED4); oprx16_8_SP

;	AND 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : AND oprx8_8_SP                 is (op16=0x9EE4); oprx8_8_SP

;	AND 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ASLA                    is op=0x48

	ASLA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ASLX                    is op=0x58

	ASLX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ASL OP1                 is (op=0x38 | op=0x68 | op=0x78) ... & OP1

	ASL *0xFE
	ASL 0xFE,X
	ASL ,X


; @if defined(HCS08) || defined(HC08)
; : ASL oprx8_8_SP                 is (op16=0x9E68); oprx8_8_SP

;	ASL 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ASRA                    is op=0x47

	ASRA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ASRX                    is op=0x57

	ASRX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ASR OP1                 is (op=0x37 | op=0x67 | op=0x77) ... & OP1

	ASR *0xFE
	ASR 0xFE,X
	ASR ,X


; @if defined(HCS08) || defined(HC08)
; : ASR oprx8_8_SP                 is (op16=0x9E67); oprx8_8_SP

;	ASR 0xFE,S


BACKWARDS1:

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BCC REL                 is op=0x24; REL

	BCC BACKWARDS1
	BCC FORWARDS1


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BCLR nIndex, opr8a_8          is op4_7=1 & nIndex & NthBit & op0_0=1; opr8a_8

	BCLR #0, *0xFE
	BCLR #1, *0xED
	BCLR #2, *0xDC
	BCLR #3, *0xCB
	BCLR #4, *0xBA
	BCLR #5, *0xA9
	BCLR #6, *0x98
	BCLR #7, *0x87


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BCS REL                 is op=0x25; REL

	BCS BACKWARDS1
	BCS FORWARDS1


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BEQ REL                 is op=0x27; REL

	BEQ BACKWARDS1
	BEQ FORWARDS1


; @if defined(HCS08) || defined(HC08)
; : BGE REL                 is op=0x90; REL

;	BGE BACKWARDS1
;	BGE FORWARDS1


; @if defined(HCS08)
; : BGND                    is op=0x82

;	BGND


; @if defined(HCS08) || defined(HC08)
; : BGT REL                 is op=0x92; REL

;	BGT BACKWARDS1
;	BGT FORWARDS1


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BHCC REL                is op=0x28; REL

	BHCC BACKWARDS1
	BHCC FORWARDS1


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BHCS REL                is op=0x29; REL

	BHCS BACKWARDS1
	BHCS FORWARDS1


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BHI REL                 is op=0x22; REL

	BHI BACKWARDS1
	BHI FORWARDS1


; :BHS REL	is op=0x24; REL		See BCC

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BIH REL                 is op=0x2F; REL

	BIH BACKWARDS1
	BIH FORWARDS1


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BIL REL                 is op=0x2E; REL

	BIL BACKWARDS1
	BIL FORWARDS1


FORWARDS1:
BACKWARDS2:

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BIT OP1                 is (op=0xA5 | op=0xB5 | op=0xC5 | op=0xD5 | op=0xE5 | op=0xF5) ... & OP1

	BIT #0xFE
	BIT *0xFE
	BIT 0xFEDC
	BIT 0xFEDC,X
	BIT 0xFE,X
	BIT ,X


; @if defined(HCS08) || defined(HC08)
; : BIT oprx16_8_SP                 is (op16=0x9ED5); oprx16_8_SP

;	BIT 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : BIT oprx8_8_SP                 is (op16=0x9EE5); oprx8_8_SP

;	BIT 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : BLE REL                 is op=0x93; REL

;	BLE BACKWARDS2
;	BLE FORWARDS2


; :BLO REL	is op=0x25; REL		see BCS

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BLS REL                 is op=0x23; REL

	BLS BACKWARDS2
	BLS FORWARDS2


; @if defined(HCS08) || defined(HC08)
; : BLT REL                 is op=0x91; REL

;	BLT BACKWARDS2
;	BLT FORWARDS2


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BMC REL                 is op=0x2C; REL

	BMC BACKWARDS2
	BMC FORWARDS2


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BMI REL                 is op=0x2B; REL

	BMI BACKWARDS2
	BMI FORWARDS2


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BMS REL                 is op=0x2D; REL

	BMS BACKWARDS2
	BMS FORWARDS2


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BNE REL                 is op=0x26; REL

	BNE BACKWARDS2
	BNE FORWARDS2


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BPL REL                 is op=0x2A; REL

	BPL BACKWARDS2
	BPL FORWARDS2


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BRA REL                 is op=0x20; REL

	BRA BACKWARDS2
	BRA FORWARDS2


FORWARDS2:
BACKWARDS3:

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BRCLR nIndex, opr8a_8, REL    is op4_7=0 & nIndex & NthBit & op0_0=1; opr8a_8; REL

	BRCLR #0, *0xFE,BACKWARDS3
	BRCLR #1, *0xED,BACKWARDS3
	BRCLR #2, *0xDC,BACKWARDS3
	BRCLR #3, *0xCB,BACKWARDS3
	BRCLR #4, *0xBA,BACKWARDS3
	BRCLR #5, *0xA9,BACKWARDS3
	BRCLR #6, *0x98,BACKWARDS3
	BRCLR #7, *0x87,BACKWARDS3

	BRCLR #0, *0xFE,FORWARDS3
	BRCLR #1, *0xED,FORWARDS3
	BRCLR #2, *0xDC,FORWARDS3
	BRCLR #3, *0xCB,FORWARDS3
	BRCLR #4, *0xBA,FORWARDS3
	BRCLR #5, *0xA9,FORWARDS3
	BRCLR #6, *0x98,FORWARDS3
	BRCLR #7, *0x87,FORWARDS3


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; branch never is a two-byte nop
; : BRN REL                 is op=0x21; REL

	BRN BACKWARDS3
	BRN FORWARDS3


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BRSET nIndex, opr8a_8, REL    is op4_7=0 & nIndex & NthBit & op0_0=0; opr8a_8; REL

	BRSET #0, *0xFE,BACKWARDS3
	BRSET #1, *0xED,BACKWARDS3
	BRSET #2, *0xDC,BACKWARDS3
	BRSET #3, *0xCB,BACKWARDS3
	BRSET #4, *0xBA,BACKWARDS3
	BRSET #5, *0xA9,BACKWARDS3
	BRSET #6, *0x98,BACKWARDS3
	BRSET #7, *0x87,BACKWARDS3

	BRSET #0, *0xFE,FORWARDS3
	BRSET #1, *0xED,FORWARDS3
	BRSET #2, *0xDC,FORWARDS3
	BRSET #3, *0xCB,FORWARDS3
	BRSET #4, *0xBA,FORWARDS3
	BRSET #5, *0xA9,FORWARDS3
	BRSET #6, *0x98,FORWARDS3
	BRSET #7, *0x87,FORWARDS3


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BSET nIndex, opr8a_8          is op4_7=1 & nIndex & NthBit & op0_0=0; opr8a_8

	BSET #0, *0xFE
	BSET #1, *0xED
	BSET #2, *0xDC
	BSET #3, *0xCB
	BSET #4, *0xBA
	BSET #5, *0xA9
	BSET #6, *0x98
	BSET #7, *0x87

FORWARDS3:
BACKWARDS4:

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : BSR REL                 is op=0xAD; REL

	BSR BACKWARDS4
	BSR FORWARDS4


; @if defined(HCS08) || defined(HC08)
; : CBEQ opr8a_8, REL           is (op=0x31); opr8a_8; REL

;	CBEQ *0xFE, BACKWARDS4
;	CBEQ *0xFE, FORWARDS4


; @if defined(HCS08) || defined(HC08)
; : CBEQA iopr8i, REL          is op=0x41; iopr8i; REL

;	CBEQA #0xFE, BACKWARDS4
;	CBEQA #0xFE, FORWARDS4


; @if defined(HCS08) || defined(HC08)
; : CBEQX iopr8i, REL          is op=0x51; iopr8i; REL

;	CBEQX #0xFE, BACKWARDS4
;	CBEQX #0xFE, FORWARDS4


; @if defined(HCS08) || defined(HC08)
; : CBEQ oprx8, X"+", REL      is (op=0x61) & X; oprx8; REL

;	CBEQ *0xFE, X+, BACKWARDS4
;	CBEQ *0xFE, X+, FORWARDS4


; @if defined(HCS08) || defined(HC08)
; : CBEQ ","X"+", REL      is (op=0x71) & X; REL

;	CBEQ ,X+, BACKWARDS4
;	CBEQ ,X+, FORWARDS4


; @if defined(HCS08) || defined(HC08)
; : CBEQ oprx8_8_SP, REL      is (op16=0x9E61); oprx8_8_SP; REL

;	CBEQ 0xFE,S, BACKWARDS4
;	CBEQ 0xFE,S, FORWARDS4


FORWARDS4:

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CLC                     is op=0x98

	CLC


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CLI                     is op=0x9A

	CLI


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CLRA                    is op=0x4F

	CLRA

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CLRX                    is op=0x5F

	CLRX


; @if defined(HCS08) || defined(HC08)
; : CLRH                    is op=0x8C

;	CLRH


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CLR OP1                 is (op=0x3F | op=0x6F | op=0x7F) ... & OP1

	CLR *0xFE
	CLR 0xFE,X
	CLR ,X


; @if defined(HCS08) || defined(HC08)
; : CLR oprx8_8_SP                 is (op16=0x9E6F); oprx8_8_SP

;	CLR 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CMP OP1                 is (op=0xA1 | op=0xB1 | op=0xC1 | op=0xD1 | op=0xE1 | op=0xF1) ... & OP1

	CMP #0xFE
	CMP *0xFE
	CMP 0xFEDC
	CMP 0xFEDC,X
	CMP 0xFE,X
	CMP ,X


; @if defined(HCS08) || defined(HC08)
; : CMP oprx16_8_SP                 is (op16=0x9ED1); oprx16_8_SP

;	CMP 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : CMP oprx8_8_SP                 is (op16=0x9EE1); oprx8_8_SP

;	CMP 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : COMA                    is op=0x43

	COMA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : COMX                    is op=0x53

	COMX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : COM OP1                 is (op=0x33 | op=0x63 | op=0x73) ... & OP1

	COM *0xFE
	COM 0xFE,X
	COM ,X


; @if defined(HCS08) || defined(HC08)
; : COM oprx8_8_SP                 is (op16=0x9E63); oprx8_8_SP

;	COM 0xFE,S


; @if defined(HCS08)
; : CPHX opr16a_16       is (op=0x3E); opr16a_16

;	CPHX 0xFEDC


; @if defined(HCS08) || defined(HC08)
; : CPHX iopr16i       is (op=0x65); iopr16i

;	CPHX #0xFEDC


; @if defined(HCS08) || defined(HC08)
; : CPHX opr8a_16       is (op=0x75); opr8a_16

;	CPHX *0xFE


; @if defined(HCS08)
; : CPHX oprx8_16_SP       is (op16=0x9EF3); oprx8_16_SP

;	CPHX 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : CPX OP1                 is (op=0xA3 | op=0xB3 | op=0xC3 | op=0xD3 | op=0xE3 | op=0xF3) ... & OP1

	CPX #0xFE
	CPX *0xFE
	CPX 0xFEDC
	CPX 0xFEDC,X
	CPX 0xFE,X
	CPX ,X


; @if defined(HCS08) || defined(HC08)
; : CPX oprx16_8_SP                 is (op16=0x9ED3); oprx16_8_SP

;	CPX 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : CPX oprx8_8_SP                 is (op16=0x9EE3); oprx8_8_SP

;	CPX 0xFE,S

BACKWARDS5:

; @if defined(HCS08) || defined(HC08)
; : DAA                     is op=0x72

;	DAA


; @if defined(HCS08) || defined(HC08)
; : DBNZA REL               is op=0x4B; REL

;	DBNZA BACKWARDS5
;	DBNZA FORWARDS5


; @if defined(HCS08) || defined(HC08)
; : DBNZX REL               is op=0x5B; REL

;	DBNZX BACKWARDS5
;	DBNZX FORWARDS5


; @if defined(HCS08) || defined(HC08)
; : DBNZ OP1, REL           is (op=0x3B | op=0x6B | op=0x7B) ... & OP1; REL

;	DBNZ *0xFE, BACKWARDS5
;	DBNZ 0xFE,X, BACKWARDS5
;	DBNZ ,X, BACKWARDS5

;	DBNZ *0xFE, FORWARDS5
;	DBNZ 0xFE,X, FORWARDS5
;	DBNZ ,X, FORWARDS5


; @if defined(HCS08) || defined(HC08)
; : DBNZ oprx8_8_SP, REL                 is (op16=0x9E6B); oprx8_8_SP; REL

;	DBNZ 0xFE,S, BACKWARDS5
;	DBNZ 0xFE,S, FORWARDS5


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : DECA                    is op=0x4A

	DECA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : DECX                    is op=0x5A

	DECX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : DEC OP1                 is (op=0x3A | op=0x6A | op=0x7A) ... & OP1

	DEC *0xFE
	DEC 0xFE,X
	DEC ,X


; @if defined(HCS08) || defined(HC08)
; : DEC oprx8_8_SP                 is (op16=0x9E6A); oprx8_8_SP

;	DEC 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : DIV                     is op=0x52

;	DIV


FORWARDS5:

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : EOR OP1                 is (op=0xA8 | op=0xB8 | op=0xC8 | op=0xD8 | op=0xE8 | op=0xF8) ... & OP1

	EOR #0xFE
	EOR *0xFE
	EOR 0xFEDC
	EOR 0xFEDC,X
	EOR 0xFE,X
	EOR ,X


; @if defined(HCS08) || defined(HC08)
; : EOR oprx16_8_SP                 is (op16=0x9ED8); oprx16_8_SP

;	EOR 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : EOR oprx8_8_SP                 is (op16=0x9EE8); oprx8_8_SP

;	EOR 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : INCA                    is op=0x4C

	INCA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : INCX                    is op=0x5C

	INCX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : INC OP1                 is (op=0x3C | op=0x6C | op=0x7C) ... & OP1

	INC *0xFE
	INC 0xFE,X
	INC ,X


; @if defined(HCS08) || defined(HC08)
; : INC oprx8_8_SP                 is (op16=0x9E6C); oprx8_8_SP

;	INC 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : JMP ADDR                is (op=0xBC | op=0xCC) ... & ADDR

	JMP *LOW_SUB_TEST
	JMP HIGH_SUB_TEST


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : JMP ADDRI               is (op=0xDC | op=0xEC | op=0xFC) ... & ADDRI

	JMP 0xFEDC,X
	JMP 0xFE,X
	JMP ,X


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : JSR ADDR                is (op=0xBD | op=0xCD) ... & ADDR

	JSR *LOW_SUB_TEST
	JSR HIGH_SUB_TEST


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : JSR ADDRI               is (op=0xDD | op=0xED | op=0xFD) ... & ADDRI

	JSR 0xFEDC,X
	JSR 0xFE,X
	JSR ,X


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : LDA OP1                 is (op=0xA6 | op=0xB6 | op=0xC6 | op=0xD6 | op=0xE6 | op=0xF6) ... & OP1

	LDA #0xFE
	LDA *0xFE
	LDA 0xFEDC
	LDA 0xFEDC,X
	LDA 0xFE,X
	LDA ,X


; @if defined(HCS08) || defined(HC08)
; : LDA oprx16_8_SP                 is (op16=0x9ED6); oprx16_8_SP

;	LDA 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : LDA oprx8_8_SP                 is (op16=0x9EE6); oprx8_8_SP

;	LDA 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : LDHX iopr16i           is (op=0x45); iopr16i

;	LDHX #0xFEDC


; @if defined(HCS08) || defined(HC08)
; : LDHX opr8a_16               is (op=0x55); opr8a_16

;	LDHX *0xFE


; @if defined(HCS08)
; : LDHX opr16a_16              is (op=0x32); opr16a_16

;	LDHX 0xFEDC


; @if defined(HCS08)
; : LDHX ","X              is (op16=0x9EAE) & X

;	LDHX ,X


; @if defined(HCS08)
; : LDHX oprx16_16_X              is (op16=0x9EBE); oprx16_16_X

;	LDHX 0xFEDC,X


; @if defined(HCS08)
; : LDHX oprx8_16_X              is (op16=0x9ECE); oprx8_16_X

;	LDHX 0xFE,X


; @if defined(HCS08)
; : LDHX oprx8_16_SP              is (op16=0x9EFE); oprx8_16_SP

;	LDHX 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : LDX OP1                 is (op=0xAE | op=0xBE | op=0xCE | op=0xDE | op=0xEE | op=0xFE) ... & OP1

	LDX #0xFE
	LDX *0xFE
	LDX 0xFEDC
	LDX 0xFEDC,X
	LDX 0xFE,X
	LDX ,X


; @if defined(HCS08) || defined(HC08)
; : LDX oprx16_8_SP                 is (op16=0x9EDE); oprx16_8_SP

;	LDX 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : LDX oprx8_8_SP                 is (op16=0x9EEE); oprx8_8_SP

;	LDX 0xFE,S


; ## Logical Shift left is same as arithmetic shift left
; :LSLA		is op=0x48
; :LSLX		is op=0x58
; :LSL OP1	is (op=0x38 | op=0x68 | op=0x78) ... & OP1

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : LSRA                    is op=0x44

	LSRA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : LSRX                    is op=0x54

	LSRX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : LSR OP1                 is (op=0x34 | op=0x64 | op=0x74) ... & OP1

	LSR *0xFE
	LSR 0xFE,X
	LSR ,X


; @if defined(HCS08) || defined(HC08)
; : LSR oprx8_8_SP                 is (op16=0x9E64); oprx8_8_SP

;	LSR 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : MOV opr8a_8, op2_opr8a	is (op=0x4E); opr8a_8; op2_opr8a

;	MOV *0xFE, *0x97


; @if defined(HCS08) || defined(HC08)
; : MOV opr8a_8, X"+"     is (op=0x5E); opr8a_8 & X

;	MOV 0xFE, X+


; @if defined(HCS08) || defined(HC08)
; : MOV iopr8i, op2_opr8a  is (op=0x6E); iopr8i; op2_opr8a

;	MOV #0xFE, *0x97


; @if defined(HCS08) || defined(HC08)
; : MOV ","X"+," op2_opr8a  is (op=0x7E) & X; op2_opr8a

;	MOV ,X+, *0xFE


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : MUL                     is op=0x42

	MUL


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : NEGA                    is op=0x40

	NEGA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : NEGX                    is op=0x50

	NEGX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : NEG OP1                 is (op=0x30 | op=0x60 | op=0x70) ... & OP1

	NEG *0xFE
	NEG 0xFE,X
	NEG ,X


; @if defined(HCS08) || defined(HC08)
; : NEG oprx8_8_SP                 is (op16=0x9E60); oprx8_8_SP

;	NEG 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : NOP                     is op = 0x9D

	NOP


; @if defined(HCS08) || defined(HC08)
; : NSA                     is op = 0x62

;	NSA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ORA OP1                 is (op=0xAA | op=0xBA | op=0xCA | op=0xDA | op=0xEA | op=0xFA) ... & OP1

	ORA #0xFE
	ORA *0xFE
	ORA 0xFEDC
	ORA 0xFEDC,X
	ORA 0xFE,X
	ORA ,X


; @if defined(HCS08) || defined(HC08)
; : ORA oprx16_8_SP                 is (op16=0x9EDA); oprx16_8_SP

;	ORA 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : ORA oprx8_8_SP                 is (op16=0x9EEA); oprx8_8_SP

;	ORA 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : PSHA                    is op = 0x87

;	PSHA


; @if defined(HCS08) || defined(HC08)
; : PSHH                    is op = 0x8B

;	PSHH


; @if defined(HCS08) || defined(HC08)
; : PSHX                    is op = 0x89

;	PSHX


; @if defined(HCS08) || defined(HC08)
; : PULA                    is op = 0x86

;	PULA


; @if defined(HCS08) || defined(HC08)
; : PULH                    is op = 0x8A

;	PULH


; @if defined(HCS08) || defined(HC08)
; : PULX                    is op = 0x88

;	PULX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ROLA                    is op=0x49

	ROLA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ROLX                    is op=0x59

	ROLX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ROL OP1                 is (op=0x39 | op=0x69 | op=0x79) ... & OP1

	ROL *0xFE
	ROL 0xFE,X
	ROL ,X


; @if defined(HCS08) || defined(HC08)
; : ROL oprx8_8_SP                 is (op16=0x9E69); oprx8_8_SP

;	ROL 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : RORA                    is op=0x46

	RORA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : RORX                    is op=0x56

	RORX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : ROR OP1                 is (op=0x36 | op=0x66 | op=0x76) ... & OP1

	ROR *0xFE
	ROR 0xFE,X
	ROR ,X


; @if defined(HCS08) || defined(HC08)
; : ROR oprx8_8_SP                 is (op16=0x9E66); oprx8_8_SP

;	ROR 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : RSP                     is op = 0x9C

	RSP


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : RTI                     is op = 0x80

	RTI


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : RTS                     is op = 0x81

	RTS


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : SBC OP1                 is (op=0xA2 | op=0xB2 | op=0xC2 | op=0xD2 | op=0xE2 | op=0xF2) ... & OP1

	SBC #0xFE
	SBC *0xFE
	SBC 0xFEDC
	SBC 0xFEDC,X
	SBC 0xFE,X
	SBC ,X


; @if defined(HCS08) || defined(HC08)
; : SBC oprx16_8_SP                 is (op16=0x9ED2); oprx16_8_SP

;	SBC 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : SBC oprx8_8_SP                 is (op16=0x9EE2); oprx8_8_SP

;	SBC 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : SEC                     is op = 0x99

	SEC


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : SEI                     is op = 0x9B

	SEI


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : STA OP1                 is (op=0xB7 | op=0xC7 | op=0xD7 | op=0xE7 | op=0xF7) ... & OP1

	STA *0xFE
	STA 0xFEDC
	STA 0xFEDC,X
	STA 0xFE,X
	STA ,X


; @if defined(HCS08) || defined(HC08)
; : STA oprx16_8_SP                 is (op16=0x9ED7); oprx16_8_SP

;	STA 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : STA oprx8_8_SP                 is (op16=0x9EE7); oprx8_8_SP

;	STA 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : STHX opr8a_16               is (op=0x35); opr8a_16

;	STHX *0xFE


; @if defined(HCS08)
; : STHX opr16a_16              is (op=0x96); opr16a_16

;	STHX 0xFEDC


; @if defined(HCS08)
; : STHX oprx8_16_SP           is (op16=0x9EFF); oprx8_16_SP

;	STHX 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : STOP                    is op=0x8E

	STOP


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : STX OP1                 is (op=0xBF | op=0xCF | op=0xDF | op=0xEF | op=0xFF) ... & OP1

	STX *0xFE
	STX 0xFEDC
	STX 0xFEDC,X
	STX 0xFE,X
	STX ,X


; @if defined(HCS08) || defined(HC08)
; : STX oprx16_8_SP                 is (op16=0x9EDF); oprx16_8_SP

;	STX 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : STX oprx8_8_SP                 is (op16=0x9EEF); oprx8_8_SP

;	STX 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : SUB OP1                 is (op=0xA0 | op=0xB0 | op=0xC0 | op=0xD0 | op=0xE0 | op=0xF0) ... & OP1

	SUB #0xFE
	SUB *0xFE
	SUB 0xFEDC
	SUB 0xFEDC,X
	SUB 0xFE,X
	SUB ,X


; @if defined(HCS08) || defined(HC08)
; : SUB oprx16_8_SP                 is (op16=0x9ED0); oprx16_8_SP

;	SUB 0xFEDC,S


; @if defined(HCS08) || defined(HC08)
; : SUB oprx8_8_SP                 is (op16=0x9EE0); oprx8_8_SP

;	SUB 0xFE,S


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : SWI                     is op=0x83

	SWI


; @if defined(HCS08) || defined(HC08)
; : TAP                     is op=0x84

;	TAP


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : TAX                     is op=0x97

	TAX


; @if defined(HCS08) || defined(HC08)
; : TPA                     is op=0x85

;	TPA

; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : TSTA                    is op=0x4D

	TSTA


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : TSTX                    is op=0x5D

	TSTX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : TST OP1                 is (op=0x3D | op=0x6D | op=0x7D) ... & OP1

	TST *0xFE
	TST 0xFE,X
	TST ,X


; @if defined(HCS08) || defined(HC08)
; : TST oprx8_8_SP                 is (op16=0x9E6D); oprx8_8_SP

;	TST 0xFE,S


; @if defined(HCS08) || defined(HC08)
; : TSX                     is op=0x95

;	TSX


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : TXA                     is op=0x9F

	TXA


; @if defined(HCS08) || defined(HC08)
; : TXS                     is op=0x94

;	TXS


; @if defined(HCS08) || defined(HC08) || defined(HC05)
; : WAIT                    is op=0x8f

	WAIT


HERE:
	BRA	HERE
