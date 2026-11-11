;    mov r2,r0
;    mov lp_count, 4
;    lp  loop_end
;loop_in:
;    ld r0,[r1]
;    add r2,r2,r0
;    add r2,r2,r0
;loop_end:
;    mov r0,r2
;    j blink

    nop
    nop
    nop
    mov lp_count, 10
    mov r2,0
    lp  loop1_end
loop1_in:
    ld r0,[r1]
    add r2,r2,r0
    add r2,r2,r0
    nop
    nop
    nop
    nop
loop1_end:
    mov r0,r2
    j blink

    mov r2, 0
    mov lp_count, 5
    mov r3, loop2_in>>2
    add r4, r3, 1
    sr  r3, [lp_start]		
    sr  r4, [lp_end]
	;; sr 0x8e, [lp_end]
    nop
    nop
loop2_in:
    add r2,r2,r0
    mov r0, r2
    j blink
