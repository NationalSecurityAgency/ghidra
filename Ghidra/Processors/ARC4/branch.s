; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

mov r0, 0
mov r1, 1

# NOTE: Nested delay slot fails to disassemble in Ghidra but is permitted by the assembler (actual results TBD).
add r0,r1,r0
b.d foo
b.d foo
add r0,r1,r0           ; not executed
foo: sub r0,r1,r0      ; executed twice?
add r0,r1,r0
j blink

sub.f 0,r1,r2
bnz.jd bar
sub r0,r0,r0
bar:


# inst 1 j.d r0
# inst 2 j.d r1    <-- inst 1 delay slot
# inst 3 mov r1,0  <--  inst 2 delay slot

# ...

# r0: inst 10 mov r2,0
#     inst 11 j.d

# ...

# r1: inst 20 mov r3, 0
#     inst 21 j.d

#     	      t=0	t=1	t=2	t=3
#j.d r0	    fetch      PC=r0    NOP   	NOP
#j.d r1    	       fetch    PC=r1   NOP
#mov r2,0		    	fetch   op fetch ..
#mov r3,0				fetch


