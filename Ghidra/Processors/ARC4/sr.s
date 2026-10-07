; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

    mov  r2, 4
    sr r1,[r2]
    sr r1,[42]
    sr r1,[420000]
    sr 430000,[43]
    sr 44,[440000]
    sr 45,[r2]
    sr 450000,[r2]
    sr r2, [lp_end]
    sr r2, [4]
    sr r2, [5]
    sr r2, [7]

    lr r0, [r2]
    j.nd blink
