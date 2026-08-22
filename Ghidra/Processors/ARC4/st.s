; Copyright 2023 The Johns Hopkins University Applied Physics Laboratory LLC
; Authors: Dan Genin and Tommy Johnson

	st r0, [r1, 1]
	st r0, [5,5]
	st r0, [5]
	st r0, [r3]
	st 3, [0x0fffffff]
    st 3, [3]
	st r0, [0x0fffffff]
	st.a r0, [r1,5]
	st.a r0, [r1,-1]

