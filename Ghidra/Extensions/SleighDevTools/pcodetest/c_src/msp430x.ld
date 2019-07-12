MEMORY {
	RAM : ORIGIN = 0, LENGTH = 0x4000
	ROM (rx) : ORIGIN = 0x4000, LENGTH = 32k
}

SECTIONS {
	.rodata : { *(.eh_frame) } >ROM
	.data : { } >RAM
	.bss : { } >RAM
}
