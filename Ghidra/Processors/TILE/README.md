# TILE (TileProcessor)

TileProcessor is a Ghidra processor module for the Tilera TILE-Gx architecture.
TILE-Gx is a RISC processor with:
- 32-bit fixed-length instructions
- 64-bit registers (8 bytes each) with 32-bit instruction encoding
- Big and little endian variants
- 36 general-purpose registers (r0-r35)
- System registers (sr0-sr35) and control registers (c0-c31)
- Rich instruction set with arithmetic, logical, load/store, branch, multiply, SIMD, and floating-point operations
- ~36 general-purpose registers (r0-r7 used for function arguments)
- Register-passing calling convention with stack fallback

Register space layout:
- 0x0000: C flag register (single-bit condition)
- 0x1000: GP — General purpose registers (r0-r35)
- 0x2000: CP — System registers (sr0-sr35)
- 0x3000: CP0 — Control registers (c0-c31)
- 0x4000: CSR — Control/Status registers

Supported variants:
- TILE-Gx 64-bit (TILEGX): 64-bit registers with 32-bit encoding
- TILE-Gx 32-bit: 32-bit registers with 32-bit encoding
