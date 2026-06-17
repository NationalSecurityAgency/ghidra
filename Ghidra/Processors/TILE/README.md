# TILE (TileProcessor)

TileProcessor is a Ghidra processor module for the Tilera TILE-Gx architecture.
TILE-Gx is a RISC processor with:
- 32-bit fixed-length instructions
- 32-bit addresses
- Big and little endian variants
- ~36 general-purpose registers (r0-r35)
- Rich instruction set with arithmetic, logical, load/store, branch, and system instructions

Supported variants:
- TILE-Gx 64-bit (TILEGX): 64-bit registers with 32-bit encoding
- TILE-Gx 32-bit: 32-bit registers with 32-bit encoding
