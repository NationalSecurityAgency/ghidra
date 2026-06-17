# TILEGX Ghidra Documentation

## Overview
TILEGX is a RISC processor from Tilera with 64-bit registers and fixed-length 32-bit instructions.
This document describes the Ghidra processor module implementation for the TILE-Gx architecture.

## Architecture
- **ISA**: TILE-Gx
- **Register Width**: 64-bit (8 bytes)
- **Instruction Width**: 32-bit (fixed-length)
- **Endianness**: Little-endian (default) / Big-endian (configurable)
- **Register Classes**:
  - GP (0x1000): General purpose registers r0-r35
  - CP (0x2000): System registers sr0-sr35
  - CP0 (0x3000): Control registers c0-c31
  - CSR: Control/status registers

## SLEC Language Files

### TILEGX.sinc
Main SLEC definition file containing:
- Register class definitions (Ghidra SLEC `register` keyword with Ghidra SLEC `= 0x1000 SIZE = 8` syntax)
- P-code operation definitions (Ghidra SLEC `op=PADD:z(8):r8:r8:r8` syntax)
- Opcodes for TILEGX instructions
- Register width definitions (Ghidra SLEC `reg_width : GP 64` syntax)

### tile_common.sinc
Common SLEC definitions shared between TILEGX and TILE32:
- Register class definitions
- P-code operations
- Data type definitions
- Multi-register operations

### TILE.slaspec
SLEC language specification file that ties everything together:
- Endianness configuration (`@define ENDIAN "big"`)
- Register size (`@define REGISTER_SIZE "8"`)
- Includes TILEGX.sinc and tile_common.sinc
- Resolves instruction semantics (`RES_IS`)

## Ghidra SLEC Syntax Notes
- Ghidra SLEC `=` operator used for attribute assignments (e.g., `offset = 0x1000`)
- Ghidra SLEC `:` operator used for expression separators (e.g., `reg_width : GP 64`)
- Ghidra SLEC `SIZE` keyword followed by Ghidra SLEC `=` and size value
- Ghidra SLEC `op=` attribute for operation codes in define lines
- Ghidra SLEC semicolons terminate define statements
