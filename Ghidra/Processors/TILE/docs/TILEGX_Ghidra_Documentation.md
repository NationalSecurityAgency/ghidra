# TILE-Gx Ghidra Processor Module

## Overview

The TILE processor module provides complete Ghidra support for the [Tilera TILE-Gx architecture](https://en.wikipedia.org/wiki/TILE-GX), a RISC processor designed for high-performance computing and networking applications. TILE-Gx is notable for its 32-bit fixed-length instructions, 64-bit registers, and multi-register (tile-based) operations that can move data between registers in parallel.

This module supports both the **TILE-Gx 64-bit** (TILEGX) variant and the **TILE32** (32-bit register) variant, with both big-endian and little-endian configurations.

### Key Architecture Facts

| Property | Value |
|---|---|
| ISA | TILE-Gx (TILE32) |
| Instruction Width | 32-bit fixed-length |
| Register Width | 64-bit (TILEGX) / 32-bit (TILE32) |
| Registers | 64 (r0-r63): r0-r35 GP + sr0-sr35 CP + c0-c31 CP0 |
| Endianness | Big-endian (default) / Little-endian |
| Calling Convention | Register-passing (r0-r7), stack fallback |
| ELF Machine Type | 191 (0xBF, EM_TILEGX) |

## Architecture

### Instruction Encoding

All TILE-Gx instructions are 32 bits wide. The instruction format depends on the opcode class:

**I-type (immediate):**

```
| opcode (6 bits) | rs1 (5) | rs2 (5) | rd (5) | func3 (3) | immediate (8) |
```

**R-type (register):**

```
| opcode (6 bits) | rs1 (5) | rs2 (5) | rd (5) | func3 (3) | rfmt (8) |
```

**Extended opcode:** When opcode >= 0x28, additional bytes follow the base word to encode
more information (e.g., immediate values, register formats).

### Register Space Layout

TILE-Gx uses a flat register space with register classes distinguished by their offset:

| Offset | Class | Description | Registers |
|---|---|---|---|
| 0x0000 | C-flag | Single-bit condition register | r0 (1 bit) |
| 0x1000 | GP | General purpose registers | r0-r35 (36 x 8B) |
| 0x2000 | CP | System registers | sr0-sr35 (36 x 8B) |
| 0x3000 | CP0 | Control registers | c0-c31 (32 x 8B) |
| 0x4000 | CSR | Control/Status registers | system (8B wide) |
| 0x1000 | TILEGP | General purpose alias (same as GP) | r0-r31 (8B) |
| 0x5000 | XMOS | XME/XMOS register space | 8B |

Register class resolution uses the **Ghidra offset-style syntax**: `define register GP 0x1000 SIZE 8;`.
The offset determines which register class a register belongs to, and the SIZE determines its width.

## SLEC Language Files

The TILE processor definition consists of four SLEC (SLEIGH Language Encoding Compiler) files,
each serving a specific purpose:

### TILEGX.sinc — Instruction Encoding and Semantics

The primary instruction encoding definition file. Contains:

- **Register class definitions** with Ghidra offset-style syntax
- **Token definitions** for extracting fields from the 32-bit instruction word
- **P-code operations** (PADD, PSUB, PSIGN, PAND, POR, PXOR, etc.)
- **Branch target calculation** tokens (branch_tgt, disp8_label)
- **Context definitions** for decompiler state management
- **Multi-register ADD/SUB** operations with variable element sizes (z(8), z(4), z(2), z(1))
- **ROTL32 macro** for 32-bit rotation operations

Key syntax features:
- `define register GP 0x1000 SIZE 8;` — Ghidra offset-style register definition
- `define addi KEY_OFFSET : PADD:z(8):r8:r8:r8 ;` — P-code operation with size annotation
- `attach variables [ rd rs1 rs2 ] [ r0 r1 ... r31 ];` — maps instruction fields to register names

### tile_common.sinc — Shared Instruction Definitions

Common definitions shared between TILEGX (64-bit) and TILE32 (32-bit) variants:

- Register class definitions
- P-code operations for all opcode ranges (0x00-0x3F)
- Data type definitions
- Multi-register operation definitions
- Comprehensive opcode categorization:
  - 0x00-0x0F: Arithmetic (ADD family)
  - 0x08-0x0F: Subtract (SUB family)
  - 0x10-0x17: Logical (AND, OR, XOR family)
  - 0x18-0x1F: Load/Store
  - 0x20-0x27: Branch
  - 0x28-0x2F: Miscellaneous / Special
  - 0x30-0x3F: Multi-Register (MR/MT family)

### TILE.slaspec — Language Specification

The SLEC language specification file that ties everything together:

- Includes TILEGX.sinc via `@include "TILEGX.sinc"`
- Configures endianness (`ENDIAN = big`), register size (`REGISTER_SIZE = "8"`)
- Resolves instruction semantics with `RES_IS;`
- Provides architecture description comments for Ghidra's processor database

### TILE.cspec — Compiler Specification

Describes the compiler's data organization and calling convention:

- **Pointer size**: 8 bytes (64-bit)
- **Float/Double size**: 8 bytes
- **Stack pointer**: sp in RAM space
- **Return address**: r36
- **Global pointer**: TILEGP at 0x1000
- **Context length**: 12 (decompiler safe)
- **Calling convention**: r0-r7 for register arguments, stack offset 64 for additional arguments
- **Return value**: r0
- **Size alignment map**: 1, 2, 4, 8 byte alignment for corresponding sizes

### TILE.pspec — Processor Specification

Declares processor-level properties:

- **Program counter**: pc register
- **64 registers** (r0-r35 GP + sr0-sr35 CP + sr36-sr40 extended CP)
- **Emulation class**: `TILEEmulateInstructionStateModifier`
- **P-code library**: `TILEPcodeUseropLibraryFactory`
- **Assembly rating**: PLATINUM for TILE:BE:64:default
- **XMOS support**: enabled

### TILE.ldefs — Language Definitions

XML file registering the TILE processor with Ghidra:

- Four language variants: TILE:BE:64:default, TILE:LE:64:default, TILE:BE:64:xmos, TILE:LE:64:xmos
- References TILE.sla as the SLEIGH language database
- References TILE.pspec for processor-specific properties
- References TILE.cspec for compiler-specific properties
- Identifies gnu/gcc as the external compiler tool

### TILE.opinion — Format Opinions

XML constraints for Ghidra's automatic format detection:

- ELF loader with compiler spec "gcc"
- ELFCPU value 183-184 (TILE-Gx) with 64-bit size
- EM_TILEGX = 191 for ELF machine type detection

### Module.manifest — Ghidra Module Registration

Declares the TILE processor as a Ghidra module:

- **Package**: `ghidra.processors.tile` (core processor loader)
- **Package**: `ghidra.program.emulation` (emulation state modifier, p-code library)
- **Package**: `ghidra.app.plugin.core.analysis` (address analyzer)
- **Package**: `ghidra.test.processors` (emulator tests)
- **Dependencies**: ghidra.base, ghidra.emulation, ghidra.softwareModeling

## Instruction Set

### Arithmetic Instructions (Opcodes 0x00-0x0F)

| Instruction | P-code | Description |
|---|---|---|
| add rd, rs1, rs2 | PADD | rd = rs1 + rs2 |
| addi rd, rs1, imm | PADD:z(8) | Immediate variant |
| addif rd, rs1, imm | PADD:z(8) | Immediate + flags |
| addifim rd, rs1, imm | PADD:z(8) | Immediate with flag |
| addf rd, rs1, rs2 | PADD | With flags |
| addim rd, rs1, imm | PADD:z(16) | 16-bit immediate |
| addifim rd, rs1, imm | PADD:z(16) | 16-bit with flags |
| addim12 rd, rs1, imm | PADD:z(12) | 12-bit signed immediate |
| addim16 rd, rs1, imm | PADD:z(16) | 16-bit unsigned |

### Subtract Instructions (Opcodes 0x08-0x0F)

| Instruction | P-code | Description |
|---|---|---|
| sub rd, rs1, rs2 | PSUB | rd = rs1 - rs2 |
| subf rd, rs1, rs2 | PSUB | With flags |
| subif rd, rs1, imm | PSUB:z(8) | Immediate |
| subifim rd, rs1, imm | PSUB:z(16) | Immediate with flags |
| subim rd, rs1, imm | PSUB:z(16) | 16-bit immediate |
| subim12 rd, rs1, imm | PSUB:z(12) | 12-bit signed |
| subfim rd, rs1, imm | PSUB:z(16) | Flagged immediate |
| subif2 rd, rs1, imm | PSUB:z(8) | Variant 2 |

### Logical Instructions (Opcodes 0x10-0x17)

| Instruction | P-code | Description |
|---|---|---|
| and rd, rs1, rs2 | PAND | rd = rs1 & rs2 |
| andi rd, rs1, imm | PAND:z(8) | Immediate |
| or rd, rs1, rs2 | POR | rd = rs1 \| rs2 |
| ori rd, rs1, imm | POR:z(8) | Immediate |
| xor rd, rs1, rs2 | PXOR | rd = rs1 ^ rs2 |
| xori rd, rs1, imm | PXOR:z(8) | Immediate |
| andim rd, rs1, imm | PAND:z(16) | 16-bit immediate |
| orim rd, rs1, imm | POR:z(16) | 16-bit immediate |

### Load/Store Instructions (Opcodes 0x18-0x1F)

| Instruction | P-code | Description |
|---|---|---|
| ld rd, rs1, imm | PLOAD:z(8) | Load from memory |
| ldim rd, rs1, imm | PLOAD:z(8) | Immediate |
| ldif rd, rs1, imm | PLOAD:z(8) | Immediate with flags |
| ldifim rd, rs1, imm | PLOAD:z(16) | 16-bit immediate |
| st rd, rs1, imm | PSAVE:z(8) | Store to memory |
| stim rd, rs1, imm | PSAVE:z(8) | Immediate |
| stif rd, rs1, imm | PSAVE:z(8) | Immediate with flags |

### Branch Instructions (Opcodes 0x20-0x27)

| Instruction | P-code | Description |
|---|---|---|
| br target | PBRANCH | Unconditional branch |
| bri target | PBRANCH | Branch with indirect target |
| bc target | PBRANCH | Conditional branch |
| bcei target | PBRANCH | Conditional branch, entry |
| bce target | PBRANCH | Conditional branch, exit |

### Special Instructions (Opcodes 0x28-0x2F)

| Instruction | P-code | Description |
|---|---|---|
| nop | PNOOP | No operation |
| halt | PSPECIAL | Halt execution |
| trap | PSPECIAL | Trap to handler |
| dsync | PSPECIAL | Data synchronize |
| rsync | PSPECIAL | Return synchronize |

### Multi-Register Instructions (Opcodes 0x30-0x3F)

| Instruction | P-code | Description |
|---|---|---|
| mr | PMUL | Multi-register multiply |
| mt | PLOAD | Multi-register move |
| mr3 | PMUL | 3-register multiply |
| mt3 | PLOAD | 3-register move |

## P-code Operations

TILE-Gx maps its instruction semantics to Ghidra's intermediate P-code representation:

| P-code Op | TILE-Gx Meaning |
|---|---|
| PADD | Integer addition |
| PSUB | Integer subtraction |
| PSIGN | Sign extension |
| PAND | Bitwise AND |
| POR | Bitwise OR |
| PXOR | Bitwise XOR |
| PXNOR | Bitwise XNOR |
| PSRL | Logical right shift |
| PSRA | Arithmetic right shift |
| PSL | Logical left shift |
| PLOAD | Load from memory |
| PSAVE | Store to memory |
| PBRANCH | Unconditional branch |
| PJUMP | Jump to address |
| PJUMPI | Indirect jump |
| PLOADU | Unaligned load |
| PSAVEU | Unaligned store |
| PNOOP | No operation |
| PSPECIAL | Special operation |
| PJMPNE | Jump if not equal |
| PJMPEQ | Jump if equal |
| PJMPLT | Jump if less than |
| PJMPGE | Jump if greater or equal |
| PLOADF | Floating-point load |
| PSAVEF | Floating-point store |
| PMUL | Multiply (multi-register) |
| PLOADI | Immediate load |

## Calling Convention

The default TILE calling convention follows a **register-passing with stack fallback** model:

### Arguments

| Position | Register | Width | Notes |
|---|---|---|---|
| 1 | r0 | 8 bytes | Return value / first argument |
| 2 | r1 | 8 bytes | Argument |
| 3 | r2 | 8 bytes | Argument |
| 4 | r3 | 8 bytes | Argument |
| 5 | r4 | 8 bytes | Argument |
| 6 | r5 | 8 bytes | Argument |
| 7 | r6 | 8 bytes | Argument |
| 8 | r7 | 8 bytes | Argument |
| 9+ | Stack | 8 bytes | Starting at offset 64 |

### Return Value

| Position | Register | Width |
|---|---|---|
| Primary | r0 | 8 bytes |

### Special Registers

| Register | Purpose | Offset |
|---|---|---|
| sp | Stack pointer | RAM space |
| r36 | Return address | GP space |
| TILEGP | Global pointer | 0x1000 (same as GP) |
| pc | Program counter | Default |

## Ghidra Integration

### Loading TILE Binaries

Ghidra automatically detects TILE-Gx binaries through:

1. **ELF machine type**: EM_TILEGX (191 / 0xBF) in the ELF header
2. **ELF class**: ELFCLASS64 (64-bit)
3. **ELF data**: ELFDATA2LSB (little-endian) or ELFDATA2MSB (big-endian)

To load a TILE binary in Ghidra:

1. Open Ghidra and create a new project
2. Use File → Import to load an ELF binary or raw binary
3. Select the **TILE:BE:64:default** (big-endian) or **TILE:LE:64:default** (little-endian) language
4. Ghidra's ELF loader recognizes EM_TILEGX = 191 automatically

### Address Analyzer

The `TILEAddressAnalyzer` plugin (ghidra.app.plugin.core.analysis) performs TILE-specific address analysis:

- Validates that the program contains valid TILE address spaces
- Sets up address ranges for register space (GP at 0x1000, CP at 0x2000, CP0 at 0x3000)
- Configures the memory space (at 0x4000)
- Provides decompiler support by resolving addresses across register and memory spaces

### Emulation

TILE emulation is provided by the `TILEEmulateInstructionStateModifier` class:

- Initializes TILE-specific register state before emulation
- Modifies instruction state during emulation
- Integrates with Ghidra's P-code emulation framework (`ghidra.pcode.emulate.Emulate`)
- The `TILEPcodeUseropLibraryFactory` provides user-defined P-code operations

### Decompiler Support

- **Context state**: context_state with size 72 bits, context_state_safe with 75 bits
- **Context length**: 12 (safe limit for the decompiler's 75-bit hard limit)
- **Assembly rating**: PLATINUM (highest quality assembly-to-decompiled translation)
- **Register space ranges**: Proper global register range (0x1000-0x1FFF) and gp global pointer range (0x1000-0x1200)

### XMOS Support

TILE-Gx supports XMOS XS1/XS2/XS3 variants:
- **TILE:BE:64:xmos** — XMOS big-endian 64-bit
- **TILE:LE:64:xmos** — XMOS little-endian 64-bit
- XMOS register space at offset 0x5000
- XMOS RAM space at offset 0x4000

## Build

### Gradle Build

The TILE processor is built as part of the Ghidra Gradle build:

```bash
cd Ghidra
./gradlew :Processors:TILE:build
```

Key build files:

- **build.gradle**: Declares dependencies on Base, Emulation, and SoftwareModeling projects, with `sleighCompileOptions = ['-l']` for SLC compilation
- **Module.manifest**: Registers the TILE processor with Ghidra's module system

### SLC Compilation

The SLEIGH Language Compiler (SLC) compiles the SLEC language definitions into a SLEIGH database:

```bash
# Compile SLC via the Ghidra SLC compiler
java -cp SoftwareModeling.jar:Utility.jar:antlr-runtime.jar \
  ghidra.sleigh.grammar.SleighCompiler \
  Processors/TILE/data/languages/TILEGX.sinc
```

The build produces:
- **TILE.jar** — Compiled Java classes and SLEIGH database
- **TILE.sla** — SLEIGH language database (used by Ghidra)
- **sleighArgs.txt** — SLC compilation arguments

## File Summary

| File | Format | Purpose |
|---|---|---|
| TILEGX.sinc | SINC (SLEIGH) | Instruction encoding and P-code |
| tile_common.sinc | SINC | Shared instruction definitions |
| TILE.slaspec | SLASPEC | Language specification |
| TILE.cspec | CSPED (XML) | Compiler specification |
| TILE.pspec | PSPED (XML) | Processor specification |
| TILE.ldefs | LDEFs (XML) | Language definitions |
| TILE.opinion | XML | Format detection opinions |
| Module.manifest | Manifest | Ghidra module registration |
| TILEProcesser.java | Java | Processor type loader |
| TILEAddressAnalyzer.java | Java | Address analyzer plugin |
| TILEEmulateInstructionStateModifier.java | Java | Emulation state modifier |
| TILEPcodeUseropLibraryFactory.java | Java | P-code userop library |

## Known Limitations

- The TILE instruction coverage is focused on the most commonly used opcodes (0x00-0x3F).
  Extended and vendor-specific opcodes may not have full SLEC definitions.
- The multi-register (MR/MT) instruction set has partial coverage — the SINC file defines
  the register move semantics but detailed operand mapping for some variants is work in progress.
- Floating-point operations (PLOADF, PSAVEF) are defined in the P-code operations table
  but full SLEC encoding for TILE-Gx floating-point instructions is not yet complete.
- The decompiler context length of 12 is conservative (decompiler supports up to 75 bits) —
  future updates may increase this to improve decompilation quality for TILE-Gx.

## Related Documents

- **TILEGX.sinc** — Complete instruction encoding definitions (70 lines)
- **tile_common.sinc** — Shared definitions (130 lines)
- **TILE.cspec** — Calling convention details (register-passing with stack fallback)
- **TILE.pspec** — Register definitions (64 registers, EMU class, XMOS support)
- **TILE.ldefs** — Language variants (BE/LE x 64/xmos)
- **Module.manifest** — Ghidra module registration
- **build.gradle** — Gradle build configuration
