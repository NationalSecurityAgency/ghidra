# TILE-Gx processor

This module provides little-endian TILE-Gx ELF loading, bundle disassembly, and
p-code for Ghidra.

- Language ID: `TILE:LE:64:default`
- ELF machine: `EM_TILEGX` (`191`)
- Calling convention: GCC TILE-Gx ABI

Each 64-bit bundle decodes as either two X-pipeline operations or three
Y-pipeline operations. P-code reads all source registers before committing any
slot's destination and defers control flow until the complete bundle executes.
Scalar, memory, control-flow, atomic, multiplication, CRC, and selected SIMD
operations have native p-code. Instructions whose hardware behavior is not yet
modeled use mnemonic-specific user-ops.

## Opcode source

`data/languages/TILE_le.slaspec` is generated from the opcode masks in GNU
binutils 2.35.1 `opcodes/tilegx-opc.c`. The generated SLEIGH file is committed
and is the module's build input. Regeneration is optional:

```bash
cc <binutils include and library flags> support/dump_tilegx_opcodes.c \
    <binutils libraries> -o dump_tilegx_opcodes
python3 support/generate_tilegx_sleigh.py \
    ./dump_tilegx_opcodes data/languages/TILE_le.slaspec
```

The generator contains decoder and semantic self-checks. The processor test
also emulates a cross-slot dependency to verify parallel bundle semantics.
