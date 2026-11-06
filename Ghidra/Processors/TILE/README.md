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

`data/languages/TILE_le.slaspec` is generated from `support/tilegx_encodings.txt`,
the instruction fields, fixed-bit encodings and operand lists of the Tilera
TILE-Gx ISA manual ("TILE-Gx Instruction Set Architecture", UG401, release 1.3,
June 2013). `support/extract_ug401_encodings.py` reads that table out of the
manual's per-instruction "Bits Encoding" figures, Syntax lines and Functional
Descriptions; it documents the three figures it transcribes by hand. The
generated SLEIGH file and the encodings table are committed and are the
module's build input. Regeneration is optional:

```bash
python3 support/extract_ug401_encodings.py UG401-ISA.pdf support/tilegx_encodings.txt
python3 support/generate_tilegx_sleigh.py \
    support/tilegx_encodings.txt data/languages/TILE_le.slaspec
```

The extractor needs `pdfplumber`; the generator uses only the standard library
and contains decoder and semantic self-checks. The processor test also emulates
a cross-slot dependency to verify parallel bundle semantics.
