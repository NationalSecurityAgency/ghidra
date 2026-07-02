# TILE-Gx Ghidra Processor Module

The TILE processor module provides complete Ghidra support for the Tilera TILE-Gx architecture — a RISC processor with 32-bit fixed-length instructions, 64-bit registers, and rich multi-register (tile-based) operations.

## Quick Reference

| | |
|---|---|
| **ISA** | TILE-Gx (TILE32) |
| **Instruction** | 32-bit fixed-length |
| **Register Width** | 64-bit (TILEGX) / 32-bit (TILE32) |
| **Registers** | r0-r35 GP + sr0-sr35 CP + c0-c31 CP0 |
| **Endianness** | Big-endian (default) / Little-endian |
| **Calling Convention** | Register-passing (r0-r7), stack fallback |
| **ELF Machine Type** | 191 (0xBF, EM_TILEGX) |

## Language Variants

| Variant | Endian | Width | Description |
|---|---|---|---|
| `TILE:BE:64:default` | Big | 64-bit | Default TILE-Gx |
| `TILE:LE:64:default` | Little | 64-bit | Little-endian variant |
| `TILE:BE:64:xmos` | Big | 64-bit | XMOS XS1/XS2/XS3 |
| `TILE:LE:64:xmos` | Little | 64-bit | XMOS XS1/XS2/XS3 |

## Loading in Ghidra

1. Create a new Ghidra project
2. Import an ELF binary or raw binary (ELF loader auto-detects EM_TILEGX = 191)
3. Select the appropriate language variant above
4. Analyze with default settings

## Register Space

| Offset | Class | Registers |
|---|---|---|
| 0x0000 | C-flag | r0 (1 bit) |
| 0x1000 | GP | r0-r35 (36 x 8B) |
| 0x2000 | CP | sr0-sr35 (36 x 8B) |
| 0x3000 | CP0 | c0-c31 (32 x 8B) |
| 0x4000 | CSR | System (8B wide) |
| 0x5000 | XMOS | Register space |

## SLEC Language Files

| File | Purpose |
|---|---|
| `TILEGX.sinc` | Instruction encoding and P-code (70 lines) |
| `tile_common.sinc` | Shared definitions (130 lines) |
| `TILE.slaspec` | Language specification |
| `TILE.csped` | Compiler specification (XML) |
| `TILE.psped` | Processor specification (XML) |
| `TILE.ldefs` | Language definitions |
| `TILE.opinion` | ELF format detection |

## Build

```bash
cd Ghidra
./gradlew :Processors:TILE:build
```

Outputs: `Processors/TILE/build/libs/TILE.jar` (compiled processor module)

## Documentation

See [docs/TILEGX_Ghidra_Documentation.md](docs/TILEGX_Ghidra_Documentation.md) for the full reference.

## License

Apache License 2.0
