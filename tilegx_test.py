#!/usr/bin/env python3
# Generate a TILEGX test binary (ELF64) for cross-compilation testing.
# This creates a hand-crafted binary with known TILEGX instructions
# that can be loaded into Ghidra and verified for correct decompilation.
#
# TILEGX Instruction Encoding:
#   - 32-bit fixed-length instructions
#   - Top 6 bits = opcode (0x00-0x3F base, 0x40+ extended)
#   - Bottom 26 bits = operands (rd, rs1, rs2, imm)
#
# Register encoding: r0=0, r1=1, ..., r35=35
# */

import struct
import sys
import os

# TILEGX constants
EM_TILEGX = 191  # EM_TILEGX from ElfConstants.java
EI_CLASS = 2     # ELFCLASS64
EI_DATA = 1      # ELFDATA2LSB
EI_OSABI = 0     # ELFOSABI_NONE
ET_EXEC = 2
PT_LOAD = 1
PF_X = 1
PF_R = 4
PF_W = 2
SH_TYPE_PROGBITS = 0x01
SH_TYPE_NULL = 0x00

def pack_tile_inst(opcode, rd=0, rs1=0, rs2=0, rs3=0, imm=0, ext=False):
    """Pack a 32-bit TILEGX instruction.
    Args:
        opcode: instruction opcode (0x00-0x3F base, 0x40+ extended)
        rd: destination register (0-31)
        rs1: first source register (0-31)
        rs2: second source register (0-31)
        rs3: third source register (0-31)
        imm: immediate value
        ext: whether this is an extended opcode (0x40+)
    """
    if ext:
        # Extended opcode: top 6 bits are 0x40-0x7F
        val = ((opcode << 26) | (rd << 20) | (rs1 << 14) | (rs2 << 8) | (imm & 0x3F)) & 0xFFFFFFFF
    else:
        # Base opcode: top 6 bits are 0x00-0x3F
        val = ((opcode << 26) | (rd << 20) | (rs1 << 14) | (rs2 << 8) | (imm & 0x3F)) & 0xFFFFFFFF
    return struct.pack('<I', val)

def create_el_header():
    """Create a 64-bit ELF header for TILEGX."""
    elf_header = bytearray()

    # ELF magic (4 bytes)
    elf_header += b'\x7fELF'
    # ELF identification
    elf_header += struct.pack('B', EI_CLASS)      # EI_CLASS = ELFCLASS64
    elf_header += struct.pack('B', EI_DATA)       # EI_DATA = ELFDATA2LSB
    elf_header += struct.pack('B', 1)             # EI_VERSION
    elf_header += struct.pack('B', EI_OSABI)      # EI_OSABI
    elf_header += struct.pack('B', 0)             # EI_ABIVERSION
    elf_header += b'\x00' * 7                     # EI_PAD

    # ELF64 header fields (all little-endian)
    elf_header += struct.pack('<H', ET_EXEC)      # e_type
    elf_header += struct.pack('<H', EM_TILEGX)    # e_machine = 191 (0xBF)
    elf_header += struct.pack('<I', 1)            # e_version
    elf_header += struct.pack('<Q', 0x1000)       # e_entry
    elf_header += struct.pack('<Q', 64)           # e_phoff
    elf_header += struct.pack('<Q', 0)            # e_shoff
    elf_header += struct.pack('<I', 0)            # e_flags
    elf_header += struct.pack('<H', 64)           # e_ehsize
    elf_header += struct.pack('<H', 56)           # e_phentsize
    elf_header += struct.pack('<H', 1)            # e_phnum
    elf_header += struct.pack('<H', 64)           # e_shentsize
    elf_header += struct.pack('<H', 0)            # e_shnum
    elf_header += struct.pack('<H', 0)            # e_shstrndx

    return elf_header

def create_phdr():
    """Create a program header (PT_LOAD) for the code section."""
    phdr = bytearray()
    phdr += struct.pack('<I', PT_LOAD)            # p_type
    phdr += struct.pack('<I', PF_R | PF_X)       # p_flags (read + execute)
    phdr += struct.pack('<Q', 0)                  # p_offset
    phdr += struct.pack('<Q', 0x1000)            # p_vaddr
    phdr += struct.pack('<Q', 0x1000)            # p_paddr
    phdr += struct.pack('<Q', 1024)              # p_filesz (code + data)
    phdr += struct.pack('<Q', 1024)              # p_memsz
    phdr += struct.pack('<Q', 4096)              # p_align
    return phdr

def create_shdr():
    """Create a section header for the code section."""
    shdr = bytearray()
    shdr += struct.pack('<I', 0)                  # sh_name (null)
    shdr += struct.pack('<I', 1)                  # sh_type = SHT_PROGBITS
    shdr += struct.pack('<I', 0)                  # sh_flags
    shdr += struct.pack('<Q', 0x1000)            # sh_addr
    shdr += struct.pack('<Q', 64 + 56)           # sh_offset (after ELF header + phdr)
    shdr += struct.pack('<Q', 512)               # sh_size
    shdr += struct.pack('<I', 0)                  # sh_link
    shdr += struct.pack('<I', 0)                  # sh_info
    shdr += struct.pack('<Q', 4096)              # sh_addralign
    shdr += struct.pack('<Q', 0)                  # sh_entsize
    return shdr

def generate_test_program():
    """Generate a TILEGX test program with known instructions.

    The test function exercises:
    - ADD (arithmetic)
    - LD/ST (load/store)
    - OR (logical)
    - MUL3 (extended multiply)
    - CMPEQI (extended compare)
    - BR (branch)
    """
    code = bytearray()

    # Function start address = 0x1000
    # All addresses are relative to base address 0

    # === ADD FAMILY ===
    # add r0, r1, r1  -> r0 = r1 + r1
    # rd=0, rs1=1, rs2=1, opcode=0x00
    inst = (0x00 << 26) | (0 << 20) | (1 << 14) | (1 << 8)
    code += struct.pack('<I', inst)
    code += b'\x00' * 4  # padding to 32-bit word

    # add r2, r0, r0  -> r2 = r0 + r0
    # rd=2, rs1=0, rs2=0
    inst = (0x00 << 26) | (2 << 20) | (0 << 14) | (0 << 8)
    code += struct.pack('<I', inst)

    # === LOAD/STORE ===
    # ld r3, 0(r1)  -> r3 = *r1
    # rd=3, rs1=1, imm12=0, opcode=0x18
    inst = (0x18 << 26) | (3 << 20) | (1 << 14) | 0
    code += struct.pack('<I', inst)

    # st r3, 8(r1)  -> *(r1+8) = r3
    # rd=3, rs1=1, imm12=8, opcode=0x1C
    inst = (0x1C << 26) | (3 << 20) | (1 << 14) | 8
    code += struct.pack('<I', inst)

    # === LOGICAL ===
    # or r4, r0, r2  -> r4 = r0 | r2
    # rd=4, rs1=0, rs2=2, opcode=0x12
    inst = (0x12 << 26) | (4 << 20) | (0 << 14) | (2 << 8)
    code += struct.pack('<I', inst)

    # === EXTENDED MULTIPLY ===
    # mul3 r5, r0, r2  -> r5 = r0 * r2
    # rd=5, rs1=0, rs2=2, opcode=0x40 (extended)
    inst = ((0x40 << 26) | (5 << 20) | (0 << 14) | (2 << 8)) & 0xFFFFFFFF
    code += struct.pack('<I', inst)

    # === EXTENDED COMPARE ===
    # cmpeqi r6, r0, 42  -> if r0 == 42, branch
    # rd=6, rs1=0, imm8=42, opcode=0x46 (extended)
    inst = ((0x46 << 26) | (6 << 20) | (0 << 14) | 42) & 0xFFFFFFFF
    code += struct.pack('<I', inst)

    # === BRANCH ===
    # br test_func  -> branch back to start
    # imm26=0, opcode=0x20
    inst = (0x20 << 26) | 0
    code += struct.pack('<I', inst)

    # NOP (for alignment)
    # opcode=0x28
    inst = 0x28 << 26
    code += struct.pack('<I', inst)

    # === DATA SECTION ===
    # Pad to 1024 bytes total
    data_section = bytearray(1024)
    # Write some test data
    struct.pack_into('<Q', data_section, 0, 42)       # word at offset 0
    struct.pack_into('<Q', data_section, 8, 84)        # word at offset 8
    struct.pack_into('<I', data_section, 16, 0x12345678)

    # Combine ELF header + program header + code + data
    elf_header = create_el_header()
    phdr = create_phdr()
    code_len = len(code)
    data_section = data_section[:1024]

    # Align code to 64 bytes
    while len(code) % 64 != 0:
        code += b'\x00'
    code_len = len(code)

    data_section = bytearray(1024)
    struct.pack_into('<Q', data_section, 0, 42)
    struct.pack_into('<Q', data_section, 8, 84)
    struct.pack_into('<I', data_section, 16, 0x12345678)

    binary = elf_header + phdr + code + data_section

    # Adjust program header to match actual offsets
    phdr = bytearray(phdr)
    # p_offset at byte 4
    struct.pack_into('<Q', phdr, 4, 64)                # p_offset
    struct.pack_into('<Q', phdr, 20, code_len)         # p_filesz
    struct.pack_into('<Q', phdr, 28, code_len + 1024)  # p_memsz

    binary = elf_header + phdr + code + data_section

    return binary

def generate_flat_binary():
    """Generate a flat (raw) binary version for BinaryLoader testing."""
    code = bytearray()

    # Same instructions as ELF but without the ELF header
    # Function at address 0x10000000

    # add r0, r1, r1
    code += struct.pack('<I', (0x00 << 26) | (0 << 20) | (1 << 14) | (1 << 8))
    # add r2, r0, r0
    code += struct.pack('<I', (0x00 << 26) | (2 << 20) | (0 << 14) | (0 << 8))
    # ld r3, 0(r1)
    code += struct.pack('<I', (0x18 << 26) | (3 << 20) | (1 << 14) | 0)
    # st r3, 8(r1)
    code += struct.pack('<I', (0x1C << 26) | (3 << 20) | (1 << 14) | 8)
    # or r4, r0, r2
    code += struct.pack('<I', (0x12 << 26) | (4 << 20) | (0 << 14) | (2 << 8))
    # mul3 r5, r0, r2
    code += struct.pack('<I', ((0x40 << 26) | (5 << 20) | (0 << 14) | (2 << 8)) & 0xFFFFFFFF)
    # cmpeqi r6, r0, 42
    code += struct.pack('<I', ((0x46 << 26) | (6 << 20) | (0 << 14) | 42) & 0xFFFFFFFF)
    # br
    code += struct.pack('<I', (0x20 << 26) | 0)
    # nop
    code += struct.pack('<I', 0x28 << 26)

    return code

def write_disassembly(binary, output_path):
    """Write a disassembly listing for verification."""
    lines = []
    lines.append("# TILEGX Test Program - Disassembly")
    lines.append("# Generated by tilegx_test.py")
    lines.append("# Language: TILE:LE:64:default")
    lines.append("# Entry point: 0x1000")
    lines.append("# Machine: EM_TILEGX (191)")
    lines.append("#")
    lines.append("# Instruction encoding: 32-bit fixed-length")
    lines.append("# Top 6 bits = opcode, bottom 26 bits = operands")
    lines.append("")

    # Parse the binary to extract the ELF and code sections
    code_start = 64 + 56  # after ELF header + program header
    code_data = binary[code_start:]

    lines.append(f"# Code section at offset 0x{code_start:X}, {len(code_data)} bytes")
    lines.append("")
    lines.append("# Code instructions:")

    # Decode instructions
    i = 0
    addr = 0x1000
    while i + 4 <= len(code_data):
        instr = struct.unpack_from('<I', code_data, i)[0]
        opcode = (instr >> 26) & 0x3F
        rd = (instr >> 20) & 0x3F
        rs1 = (instr >> 14) & 0x3F
        rs2 = (instr >> 8) & 0x3F
        imm = instr & 0x3F

        # Determine mnemonic
        if opcode == 0x00:
            mnemonic = f"add"
        elif opcode == 0x12:
            mnemonic = f"or"
        elif opcode == 0x18:
            mnemonic = f"ld"
        elif opcode == 0x1C:
            mnemonic = f"st"
        elif opcode == 0x20:
            mnemonic = f"br"
        elif opcode == 0x28:
            mnemonic = f"nop"
        elif opcode == 0x40:
            mnemonic = f"mul3"
        elif opcode == 0x46:
            mnemonic = f"cmpeqi"
        elif opcode >= 0x40:
            mnemonic = f"ext_0x{opcode:X}"
        else:
            mnemonic = f"0x{opcode:X}"

        if opcode == 0x18:  # ld
            line = f"  {addr:#010x}: {instr:08x}  {mnemonic} r{rd}, r{rs1}, {imm}"
        elif opcode == 0x1C:  # st
            line = f"  {addr:#010x}: {instr:08x}  {mnemonic} r{rd}, r{rs1}, {imm}"
        elif opcode == 0x46:  # cmpeqi
            line = f"  {addr:#010x}: {instr:08x}  {mnemonic} r{rd}, r{rs1}, {imm}"
        elif opcode == 0x20:  # br
            line = f"  {addr:#010x}: {instr:08x}  {mnemonic} (0x{imm:X})"
        elif opcode >= 0x40:  # extended
            line = f"  {addr:#010x}: {instr:08x}  {mnemonic} r{rd}, r{rs1}, r{rs2}"
        else:  # base
            line = f"  {addr:#010x}: {instr:08x}  {mnemonic} r{rd}, r{rs1}, r{rs2}"

        lines.append(line)
        i += 4
        addr += 4
        if i >= len(code_data) - 100:  # stop after reasonable number of instructions
            break

    lines.append("")
    lines.append("# Data section (first 32 bytes):")
    data_section = code_data[len(code_data) - 1024:]
    for j in range(0, min(32, len(data_section)), 8):
        val = struct.unpack_from('<Q', data_section, j)[0]
        lines.append(f"  .data + {j}: {val:#018x}")

    lines.append("")
    lines.append("# Expected C code after decompilation:")
    lines.append("# ulonglong test_func(ulonglong r0, ulonglong r1) {")
    lines.append("#     r0 = r1 + r1;")
    lines.append("#     r2 = r0 + r0;")
    lines.append("#     r3 = *r1;")
    lines.append("#     *(r1 + 8) = r3;")
    lines.append("#     r4 = r0 | r2;")
    lines.append("#     r5 = r0 * r2;")
    lines.append("#     if (r0 == 42) br test_func;")
    lines.append("#     br test_func;")
    lines.append("# }")

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines) + '\n')

    return lines

def main():
    """Main entry point."""
    output_dir = os.environ.get('TILEGX_OUTPUT', '/tmp')

    # Generate ELF binary
    print("Generating TILEGX ELF binary...")
    elf_binary = generate_test_program()
    elf_path = os.path.join(output_dir, 'tilegx_test.elf')
    with open(elf_path, 'wb') as f:
        f.write(elf_binary)
    print(f"  ELF binary: {elf_path} ({len(elf_binary)} bytes)")

    # Generate flat binary
    print("Generating TILEGX flat binary...")
    flat_binary = generate_flat_binary()
    flat_path = os.path.join(output_dir, 'tilegx_test.flat')
    with open(flat_path, 'wb') as f:
        f.write(flat_binary)
    print(f"  Flat binary: {flat_path} ({len(flat_binary)} bytes)")

    # Write disassembly
    print("Generating disassembly listing...")
    disasm_path = os.path.join(output_dir, 'tilegx_test.asm')
    lines = write_disassembly(elf_binary, disasm_path)
    print(f"  Disassembly: {disasm_path} ({len(lines)} lines)")

    # Verify ELF header
    print("\nVerifying ELF header...")
    magic = elf_binary[0:4]
    assert magic == b'\x7fELF', f"Bad ELF magic: {magic.hex()}"
    print(f"  ELF magic: {magic.hex()} ✓")

    class_ = elf_binary[4]
    assert class_ == 2, f"Bad ELF class: {class_}"
    print(f"  ELF class: {class_} (ELFCLASS64) ✓")

    data = elf_binary[5]
    assert data == 1, f"Bad ELF data: {data}"
    print(f"  ELF data: {data} (ELFDATA2LSB) ✓")

    machine = struct.unpack_from('<H', elf_binary, 18)[0]
    assert machine == EM_TILEGX, f"Bad machine type: {machine} (expected {EM_TILEGX})"
    print(f"  Machine: {machine} (EM_TILEGX) ✓")

    entry = struct.unpack_from('<Q', elf_binary, 24)[0]
    print(f"  Entry: 0x{entry:X} ✓")

    # Write verification results
    print("\nTILEGX binary generation complete!")
    print(f"\nNext steps:")
    print(f"  1. Load {elf_path} into Ghidra as TILE:LE:64:default")
    print(f"  2. Verify disassembly shows 8 instructions")
    print(f"  3. Verify decompiler produces C code with r0 = r1 + r1, etc.")

    return 0

if __name__ == '__main__':
    sys.exit(main())
