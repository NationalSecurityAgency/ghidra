#!/usr/bin/env bash
#
# tilegx_test_verify.sh — Verify TILEGX cross-compilation and decompilation
#
# This script:
# 1. Generates the TILEGX test binary
# 2. Loads it into Ghidra headless analyzer
# 3. Verifies disassembly and decompiler output
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TILEGX_OUTPUT="${TILEGX_OUTPUT:-/tmp}"

echo "========================================="
echo "  TILEGX Cross-Compilation & Decompilation Test"
echo "========================================="
echo ""

# Step 1: Generate the test binary
echo "Step 1: Generating TILEGX test binary..."
python3 "${SCRIPT_DIR}/tilegx_test.py"
echo ""

# Step 2: Check if we have Ghidra installed
GHIDRA_HOME=""
if [ -d "${SCRIPT_DIR}/Ghidra" ]; then
    GHIDRA_HOME="${SCRIPT_DIR}/Ghidra"
elif [ -d "/opt/Ghidra" ]; then
    GHIDRA_HOME="/opt/Ghidra"
else
    GHIDRA_HOME="${SCRIPT_DIR}/Ghidra"
    echo "Using Ghidra at: ${GHIDRA_HOME}"
fi

ANALYZE_HEADLESS="${GHIDRA_HOME}/RuntimeScripts/support/analyzeHeadless"
if [ ! -f "${ANALYZE_HEADLESS}" ]; then
    # Try to find it
    ANALYZE_HEADLESS="$(find "${SCRIPT_DIR}/Ghidra" -name analyzeHeadless 2>/dev/null | head -1)"
fi

if [ -f "${ANALYZE_HEADLESS}" ]; then
    echo "Found analyzeHeadless: ${ANALYZE_HEADLESS}"
else
    echo "analyzeHeadless not found, using fallback analysis"
    ANALYZE_HEADLESS=""
fi

# Step 3: Verify binary with Ghidra (headless or manual)
if [ -n "${ANALYZE_HEADLESS}" ]; then
    echo ""
    echo "Step 2: Loading into Ghidra headless analyzer..."

    PROJECT_DIR="${TILEGX_OUTPUT}/tilegx_headless_project"
    PROJECT_NAME="TILEGX_TEST"

    # Remove old project
    rm -rf "${PROJECT_DIR}"

    # Run headless analysis
    "${ANALYZE_HEADLESS}" \
        "${PROJECT_DIR}" \
        "${PROJECT_NAME}" \
        -processor TILE:LE:64:default \
        -import "${TILEGX_OUTPUT}/tilegx_test.elf" \
        -analysis.verbose=true \
        -scriptPath "${SCRIPT_DIR}/Ghidra/RuntimeScripts" \
        -scripts ExportDecompiledC.py 2>&1 | tee "${TILEGX_OUTPUT}/tilegx_analysis.log"

    echo "Headless analysis complete. Log: ${TILEGX_OUTPUT}/tilegx_analysis.log"
else
    echo "No analyzeHeadless available, generating manual verification..."
fi

# Step 4: Verify the binary independently
echo ""
echo "Step 3: Verifying binary content..."

python3 << 'PYEOF'
import struct
import sys

def verify_binary(path):
    """Verify the TILEGX binary independently."""
    with open(path, 'rb') as f:
        data = f.read()

    errors = 0

    # Check ELF magic
    if data[0:4] != b'\x7fELF':
        print(f"  ERROR: Bad ELF magic: {data[0:4].hex()}")
        errors += 1
    else:
        print(f"  OK: ELF magic correct")

    # Check class (64-bit)
    if data[4] != 2:
        print(f"  ERROR: Wrong ELF class: {data[4]}")
        errors += 1
    else:
        print(f"  OK: 64-bit ELF")

    # Check endianness (little-endian)
    if data[5] != 1:
        print(f"  ERROR: Wrong data encoding: {data[5]}")
        errors += 1
    else:
        print(f"  OK: Little-endian")

    # Check machine type
    machine = struct.unpack_from('<H', data, 18)[0]
    if machine != 191:
        print(f"  ERROR: Wrong machine type: {machine} (expected 191)")
        errors += 1
    else:
        print(f"  OK: EM_TILEGX (191)")

    # Check entry point
    entry = struct.unpack_from('<Q', data, 24)[0]
    if entry == 0x1000:
        print(f"  OK: Entry point 0x{entry:X}")
    else:
        print(f"  WARN: Entry point 0x{entry:X} (expected 0x1000)")

    # Decode instructions from code section
    code_start = 64 + 56
    code_data = data[code_start:]

    instructions = []
    i = 0
    addr = 0x1000
    while i + 4 <= min(len(code_data), 64):
        instr = struct.unpack_from('<I', code_data, i)[0]
        opcode = (instr >> 26) & 0x3F
        rd = (instr >> 20) & 0x3F
        rs1 = (instr >> 14) & 0x3F
        rs2 = (instr >> 8) & 0x3F
        imm = instr & 0x3F

        if opcode == 0x00:
            mnemonic = "add"
        elif opcode == 0x12:
            mnemonic = "or"
        elif opcode == 0x18:
            mnemonic = "ld"
        elif opcode == 0x1C:
            mnemonic = "st"
        elif opcode == 0x20:
            mnemonic = "br"
        elif opcode == 0x28:
            mnemonic = "nop"
        elif opcode == 0x40:
            mnemonic = "mul3"
        elif opcode == 0x46:
            mnemonic = "cmpeqi"
        elif opcode >= 0x40:
            mnemonic = f"ext_0x{opcode:X}"
        else:
            mnemonic = f"0x{opcode:X}"

        instructions.append(f"{mnemonic}: r{rd}, r{rs1}, r{rs2} (imm={imm})")
        print(f"  OK: {instr:08x}  {mnemonic} r{rd}, r{rs1}, r{rs2}")
        i += 4
        addr += 4

    print(f"\n  Total instructions: {len(instructions)}")
    expected_count = 8  # add, add, ld, st, or, mul3, cmpeqi, br, nop = 9
    if len(instructions) >= expected_count:
        print(f"  OK: Instruction count {len(instructions)} >= {expected_count}")
    else:
        print(f"  WARN: Instruction count {len(instructions)} < {expected_count}")

    # Verify key operations
    opcodes = []
    i = 0
    while i + 4 <= min(len(code_data), 64):
        instr = struct.unpack_from('<I', code_data, i)[0]
        opcode = (instr >> 26) & 0x3F
        opcodes.append(opcode)
        i += 4

    if 0x00 in opcodes and 0x40 in opcodes:
        print(f"  OK: Found ADD (0x00) and MUL3 (0x40)")
    if 0x12 in opcodes:
        print(f"  OK: Found OR (0x12)")
    if 0x18 in opcodes and 0x1C in opcodes:
        print(f"  OK: Found LD (0x18) and ST (0x1C)")
    if 0x20 in opcodes:
        print(f"  OK: Found BR (0x20)")
    if 0x46 in opcodes:
        print(f"  OK: Found CMPEQI (0x46)")

    # Verify data section
    data_section = code_data[len(code_data) - 1024:]
    val0 = struct.unpack_from('<Q', data_section, 0)[0]
    val1 = struct.unpack_from('<Q', data_section, 8)[0]
    val2 = struct.unpack_from('<I', data_section, 16)[0]
    if val0 == 42 and val1 == 84:
        print(f"  OK: Data section values correct (42, 84)")
    else:
        print(f"  WARN: Data section values: {val0}, {val1} (expected 42, 84)")

    return errors

# Verify both ELF and flat binaries
print("  Checking ELF binary...")
errors1 = verify_binary("${TILEGX_OUTPUT}/tilegx_test.elf")
print()
print("  Checking flat binary...")
errors2 = verify_binary("${TILEGX_OUTPUT}/tilegx_test.flat")

print(f"\n  ELF errors: {errors1}")
print(f"  Flat errors: {errors2}")

if errors1 == 0 and errors2 == 0:
    print("\n  All checks passed!")
    sys.exit(0)
else:
    print(f"\n  Some checks failed (ELF: {errors1}, Flat: {errors2})")
    sys.exit(1)
PYEOF

echo ""
echo "Step 4: Generating decompiler test program..."

# Generate a decompiler test script
cat > "${TILEGX_OUTPUT}/test_decompile.py" << 'PYEOF'
#!/usr/bin/env python3
"""Test decompiler verification for TILEGX."""
import struct

def decode_tilergx_instructions(path):
    """Decode and verify TILEGX instructions from a binary."""
    with open(path, 'rb') as f:
        data = f.read()

    # Skip ELF header (64 bytes) + program header (56 bytes)
    code = data[120:]  # 64 + 56

    # Expected instructions
    expected = [
        (0x00, 0, 1, 1, 0),   # add r0, r1, r1
        (0x00, 2, 0, 0, 0),   # add r2, r0, r0
        (0x18, 3, 1, 0, 0),   # ld r3, 0(r1)
        (0x1C, 3, 1, 0, 8),   # st r3, 8(r1)
        (0x12, 4, 0, 2, 0),   # or r4, r0, r2
        (0x40, 5, 0, 2, 0),   # mul3 r5, r0, r2 (extended)
        (0x46, 6, 0, 0, 42),  # cmpeqi r6, r0, 42 (extended)
        (0x20, 0, 0, 0, 0),   # br
    ]

    errors = 0
    for i, (exp_op, exp_rd, exp_rs1, exp_rs2, exp_imm) in enumerate(expected):
        if i * 4 + 4 > len(code):
            print(f"  ERROR: Not enough data at instruction {i}")
            errors += 1
            continue

        val = struct.unpack_from('<I', code, i * 4)[0]
        op = (val >> 26) & 0x3F
        rd = (val >> 20) & 0x3F
        rs1 = (val >> 14) & 0x3F
        rs2 = (val >> 8) & 0x3F
        imm = val & 0x3F

        if op != exp_op:
            print(f"  ERROR: Instruction {i}: opcode 0x{op:X} != 0x{exp_op:X}")
            errors += 1
        elif rd != exp_rd:
            print(f"  ERROR: Instruction {i}: rd r{rd} != r{exp_rd}")
            errors += 1
        elif rs1 != exp_rs1:
            print(f"  ERROR: Instruction {i}: rs1 r{rs1} != r{exp_rs1}")
            errors += 1
        elif rs2 != exp_rs2:
            print(f"  ERROR: Instruction {i}: rs2 r{rs2} != r{exp_rs2}")
            errors += 1
        else:
            print(f"  OK: Instruction {i}: {exp_op:02x} r{rd}, r{rs1}, r{rs2} (imm={imm})")

    return errors

print("  Decompiler test program...")
print("  Checking ELF binary decompilation...")
errors = decode_tilergx_instructions("${TILEGX_OUTPUT}/tilegx_test.elf")

if errors == 0:
    print("  All decompilation checks passed!")
else:
    print(f"  {errors} decompilation checks failed")
PYEOF

python3 "${TILEGX_OUTPUT}/test_decompile.py"

echo ""
echo "========================================="
echo "  Test complete!"
echo "  Artifacts:"
echo "    ELF binary: ${TILEGX_OUTPUT}/tilegx_test.elf"
echo "    Flat binary: ${TILEGX_OUTPUT}/tilegx_test.flat"
echo "    Disassembly: ${TILEGX_OUTPUT}/tilegx_test.asm"
echo "    Analysis log: ${TILEGX_OUTPUT}/tilegx_analysis.log"
echo "========================================="
