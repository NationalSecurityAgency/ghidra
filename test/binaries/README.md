# MIPS Test Binaries

This directory contains test binaries for validating the enhanced MIPS decompiler control flow analysis.

## Test Binary Corpus

### Switch Table Tests
- **gcc_o0_switch.elf** - Unoptimized GCC switch statement (baseline)
- **gcc_o3_switch.elf** - Optimized GCC switch with jump tables
- **llvm_switch.elf** - LLVM compiled switch statements
- **pic_switch.elf** - Position-independent code with switch tables

### Advanced Pattern Tests
- **inline_handlers.elf** - Inline case handlers embedded after jump instructions
- **vtable_example.elf** - Virtual function tables (C++ vtables)
- **callback_struct.elf** - Function pointer structures and callback patterns

## Building Test Binaries

To create these test binaries, you'll need a MIPS cross-compiler toolchain:

```bash
# Install MIPS toolchain (Debian/Ubuntu)
sudo apt-get install gcc-mips-linux-gnu g++-mips-linux-gnu

# Or use buildroot/crosstool-ng for embedded targets
```

### Example: Building a switch test

```c
// test_switch.c
int test_switch(int x) {
    switch(x) {
        case 0: return 0x20016;
        case 1: return 0x20008;
        case 2: return 0x20009;
        case 3: return 0x20005;
        case 4: return 0x20006;
        case 6: return 0x20007;
        default: return 0;
    }
}
```

```bash
# Unoptimized
mips-linux-gnu-gcc -O0 -static test_switch.c -o gcc_o0_switch.elf

# Optimized (creates jump tables)
mips-linux-gnu-gcc -O3 -static test_switch.c -o gcc_o3_switch.elf

# Position-independent
mips-linux-gnu-gcc -O3 -fPIC -static test_switch.c -o pic_switch.elf
```

## Test Criteria

Each binary should be tested for:
1. **Detection Rate**: >95% of switch tables correctly identified
2. **False Positive Rate**: <0.1%
3. **Decompiler Output**: Proper switch statement reconstruction
4. **Call Graph**: Complete for indirect calls
5. **Performance**: <10% increase in analysis time

## Real-World Test Sources

For comprehensive testing, also test against:
- Linux kernel modules (MIPS architecture)
- OpenWrt firmware images
- MIPS-based router firmware
- PlayStation 1/2 executables
- Embedded device firmware

