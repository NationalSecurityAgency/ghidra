# MIPS Decompiler Enhancement - Implementation Plan

## Executive Summary

This document outlines the implementation plan for enhancing Ghidra's MIPS decompiler to properly handle common compiler optimization patterns including jump tables, inline switch handlers, and indirect function calls.

## Problem Validation

### Real-World Test Case: tx-isp-t31.ko

We have a real MIPS kernel module (`tx-isp-t31.ko`) that exhibits the exact bug described in the PRD:

**Function:** `ispcore_irq_fs_work` at address `0x665f8`

**Current Broken Decompilation (Binary Ninja - same issue as Ghidra):**
```c
if (i u< 7)
    jump((&data_6de20)[i])  // ← BROKEN: Shows raw jump instead of switch
```

**Expected Decompilation:**
```c
switch(i) {
    case 0: ioctl_cmd = 0x20016; break;
    case 1: ioctl_cmd = 0x20008; break;
    case 2: ioctl_cmd = 0x20009; break;
    case 3: ioctl_cmd = 0x20005; break;
    case 4: ioctl_cmd = 0x20006; break;
    case 5: continue;
    case 6: ioctl_cmd = 0x20007; break;
}
```

This confirms:
- ✅ Jump table at `data_6de20` is not recognized
- ✅ Decompiler gives up and shows raw `jump()` 
- ✅ Control flow analysis is incomplete
- ✅ Both Binary Ninja and Ghidra have the same limitation

## Implementation Phases

### Phase 1: Foundation & Setup ✓ IN PROGRESS
- [x] Create test binary directory structure
- [/] Review existing MIPS analyzer infrastructure
- [ ] Study existing switch table implementations

### Phase 2: Core Analyzer Enhancements (FR1)
**Goal:** Detect and analyze MIPS switch tables

#### FR1.1: Create MipsSwitchTableAnalyzer.java
**Location:** `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/`

**Key Algorithm:**
```java
public SwitchTable detectSwitchTable(Instruction jumpInst) {
    // 1. Detect jr $reg patterns
    if (!isJumpRegister(jumpInst)) return null;
    
    // 2. Backtrack to find table load (e.g., lw $reg, offset($base))
    Instruction loadInst = findTableLoad(jumpInst);
    
    // 3. Find table base calculation (lui/addiu pairs, $gp-relative)
    Address tableBase = findTableBase(loadInst);
    
    // 4. Find bounds check to determine table size
    int tableSize = findTableBounds(jumpInst);
    
    // 5. Extract jump targets from table
    List<Address> targets = extractTargets(tableBase, tableSize);
    
    // 6. Check for inline handlers (code in "data" regions)
    for (Address target : targets) {
        if (!isDisassembled(target)) {
            disassembleInlineHandler(target);
        }
    }
    
    return new SwitchTable(jumpInst.getAddress(), targets);
}
```

#### FR1.2-1.3: Pattern Recognition
Support multiple compiler patterns:
- **GCC -O2/-O3:** Jump tables with bounds checking
- **LLVM:** Different table layout and indexing
- **PIC code:** $gp-relative addressing
- **Non-PIC:** Absolute addresses

#### FR1.4: MipsInlineCodeAnalyzer.java
Detect valid MIPS instructions in data regions following jumps

#### FR1.5: Enhance MipsAddressAnalyzer.java
Integrate new switch table detection with existing constant propagation

### Phase 3: Indirect Call Resolution (FR3)
**Goal:** Resolve function pointers and vtables

- Create MipsFunctionPointerAnalyzer.java
- Track jalr call sites
- Detect operation structures and vtables
- Link indirect calls to targets

### Phase 4: Data Flow Improvements (FR4)
**Goal:** Better constant propagation for table addresses

- Track register values across basic blocks
- Support MIPS hi/lo register pairs (lui/addiu)
- Handle $gp-relative addressing
- Multi-level pointer indirection

### Phase 5: Decompiler Integration (FR2)
**Goal:** Make decompiler use switch table information

#### Java Side:
- Modify `DecompInterface.java` to pass switch hints
- Update PCode generation for MIPS

#### C++ Side:
- Modify `flow.cc` for control flow
- Modify `jumptable.cc` for jump table recovery
- Consider creating `mips_switch.cc` for MIPS-specific logic

### Phase 6: Language Specification Updates
- Update `mips.cspec` for compiler patterns
- Update `mips.pspec` to register new analyzers

### Phase 7: Testing & Validation
**Test Binaries:**
- tx-isp-t31.ko (real-world kernel module) ✓
- gcc_o0_switch.elf
- gcc_o3_switch.elf
- llvm_switch.elf
- pic_switch.elf
- inline_handlers.elf
- vtable_example.elf
- callback_struct.elf

**Success Metrics:**
- Detection Rate: >95%
- False Positive Rate: <0.1%
- Performance Impact: <10%
- Code Coverage: >90%

### Phase 8: Documentation & Code Quality
- Comprehensive JavaDoc
- Developer guide
- User documentation
- Code cleanup per Ghidra standards

### Phase 9: Upstream Contribution
- Open GitHub issue
- Engage with maintainers
- Prepare pull requests
- Submit with examples

## Key Files to Modify

### New Files:
```
Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/
├── MipsSwitchTableAnalyzer.java        [NEW]
├── MipsInlineCodeAnalyzer.java         [NEW]
└── MipsFunctionPointerAnalyzer.java    [NEW]
```

### Modified Files:
```
Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/
└── MipsAddressAnalyzer.java            [MODIFY]

Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/
└── DecompInterface.java                [MODIFY]

Ghidra/Features/Decompiler/src/decompile/cpp/
├── flow.cc                             [MODIFY]
├── jumptable.cc                        [MODIFY]
└── mips_switch.cc                      [NEW - optional]

Ghidra/Processors/MIPS/data/languages/
├── mips.cspec                          [MODIFY]
└── mips.pspec                          [MODIFY]
```

## Next Steps

1. ✅ Create test binary directory
2. 🔄 Review MipsAddressAnalyzer.java to understand existing infrastructure
3. ⏳ Study JvmSwitchAnalyzer.java and AddressTable.java for patterns
4. ⏳ Begin implementing MipsSwitchTableAnalyzer.java

## References

- Product Requirements Document (PRD)
- Test binary: `/home/matteius/ghidra/tx-isp-t31.ko`
- Binary Ninja analysis confirms same bug exists
- Function to fix: `ispcore_irq_fs_work` @ 0x665f8

