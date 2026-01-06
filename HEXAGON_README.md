# Hexagon Processor Architecture Documentation

This directory contains comprehensive documentation of the Qualcomm Hexagon processor architecture, based on examination of the LLVM Project's Hexagon target implementation.

## Overview

The Hexagon processor is a VLIW (Very Long Instruction Word) DSP architecture developed by Qualcomm, commonly used in mobile SoCs and embedded applications. This documentation was created by examining the LLVM source code in `llvm/lib/Target/Hexagon/`.

## Documentation Files

### 📋 [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md)
**Start here!** Provides a high-level overview of all findings, with direct answers to key questions about new-value register restrictions.

**Contents:**
- Quick answers to specific questions
- Summary of key findings
- Overview of all three detailed documents
- Implementation considerations for Ghidra
- Reference information

---

### 📘 [HexagonArchitectureAnalysis.md](HexagonArchitectureAnalysis.md)
Comprehensive architectural analysis (15KB)

**Contents:**
1. Overview and key characteristics
2. Processor versions (V5 through V81)
3. Register architecture
   - 32 general-purpose registers (R0-R31)
   - 16 double registers (D0-D15)
   - 4 predicate registers (P0-P3)
   - Vector registers (HVX)
   - Control and system registers
4. Instruction format and encoding
5. Instruction types (57+ types)
6. Addressing modes
7. HVX (Hexagon Vector eXtensions)
8. Sub-instructions and duplex encoding
9. Target flags and relocations
10. Implementation considerations for Ghidra

**Use this for:** Understanding the overall architecture and register organization.

---

### 📗 [HexagonImplementationGuide.md](HexagonImplementationGuide.md)
Practical implementation guide (16KB)

**Contents:**
1. Register encoding examples from LLVM
2. Instruction format examples with bit layouts
3. Packet structure and parse bits
4. Instruction type categories
5. Predication examples
6. New-value mechanism examples
7. Constant extenders
8. Hardware loops
9. Duplex instructions
10. Compound instructions
11. TSFlags bit layout
12. Implementation checklist for Ghidra
13. Example SLEIGH patterns
14. Testing strategy

**Use this for:** Practical coding examples and implementation patterns.

---

### 📕 [HexagonNewValueRestrictions.md](HexagonNewValueRestrictions.md)
In-depth new-value restrictions analysis (18KB)

**Contents:**
1. Overview of new-value mechanism
2. New-value categories (stores, jumps, predicates)
3. **Scalar register restrictions** (detailed)
   - What cannot produce/consume new values
   - Double register limitations
   - Post-increment restrictions
   - WAR hazard prevention
   - New-value store constraints
4. **Vector register restrictions** (detailed)
   - Vector double register issues
   - Vector store with predicate restrictions
   - Timing and pipeline considerations
5. Predicate register new-value rules
6. Implicit dependency restrictions
7. Inline assembly restrictions
8. Hardware loop restrictions
9. Resource availability checks
10. **Summary tables** of all restrictions
11. **20+ practical examples** (valid and invalid patterns)
12. Implementation guidelines for Ghidra
13. References to Hexagon PRM sections

**Use this for:** Understanding new-value forwarding restrictions in detail.

---

### 📙 [HexagonConditionalNewValue.md](HexagonConditionalNewValue.md)
Conditional execution and new-value interactions (19KB)

**Contents:**
1. Executive summary answering key questions
2. Architectural background on predicated execution
3. **Conditional instructions and new-value stores**
   - Core rules from Arch Spec 5.4.2.3
   - Predicate matching requirements
   - Valid and invalid examples
4. **Opposite predicates in same packet**
   - Complement predicate rules
   - The critical corner case
   - Transitive dependency limitations
5. **Accessing new values with conditional instructions**
   - Hardware handling mechanisms
   - Execution scenarios
   - Why mismatched predicates fail
6. Summary of all rules with quick reference table
7. **Practical examples** with detailed explanations
8. Implementation guidance for Ghidra

**Use this for:** Understanding how conditional execution interacts with new-value forwarding, especially for complex predicated scenarios.

---

## Quick Reference

### Key Questions Answered

**Q: Can scalar double registers use new-values?**  
**A: NO.** 64-bit double registers (D0-D15) cannot produce or consume new values. (See HexagonNewValueRestrictions.md §3.1)

**Q: Can vector registers use new-values?**  
**A: YES, with restrictions.** Single vectors can use new-values, BUT vector stores cannot use `.new` predicates. (See HexagonNewValueRestrictions.md §4)

**Q: Can new-value stores coexist with other stores?**  
**A: NO.** Only one store per packet when using new-value stores. (See HexagonNewValueRestrictions.md §3.4)

**Q: When a conditional instruction updates a scalar register, does the new value store get updated?**  
**A: YES, but only if both instructions have matching predicates** (same register, sense, and .new/.old form). (See HexagonConditionalNewValue.md §2)

**Q: Can two instructions with opposite conditions update the same register in one packet?**  
**A: YES, if they use complement predicates** (same register, opposite sense, same .new/.old form), but they cannot both feed new-value operations. (See HexagonConditionalNewValue.md §3)

**Q: What are the main new-value restrictions?**  
**A: See summary table in HexagonNewValueRestrictions.md §10**

### Architecture Quick Facts

| Property | Value |
|----------|-------|
| Architecture | VLIW DSP |
| Word Size | 32-bit |
| Endianness | Little-endian |
| GPRs | 32 (R0-R31) |
| Predicates | 4 (P0-P3) |
| Versions | V5, V55, V60-V69, V71, V73, V75, V79, V81 |
| ELF Machine | EM_HEXAGON (164) |
| Instruction Size | 32-bit (base) |
| Packet Size | Up to 4 instructions |

## Document Organization

```
Hexagon Documentation/
│
├── EXECUTIVE_SUMMARY.md          ← Start here
│   ├── Quick answers to questions
│   ├── Overview of all documents
│   └── Key findings summary
│
├── HexagonArchitectureAnalysis.md  ← Architecture reference
│   ├── Processor versions
│   ├── Register architecture
│   ├── Instruction formats
│   └── HVX extensions
│
├── HexagonImplementationGuide.md   ← Implementation patterns
│   ├── Code examples
│   ├── Encoding patterns
│   ├── SLEIGH templates
│   └── Implementation checklist
│
├── HexagonNewValueRestrictions.md  ← New-value deep dive
│   ├── Scalar restrictions
│   ├── Vector restrictions
│   ├── Practical examples
│   └── Guidelines
│
└── HexagonConditionalNewValue.md   ← Conditional execution
    ├── Predicated instruction rules
    ├── Complement predicates
    ├── Matching requirements
    └── Corner cases
```

## How to Use This Documentation

### For Understanding the Architecture:
1. Read **EXECUTIVE_SUMMARY.md** for overview
2. Read **HexagonArchitectureAnalysis.md** for details
3. Refer to **HexagonImplementationGuide.md** for examples

### For Implementing Ghidra Support:
1. Read **EXECUTIVE_SUMMARY.md** for scope
2. Study **HexagonImplementationGuide.md** thoroughly
3. Use **HexagonArchitectureAnalysis.md** as reference
4. Consult **HexagonNewValueRestrictions.md** for validation rules

### For Analyzing Hexagon Binaries:
1. Review **HexagonArchitectureAnalysis.md** sections 3-6
2. Study packet structure in **HexagonImplementationGuide.md** §3.2
3. Reference new-value patterns in **HexagonNewValueRestrictions.md** §11

### For Understanding New-Value Mechanism:
1. Read **HexagonNewValueRestrictions.md** sections 1-2
2. Study restrictions in sections 3-4
3. For conditional cases, read **HexagonConditionalNewValue.md**
4. Review examples in both documents
5. Check summary tables

## Source Information

### Primary Source:
- **LLVM Project**: https://github.com/llvm/llvm-project
- **Path**: `llvm/lib/Target/Hexagon/`
- **Date Examined**: January 6, 2026

### Key Files Examined:
- `Hexagon.td` - Target definition
- `HexagonRegisterInfo.td` - Register definitions  
- `HexagonInstrFormats.td` - Instruction formats
- `HexagonDepArch.td` - Architecture versions
- `HexagonDepITypes.td` - Instruction types
- `HexagonBaseInfo.h` - Constants and base info
- `HexagonVLIWPacketizer.cpp` - Packetization rules
- `HexagonNewValueJump.cpp` - New-value jump optimization
- `HexagonInstrInfo.cpp` - Instruction information
- `HexagonInstrInfo.h` - Instruction query interface

### Additional Resources Needed:
For a complete implementation, official Qualcomm documentation is recommended:
- Qualcomm Hexagon Programmer's Reference Manual (PRM)
- Hexagon V6x ISA Specification
- Hexagon Application Binary Interface (ABI)

## Current Status in Ghidra

As of the examination date:
- ✅ Hexagon ELF constant defined (EM_HEXAGON = 164)
- ✅ LLDB debugger entries present (empty)
- ❌ No Hexagon processor module exists
- ❌ No SLEIGH specification

## Implementation Effort Estimate

Implementing full Hexagon support in Ghidra would require:
- **Complexity**: High (VLIW architecture with complex packet semantics)
- **Estimated Effort**: Several person-months
- **Prerequisites**: 
  - Official Qualcomm documentation
  - VLIW architecture expertise
  - SLEIGH specification experience
  - Access to test binaries

## Restrictions Summary

### Scalar Registers (R0-R31)
- ❌ Double registers (D0-D15) cannot use new-values
- ❌ Predicated instructions cannot produce new-values
- ❌ Only one store per packet with new-value stores
- ❌ Floating-point operations cannot use new-values

### Vector Registers (HVX)
- ❌ Vector stores cannot use `.new` predicates (critical!)
- ❌ Vector double registers problematic
- ⚠️ Different timing model, may cause stalls

### General
- ❌ Inline assembly cannot produce new-values
- ❌ Solo instructions cannot participate
- ❌ WAR hazards must be prevented

See **HexagonNewValueRestrictions.md** for complete details and examples.

## Contributing

This documentation is based on examination of open-source LLVM code. If you have:
- Official Qualcomm documentation
- Corrections or clarifications
- Additional insights
- Real-world Hexagon binaries for testing

Please consider contributing to improve the accuracy and completeness of this documentation.

## License

This documentation is provided for educational and research purposes. The Hexagon architecture is a trademark of Qualcomm. The LLVM source code examined is licensed under the Apache License v2.0 with LLVM Exceptions.

---

**Documentation Version**: 1.0  
**Date**: January 6, 2026  
**Total Size**: ~50KB across 4 documents  
**Based On**: LLVM Project commit (latest as of examination date)
