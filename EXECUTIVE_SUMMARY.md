# Executive Summary: Hexagon Processor Examination

## Project Overview

This analysis examines the Hexagon processor architecture as implemented in the LLVM project (llvm/lib/Target/Hexagon) to document its characteristics, particularly focusing on the new-value register mechanism and its restrictions for both scalar and vector registers.

---

## Key Questions Addressed

### Q: What are the restrictions for new-value registers in Hexagon?

The Hexagon architecture's new-value mechanism has distinct restrictions for scalar and vector registers:

#### Scalar Register (R0-R31) Restrictions

**CANNOT produce new values:**
- ❌ **64-bit double registers (D0-D15)** - Architectural limitation (PRM 5.4.2.2)
- ❌ **Predicated instructions** - Cannot be producers
- ❌ **Floating-point operations** - Different timing characteristics
- ❌ **Solo instructions** - Must be in own packet
- ❌ **Inline assembly** - Unknown timing/side effects
- ❌ **Implicit definitions** - Compiler artifacts

**Additional constraints:**
- ❌ **Post-increment base registers** cannot be the new-value source in stores
- ❌ **Only ONE store per packet** when using new-value stores (PRM 3.4.4.2, 5.4.2.3)
- ❌ **No stores/calls** in dependency path for new-value jumps
- ❌ **WAR hazards** must be avoided when reordering for new-value

#### Vector Register (HVX) Restrictions

**Critical limitation:**
- ❌ **Vector stores CANNOT use `.new` predicates** - Fundamental architectural restriction
  ```assembly
  # INVALID:
  {
    p0 = vcmp.gt(v1, v2)
    if (p0.new) vmem(r0) = v3.new   # ERROR
  }
  ```

**Other restrictions:**
- ❌ **Vector double registers (HvxWR)** - Problematic, often disabled via `-disable-vecdbl-nv-stores`
- ⚠️ **Pipeline stalls** - Vector operations have different timing, may stall
- ⚠️ **Forward scheduling required** - Vectors usable in next packet with special handling

**CAN do:**
- ✓ Single vector registers can produce new values
- ✓ Vector new-value stores (without .new predicates)
- ✓ Vector ALU forwarding (with EnableALUForwarding)

---

## Documentation Deliverables

### 1. HexagonArchitectureAnalysis.md (15KB)
Comprehensive architectural analysis covering:
- Processor versions (V5 through V81)
- Register architecture (32 GPRs, predicates, vectors, control/system regs)
- Instruction format (ICLASS, packet structure, 57+ instruction types)
- HVX vector extensions
- Addressing modes and memory access
- TSFlags bit layout (64-bit instruction properties)
- Implementation requirements for Ghidra

### 2. HexagonImplementationGuide.md (16KB)
Practical implementation guide with:
- Register encoding patterns from LLVM TableGen
- Instruction format examples with bit layouts
- Packet structure and parse bits
- Predication mechanism examples
- New-value forwarding examples
- Constant extenders and duplex instructions
- Hardware loop support
- SLEIGH pattern templates
- Implementation checklist for Ghidra

### 3. HexagonNewValueRestrictions.md (18KB)
In-depth analysis of new-value restrictions including:
- Detailed scalar register restrictions with code examples
- Vector register restrictions and timing issues
- Predicate register special cases
- WAR hazard prevention
- Post-increment register conflicts
- Resource availability constraints
- Hardware loop restrictions
- 20+ practical examples of valid/invalid patterns
- Implementation guidelines for Ghidra

---

## Key Findings

### 1. Architecture Complexity

Hexagon is a sophisticated VLIW DSP architecture with:
- **Packet-based execution** - Multiple instructions execute in parallel
- **Complex instruction encoding** - 16 instruction classes (ICLASS)
- **Rich instruction set** - 57+ instruction types
- **Extensive versioning** - 14 major versions (V5-V81)
- **Vector extensions** - HVX with 64B/128B vectors

### 2. New-Value Mechanism

The new-value forwarding mechanism is a critical performance feature:

**Purpose:** Allow values produced in a packet to be consumed in the same packet without register file write-back

**Benefits:**
- Reduced latency
- Better resource utilization
- Enables complex single-cycle operations

**Challenges:**
- Complex validation rules
- Different restrictions for scalar vs. vector
- Timing dependencies
- Resource conflicts

### 3. Most Important Restrictions

#### For Scalar Registers:
1. **Double registers cannot produce new values** - Fundamental limitation
2. **Only one store per packet with NV stores** - Architectural constraint
3. **No predicated producers** - Timing restriction
4. **WAR hazard prevention required** - Correctness requirement

#### For Vector Registers:
1. **Vector stores cannot use .new predicates** - Most critical restriction
2. **Vector double registers problematic** - May be disabled
3. **Different timing model** - Pipeline stalls possible
4. **Forward scheduling needed** - Complexity in optimization

### 4. Architectural Versions

The evolution shows incremental feature additions:
- **V5/V55** - Base architecture
- **V60** - Introduces HVX (vector extensions)
- **V62-V69** - Progressive HVX enhancements
- **V71-V81** - Latest features including advanced HVX

Each version maintains backward compatibility while adding new capabilities.

---

## Implementation Considerations for Ghidra

### Current State in Ghidra:
- ✓ ELF recognition (EM_HEXAGON = 164)
- ✓ LLDB debugger entries (but empty - no language defined)
- ❌ No Hexagon processor module exists

### Required for Implementation:

1. **SLEIGH Specification** (.slaspec, .sinc files)
   - Register space definitions
   - Instruction token formats
   - Packet boundary detection
   - New-value semantics
   - Predication handling
   - 57+ instruction type constructors

2. **Processor Module Structure**
   - Module.manifest
   - build.gradle
   - Language definitions (.ldefs)
   - Processor specification (.pspec)
   - Calling conventions (.cspec)
   - DWARF mappings (.dwarf)

3. **Key Challenges**
   - VLIW packet handling
   - New-value forwarding representation
   - Complex instruction encoding
   - Multiple architecture versions
   - HVX vector instruction set
   - Hardware loop semantics

### Effort Estimate:
Implementing Hexagon support would be a **substantial undertaking** requiring:
- Deep understanding of VLIW architectures
- Access to official Qualcomm documentation
- Extensive testing with real binaries
- Several person-months of development

---

## Answers to Specific Questions

### Q: Can scalar double registers use new-values?
**A: NO.** Double registers (D0-D15, which are 64-bit pairs like r1:r0) **cannot** produce or consume new values. This is an architectural limitation documented in the Hexagon Programmer's Reference Manual section 5.4.2.2.

### Q: Can vector registers use new-values?
**A: YES, with major restrictions.** Single vector registers can use new-values, BUT:
- Vector stores **cannot** use `.new` predicates (fundamental limitation)
- Vector double registers (HvxWR) are problematic/disabled
- Different timing model may cause pipeline stalls
- Requires special forward scheduling

### Q: What about predicates with new-values?
**A: Depends on context.**
- Scalar operations with `.new` predicates: ✓ **ALLOWED**
- Vector stores with `.new` predicates: ❌ **PROHIBITED**
- Predicate registers themselves can be `.new`: ✓ **ALLOWED**

### Q: Can new-value stores coexist with other stores?
**A: NO.** When a packet contains a new-value store, it **cannot** contain any other stores. This is specified in PRM sections 3.4.4.2 and 5.4.2.3. The architectural reason is that new-value stores use execution slot 0 (class NV), and dual stores require standard store slots.

### Q: What prevents a post-increment register from being a new-value?
**A: Correctness.** If the base address register of a store is also the value being stored as a new-value, it creates a circular dependency. Example of prohibited pattern:
```assembly
{
  r1 = add(r1, #4)      # Modifies r1
  memw(r1) = r1.new     # ERROR: r1 is both base and new-value
}
```

---

## References

### Primary Source:
- **LLVM Project**: https://github.com/llvm/llvm-project
- **Path**: llvm/lib/Target/Hexagon/

### Key Files Examined:
- `Hexagon.td` - Target definition
- `HexagonRegisterInfo.td` - Register definitions
- `HexagonInstrFormats.td` - Instruction formats
- `HexagonDepArch.td` - Architecture versions
- `HexagonDepITypes.td` - Instruction types
- `HexagonBaseInfo.h` - Constants and enumerations
- `HexagonVLIWPacketizer.cpp` - Packetization rules
- `HexagonNewValueJump.cpp` - New-value optimization
- `HexagonInstrInfo.cpp` - Instruction queries

### Required Additional Documentation:
- Qualcomm Hexagon Programmer's Reference Manual
- Hexagon V6x ISA Specification
- Hexagon ABI Documentation

---

## Conclusion

The examination of the LLVM Hexagon target implementation reveals a complex, feature-rich VLIW DSP architecture with sophisticated new-value forwarding mechanisms. The key insight regarding your question about new-value register restrictions is:

**Scalar registers (R0-R31)** have well-defined restrictions, with the most significant being that **64-bit double registers cannot participate in new-value forwarding**.

**Vector registers (HVX)** have a critical limitation: **vector stores cannot use .new predicates**, though they can use new-value stores with regular predicates. Vector double registers are additionally problematic.

These restrictions are fundamental to the architecture and must be respected by any implementation, including a potential Ghidra processor module. The documentation provided gives a comprehensive foundation for understanding these constraints and implementing proper support.

---

**Date:** January 6, 2026  
**Analysis Based On:** LLVM Project llvm/lib/Target/Hexagon/  
**Total Documentation:** ~50KB across 3 comprehensive documents
