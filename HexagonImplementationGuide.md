# Hexagon Implementation Guide for Ghidra
## Practical Examples and Code Patterns from LLVM

**Companion Document to:** HexagonArchitectureAnalysis.md  
**Date:** January 6, 2026

---

## 1. Introduction

This guide provides practical examples and implementation patterns derived from the LLVM Hexagon target backend. It serves as a companion to the architectural analysis and focuses on concrete examples that would be useful when implementing Hexagon support in Ghidra.

---

## 2. Register Encoding Examples

### 2.1 Integer Register Definition Pattern

From `HexagonRegisterInfo.td`:

```tablegen
// Integer registers R0-R28
foreach i = 0-28 in { 
  def R#i : Ri<i, "r"#i>, DwarfRegNum<[i]>; 
}

// Special registers with aliases
def R29 : Ri<29, "r29", ["sp"]>, DwarfRegNum<[29]>;  // Stack Pointer
def R30 : Ri<30, "r30", ["fp"]>, DwarfRegNum<[30]>;  // Frame Pointer  
def R31 : Ri<31, "r31", ["lr"]>, DwarfRegNum<[31]>;  // Link Register
```

**Key Points:**
- Registers use 5-bit encoding (0-31)
- R29, R30, R31 have architectural significance and aliases
- DWARF register numbers map 1:1 with register numbers

### 2.2 Double Register Pattern

```tablegen
let SubRegIndices = [isub_lo, isub_hi], CoveredBySubRegs = 1 in {
  def D0 : Rd<0, "r1:0", [R0, R1]>, DwarfRegNum<[32]>;
  def D1 : Rd<2, "r3:2", [R2, R3]>, DwarfRegNum<[34]>;
  // ... continues
  def D15 : Rd<30, "r31:30", [R30, R31], ["lr:fp"]>, DwarfRegNum<[62]>;
}
```

**Key Points:**
- Double registers are formed from consecutive R0/R1, R2/R3, etc.
- Notation is "high:low" (e.g., "r1:r0")
- Encoding uses the even register number
- DWARF numbers are offset (start at 32)
- SubRegIndices define how the double register maps to components

### 2.3 Predicate Registers

```tablegen
def P0 : Rp<0, "p0">, DwarfRegNum<[63]>;
def P1 : Rp<1, "p1">, DwarfRegNum<[64]>;
def P2 : Rp<2, "p2">, DwarfRegNum<[65]>;
def P3 : Rp<3, "p3">, DwarfRegNum<[66]>;
```

**Key Points:**
- 4 predicate registers
- Used for conditional execution
- DWARF numbers 63-66

---

## 3. Instruction Format Examples

### 3.1 Instruction Class Identification

The top 4 bits (31-28) of every instruction identify its class:

```
Bit Pattern  | ICLASS       | Description
-------------|--------------|------------------
0000 (0x0)   | EXTENDER     | Constant extender or duplex
0001 (0x1)   | J_1          | Jump type 1
0010 (0x2)   | J_2          | Jump type 2
0011 (0x3)   | LD_ST_1      | Load/Store type 1
0100 (0x4)   | LD_ST_2      | Load/Store type 2
0101 (0x5)   | J_3          | Jump type 3
0110 (0x6)   | CR           | Control register ops
0111 (0x7)   | ALU32_1      | 32-bit ALU type 1
1000 (0x8)   | XTYPE_1      | Extended type 1
1001 (0x9)   | LD           | Load
1010 (0xa)   | ST           | Store
1011 (0xb)   | ALU32_2      | 32-bit ALU type 2
1100 (0xc)   | XTYPE_2      | Extended type 2
1101 (0xd)   | XTYPE_3      | Extended type 3
1110 (0xe)   | XTYPE_4      | Extended type 4
1111 (0xf)   | ALU32_3      | 32-bit ALU type 3
```

### 3.2 Packet Parse Bits

Bits 15-14 indicate packet boundaries:

```
Bits [15:14] | Meaning
-------------|---------------------------
11           | End of packet
10           | End of hardware loop
01           | Not end, more in packet
00           | Duplex or extender
```

**Example Packet:**
```
Instruction 1: [31:28]=ALU32_1, [15:14]=01 (not end)
Instruction 2: [31:28]=LD,      [15:14]=01 (not end)  
Instruction 3: [31:28]=ST,      [15:14]=01 (not end)
Instruction 4: [31:28]=ALU32_2, [15:14]=11 (packet end)
```
These four instructions execute in parallel.

---

## 4. Instruction Type Categories

### 4.1 ALU Instructions

**32-bit ALU Operations:**
```
TypeALU32_2op (0)  - Two operand: Rd = op Rs
TypeALU32_3op (1)  - Three operand: Rd = Rs op Rt
TypeALU32_ADDI (2) - Add immediate: Rd = Rs + #imm
```

**64-bit ALU:**
```
TypeALU64 (3)      - 64-bit operations on register pairs
```

### 4.2 Memory Operations

**Loads:**
```
TypeLD (36)        - Standard load instructions
TypeV2LDST (47)    - Vector 2 load/store
TypeV4LDST (48)    - Vector 4 load/store
```

**Stores:**
```
TypeST (41)        - Standard store instructions
```

**Addressing modes for loads/stores:**
- Base + immediate offset
- Base + register offset  
- Post-increment
- Absolute addressing

### 4.3 Control Flow

```
TypeJ (35)         - Unconditional jumps
TypeCJ (4)         - Conditional jumps
TypeNCJ (39)       - Compare and jump
TypeENDLOOP (33)   - Hardware loop end
```

### 4.4 Vector (HVX) Instructions

**Vector Memory:**
```
TypeCVI_VM_LD (18)      - Vector memory load
TypeCVI_VM_ST (20)      - Vector memory store
TypeCVI_VM_NEW_ST (19)  - Vector memory new-value store
TypeCVI_VM_STU (21)     - Vector memory store unconditional
```

**Vector Arithmetic:**
```
TypeCVI_VA (16)         - Vector arithmetic
TypeCVI_VA_DV (17)      - Vector arithmetic double vector
```

**Vector Permute:**
```
TypeCVI_VP (24)         - Vector permute
TypeCVI_VP_VS (25)      - Vector permute/shift
```

**Vector Multiply:**
```
TypeCVI_4SLOT_MPY (6)   - 4-slot multiply
```

**Gather/Scatter:**
```
TypeCVI_GATHER (7)      - Vector gather
TypeCVI_SCATTER (11)    - Vector scatter
```

---

## 5. Predication Examples

### 5.1 Predicate Instruction Flags

Instructions can be predicated with these flag combinations:

```c
// Unpredicated instruction
isPredicated = 0

// Predicated on true: if (P0) ...
isPredicated = 1
isPredicatedFalse = 0

// Predicated on false: if (!P0) ...
isPredicated = 1  
isPredicatedFalse = 1

// Using new predicate value: if (P0.new) ...
isPredicated = 1
isPredicatedNew = 1
```

### 5.2 Example Predicated Assembly

```assembly
// Standard predication
if (p0) r1 = add(r2, r3)      // Execute if p0 is true
if (!p1) r4 = r5              // Execute if p1 is false

// New-value predication  
{
  p0 = cmp.gt(r1, r2)         // Produce p0
  if (p0.new) r3 = add(r4, r5)  // Use p0 in same packet
}
```

---

## 6. New-Value Mechanism

### 6.1 New-Value Producer/Consumer Flags

```c
// Producer instruction
hasNewValue = 1        // This instruction produces a new value
opNewValue = N         // Operand N is the new value (0-7)

// Consumer instruction  
isNewValue = 1         // This instruction uses a new value
// References the producer in the same packet
```

### 6.2 Example New-Value Operations

**New-Value Register:**
```assembly
{
  r1 = add(r2, r3)     // Producer: hasNewValue=1, opNewValue=0
  r4 = add(r5, r1.new)  // Consumer: isNewValue=1, uses r1.new
}
```

**New-Value Store:**
```assembly
{
  r1 = add(r2, r3)       // Producer
  memw(r10) = r1.new    // New-value store: isNVStore=1
}
```

**New-Value Compare:**
```assembly
{
  r1 = add(r2, r3)           // Producer
  p0 = cmp.gt(r1.new, r4)   // Consumer uses r1.new
}
```

---

## 7. Constant Extenders

### 7.1 Extender Mechanism

Instructions with immediate operands can be extended to 32 bits:

```c
// Instruction with extendable immediate
isExtendable = 1       // Can be extended
opExtendable = N       // Operand N can be extended
isExtentSigned = 1/0   // Signed or unsigned
opExtentBits = B       // B bits without extension
opExtentAlign = A      // Aligned to 2^A bytes
```

### 7.2 Example Extended Instructions

```assembly
// Without extender (11-bit immediate)
r0 = add(r1, #100)

// With extender (32-bit immediate)
r0 = add(r1, ##0x12345678)  // ## indicates constant extender needed

// The assembler generates two instructions:
// 1. Constant extender packet (ICLASS=0x0)
// 2. The actual add instruction with extended immediate
```

### 7.3 Extender Packet Format

```
ICLASS [31:28] = 0000 (extender)
Extended bits [27:16] = high bits of constant
Extended bits [13:0]  = low bits of constant
Parse bits [15:14] = 01 (not end)
```

---

## 8. Hardware Loops

### 8.1 Loop Structure

Hexagon has hardware support for zero-overhead loops:

```assembly
loop0(.label, #count)    // Setup loop0 with count iterations
  // Loop body
.label:                   // Loop end marker
```

### 8.2 Loop Instructions

- **loop0** - Setup loop 0
- **loop1** - Setup loop 1 (nested)
- **endloop0** - End of loop 0 (TypeENDLOOP)
- **endloop1** - End of loop 1

**Features:**
- Zero overhead (no branch penalty)
- Automatically decrements counter
- Can nest loops (loop0 and loop1)

---

## 9. Duplex Instructions

### 9.1 Duplex Format

Duplex instructions pack two sub-instructions into one 32-bit word:

```
[31:28] = 0000 (ICLASS indicates duplex)
[27:25] = Sub-instruction group info
[12:0]  = Sub-instruction 1
[24:13] = Sub-instruction 2
```

### 9.2 Sub-Instruction Groups

Valid combinations:
- **L1/L2** - Load sub-instructions
- **S1/S2** - Store sub-instructions  
- **A** - ALU sub-instructions
- **Compound** - Predefined compound operations

### 9.3 Example Duplex

```assembly
{
  r0 = memw(r10++#4)     // Load with post-increment (L2)
  r1 = add(r1, #1)       // ALU immediate (A)
}
```

This can be encoded as a duplex instruction if both operations fit the sub-instruction constraints.

---

## 10. Compound Instructions

### 10.1 Compound Groups

Compound instructions are common operation pairs optimized into single encodings:

**Group A Examples:**
```assembly
r0 = add(r1, #1); if (cmp.eq(r0.new, #0)) jump .label
r0 = r1; r2 = r3
```

**Group B Examples:**
```assembly
if (p0) r0 = r1; if (!p0) r0 = r2  // Conditional move
```

**Group C Examples:**
```assembly
memw(r0) = r1; r0 = add(r0, #4)   // Store with update
```

---

## 11. TSFlags Bit Layout

The instruction TSFlags field encodes properties (64 bits):

```
Bits      | Field                  | Description
----------|------------------------|---------------------------
[6:0]     | Type                   | Instruction type (57 types)
[7]       | isSolo                 | Cannot be in packet
[8]       | isSoloAX              | Only with A/X types
[9]       | RestrictSlot1AOK      | Slot 1 ALU only
[10]      | isPredicated          | Predicated instruction
[11]      | isPredicatedFalse     | Predicate on false
[12]      | isPredicatedNew       | Uses .new predicate
[13]      | isPredicateLate       | Late predicate producer
[14]      | isNewValue            | New-value consumer
[15]      | hasNewValue           | New-value producer
[18:16]   | opNewValue            | New-value operand
[19]      | isNVStorable          | Can be NV store
[20]      | isNVStore             | Is NV store
[21]      | isCVLoadable          | Can be CV load
[22]      | isCVLoad              | Is CV load
[23]      | isExtendable          | Can extend immediate
[24]      | isExtended            | Must extend immediate
[27:25]   | opExtendable          | Extendable operand
[28]      | isExtentSigned        | Signed extension
[33:29]   | opExtentBits          | Bits before extension
[35:34]   | opExtentAlign         | Alignment power
[36]      | cofMax1               | Compound flag
[37]      | cofRelax1             | Compound flag
[38]      | cofRelax2             | Compound flag
[39]      | RestrictNoSlot1Store  | No store in slot 1
[42:40]   | addrMode              | Addressing mode
[46:43]   | accessSize            | Memory access size
[47]      | isTaken               | Branch predicted
[48]      | isFP                  | Floating-point
[50]      | hasNewValue2          | Second NV producer
[53:51]   | opNewValue2           | Second NV operand
[54]      | isAccumulator         | Accumulator instruction
[55]      | prefersSlot3          | Prefer slot 3
[56]      | hasHvxTmp             | HVX temp register
[58]      | CVINew                | CVI new-value
[59]      | isCVI                 | Is CVI
[60]      | isHVXALU              | HVX ALU
[61]      | isHVXALU2SRC          | HVX ALU 2-source
[62]      | hasUnaryRestriction   | Unary restriction
```

---

## 12. Implementation Checklist for Ghidra

### 12.1 Essential Components

**Language Definition (.slaspec):**
- [ ] Define register spaces (R0-R31, P0-P3, D0-D15, etc.)
- [ ] Define token formats for instruction encoding
- [ ] Implement ICLASS decoding (bits 31-28)
- [ ] Implement packet boundary detection (bits 15-14)
- [ ] Define constructors for each instruction type
- [ ] Implement predication semantics
- [ ] Implement new-value forwarding
- [ ] Handle constant extenders
- [ ] Support duplex instructions
- [ ] Add hardware loop support

**Processor Specification (.pspec):**
- [ ] Define endianness (little-endian)
- [ ] Define default space sizes
- [ ] Define code and data alignment

**Calling Convention (.cspec):**
- [ ] Define parameter passing (R0-R5)
- [ ] Define return value registers
- [ ] Define callee-saved registers
- [ ] Define stack pointer (R29) and frame pointer (R30)
- [ ] Define return address (R31)

**Language Definition (.ldefs):**
- [ ] Define language variants (V5, V60, V62, etc.)
- [ ] Associate .slaspec files with variants
- [ ] Define processor naming

**DWARF Mappings (.dwarf):**
- [ ] Map DWARF register numbers to Ghidra registers
- [ ] R0-R31 → DWARF 0-31
- [ ] D0-D15 → DWARF 32-62
- [ ] P0-P3 → DWARF 63-66

### 12.2 Testing Strategy

1. **Basic Instruction Decoding:**
   - Test each ICLASS type
   - Verify register encodings
   - Check immediate values

2. **Packet Handling:**
   - Test packet boundary detection
   - Verify parallel execution representation
   - Test predicated instructions in packets

3. **Advanced Features:**
   - Test new-value forwarding
   - Test constant extenders
   - Test duplex instructions
   - Test hardware loops

4. **Binary Compatibility:**
   - Test with real Hexagon ELF binaries
   - Verify disassembly matches objdump
   - Check function analysis

---

## 13. Example SLEIGH Patterns

### 13.1 Register Definition

```sleigh
# Define register space
define space register type=register_space size=4;

# General purpose registers
define register offset=0x00 size=4 [
  R0  R1  R2  R3  R4  R5  R6  R7
  R8  R9  R10 R11 R12 R13 R14 R15
  R16 R17 R18 R19 R20 R21 R22 R23
  R24 R25 R26 R27 R28 SP  FP  LR
];

# Predicate registers  
define register offset=0x80 size=1 [P0 P1 P2 P3];

# Double registers (contexts)
define register offset=0x100 size=8 [
  D0 D1 D2 D3 D4 D5 D6 D7
  D8 D9 D10 D11 D12 D13 D14 D15
];
```

### 13.2 Basic Instruction Pattern

```sleigh
# Define ICLASS field
define token instr(32)
  iclass=(28,31)
  parse=(14,15)
  # ... more fields
;

# ALU32_1 class
:add Rd, Rs, Rt is iclass=0x7 & Rd & Rs & Rt {
  Rd = Rs + Rt;
}
```

### 13.3 Predicated Instruction

```sleigh
# Predicated add
:if (Pn) add Rd, Rs, Rt is pred=1 & Pn & Rd & Rs & Rt {
  if (Pn) goto <skip>;
  Rd = Rs + Rt;
  <skip>
}
```

---

## 14. References and Resources

### 14.1 LLVM Source Files

Key files examined for this guide:
- `Hexagon.td` - Target definition
- `HexagonRegisterInfo.td` - Register architecture
- `HexagonInstrFormats.td` - Instruction formats
- `HexagonDepArch.td` - Architecture versions
- `HexagonDepITypes.td` - Instruction types
- `HexagonBaseInfo.h` - Constants and enumerations

### 14.2 Additional Documentation Needed

- Qualcomm Hexagon Programmer's Reference Manual (official ISA spec)
- Hexagon V6x Programmer's Reference (version-specific details)
- Hexagon Application Binary Interface (ABI)
- Hexagon Assembly Language Reference

### 14.3 Similar Ghidra Implementations

Study these existing VLIW/DSP processors in Ghidra for reference:
- **TI_MSP430** - Simple processor with good structure
- **tricore** - Another VLIW architecture
- **ARM** - Well-documented with multiple variants
- **MIPS** - Good example of multiple architecture versions

---

## 15. Conclusion

Implementing Hexagon support in Ghidra is a significant undertaking that requires:

1. **Deep understanding** of VLIW packet execution
2. **Careful SLEIGH specification** of complex instruction formats
3. **Proper handling** of new-value forwarding and predication
4. **Support for multiple** architecture versions

The LLVM implementation provides excellent reference material for understanding the architecture, but official Qualcomm documentation would be essential for a complete and accurate implementation.

This guide provides the foundational patterns and examples needed to begin such an implementation, based on careful examination of the LLVM Hexagon target backend.

---

**Document prepared through examination of LLVM Project source code**  
**Repository:** https://github.com/llvm/llvm-project  
**Path:** llvm/lib/Target/Hexagon/
