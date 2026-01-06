# Hexagon Processor Architecture Analysis
## Based on LLVM Project Source Code Examination

**Date:** January 6, 2026  
**Source:** LLVM Project (llvm/lib/Target/Hexagon)  
**Purpose:** Documentation of Hexagon architecture for potential Ghidra processor module implementation

---

## 1. Overview

The Hexagon processor is a VLIW (Very Long Instruction Word) DSP architecture developed by Qualcomm. It is commonly used in mobile SoCs and other embedded applications. The LLVM project contains a comprehensive backend implementation for this architecture.

### Key Characteristics

- **Architecture Type:** VLIW DSP
- **Instruction Set:** Variable-length packets containing multiple instructions
- **Endianness:** Little-endian
- **Instruction Size:** 32-bit base instruction size
- **Packet-Based Execution:** Multiple instructions can execute in parallel within a packet
- **ELF Machine Type:** EM_HEXAGON (164)

---

## 2. Processor Versions

The Hexagon architecture has evolved through multiple versions, each adding new features and capabilities:

### Architecture Versions
- **V5** - Hexagon V5 architecture
- **V55** - Hexagon V55 architecture  
- **V60** - Hexagon V60 architecture (introduces HVX)
- **V62** - Hexagon V62 architecture
- **V65** - Hexagon V65 architecture
- **V66** - Hexagon V66 architecture
- **V67** - Hexagon V67 architecture
- **V68** - Hexagon V68 architecture
- **V69** - Hexagon V69 architecture
- **V71** - Hexagon V71 architecture
- **V73** - Hexagon V73 architecture
- **V75** - Hexagon V75 architecture
- **V79** - Hexagon V79 architecture
- **V81** - Hexagon V81 architecture (latest)

### Special Features
- **TinyCore** - Hexagon Tiny Core variant
- **ZReg** - ZReg extension instructions
- **Audio** - Audio extension instructions

---

## 3. Register Architecture

### 3.1 General Purpose Registers (GPRs)

**Integer Registers (32-bit):**
- **R0-R28** - General purpose integer registers
- **R29 (SP)** - Stack pointer
- **R30 (FP)** - Frame pointer
- **R31 (LR)** - Link register
- Total: 32 registers (R0-R31)

**Double Registers (64-bit):**
Formed by pairing consecutive even/odd registers:
- **D0** = R1:R0
- **D1** = R3:R2
- **D2** = R5:R4
- ... (continues)
- **D15** = R31:R30 (LR:FP)
- Total: 16 double registers

**Encoding:** 5-bit encoding (bits 4-0)

### 3.2 Predicate Registers

**Standard Predicate Registers:**
- **P0-P3** - 4 predicate registers for conditional execution
- Used for predicated instruction execution
- **Encoding:** 5-bit encoding

### 3.3 Vector Registers (HVX Extension)

**Vector Predicate Registers:**
- **Q0-Q3** - Vector predicate registers (at minimum, may be more)
- **Encoding:** 3-bit encoding (bits 2-0)

**HVX Vector Registers:**
The Hexagon Vector eXtensions (HVX) provide SIMD capabilities with configurable vector widths:
- **64-byte vectors** (hvx-length64b)
- **128-byte vectors** (hvx-length128b)

### 3.4 Control Registers

**Control Registers (Rc):**
- Various control registers with 5-bit encoding
- Include special-purpose registers for processor control

**Control Double Registers (Rcc):**
- 64-bit control register pairs

### 3.5 System Registers

**System Registers (Rs):**
- 7-bit encoding (bits 6-0)
- Used for system-level control

**System Double Registers (Rss):**
- 64-bit system register pairs

### 3.6 Other Registers

**Modifier Registers (Mx):**
- **M0-M1** - Address modifier registers
- 1-bit encoding

**Guest/Hypervisor Registers:**
- **Rg** - Guest/Hypervisor registers (32-bit)
- **Rgg** - Guest/Hypervisor register pairs (64-bit)
- 5-bit encoding

**Special Overflow Register:**
- **USR.OVF** - User Status Register overflow bit
- Used by arithmetic/saturating instructions
- Multiple instructions in a packet can modify this bit

### 3.7 SubRegister Indices

- **isub_lo** - Low 32 bits (offset 0)
- **isub_hi** - High 32 bits (offset 32)
- **vsub_lo** - Vector low subregister
- **vsub_hi** - Vector high subregister
- **vsub_fake** - Fake vector subregister
- **wsub_lo** - Wide vector low subregister
- **wsub_hi** - Wide vector high subregister
- **subreg_overflow** - Overflow bit subregister (1 bit at offset 0)

---

## 4. Instruction Format

### 4.1 Base Instruction Structure

**Instruction Width:** 32 bits

**ICLASS Field (bits 31-28):**
The top 4 bits identify the instruction class:
- `0x0` - EXTENDER or DUPLEX
- `0x1` - J_1 (Jump type 1)
- `0x2` - J_2 (Jump type 2)
- `0x3` - LD_ST_1 (Load/Store type 1)
- `0x4` - LD_ST_2 (Load/Store type 2)
- `0x5` - J_3 (Jump type 3)
- `0x6` - CR (Control Register)
- `0x7` - ALU32_1 (32-bit ALU type 1)
- `0x8` - XTYPE_1 (Extended type 1)
- `0x9` - LD (Load)
- `0xa` - ST (Store)
- `0xb` - ALU32_2 (32-bit ALU type 2)
- `0xc` - XTYPE_2 (Extended type 2)
- `0xd` - XTYPE_3 (Extended type 3)
- `0xe` - XTYPE_4 (Extended type 4)
- `0xf` - ALU32_3 (32-bit ALU type 3)

### 4.2 Packet Structure

**Parse Bits (bits 15-14):**
Instructions are grouped into packets that execute in parallel. Parse bits indicate packet boundaries:
- `0b11` - Packet end (INST_PARSE_PACKET_END)
- `0b10` - Loop end (INST_PARSE_LOOP_END)
- `0b01` - Not end (INST_PARSE_NOT_END)
- `0b00` - Duplex or Extender

**Packet Execution:**
- Multiple instructions in a packet execute in parallel
- Instructions within a packet have data dependencies resolved
- Packets can contain up to 4 instructions (typically)

### 4.3 Instruction Types

The architecture supports numerous instruction types (57+ types defined):

**Basic Types:**
- TypeALU32_2op - 32-bit ALU with 2 operands
- TypeALU32_3op - 32-bit ALU with 3 operands
- TypeALU32_ADDI - 32-bit ALU add immediate
- TypeALU64 - 64-bit ALU operations
- TypeJ - Jump instructions
- TypeLD - Load instructions
- TypeST - Store instructions
- TypeM - Multiply instructions
- TypeS_2op - Shift 2 operand
- TypeS_3op - Shift 3 operand

**Control Flow:**
- TypeCJ - Conditional jump
- TypeNCJ - Non-conditional jump
- TypeCR - Control register operations
- TypeENDLOOP - Hardware loop end

**Vector Types (HVX):**
- TypeCVI_4SLOT_MPY - 4-slot multiply
- TypeCVI_GATHER - Vector gather
- TypeCVI_SCATTER - Vector scatter
- TypeCVI_VA - Vector arithmetic
- TypeCVI_VM_LD - Vector memory load
- TypeCVI_VM_ST - Vector memory store
- TypeCVI_VP - Vector permute
- TypeCVI_VS - Vector shift
- TypeCVI_VX - Vector extended
- TypeCVI_ZW - Zero/Write operations

**Special Types:**
- TypeDUPLEX - Duplex instructions (two sub-instructions)
- TypeEXTENDER - Immediate extender
- TypeSUBINSN - Sub-instruction
- TypePSEUDO - Pseudo instructions
- TypeMAPPING - Mapping instructions

---

## 5. Instruction Features

### 5.1 Predication

**Predicated Execution:**
- Instructions can be conditionally executed based on predicate registers
- **isPredicated** - Instruction is predicated
- **isPredicatedFalse** - Execute if predicate is false
- **isPredicatedNew** - Uses new predicate value
- **isPredicateLate** - Late predicate producer

### 5.2 New-Value Operations

**New-Value Mechanism:**
Allows using the result of an instruction in the same packet:

- **isNewValue** - Instruction consumes a new value
- **hasNewValue** - Instruction produces a new value
- **opNewValue** - Which operand is the new value (3 bits)
- **hasNewValue2** - Second new-value producer
- **opNewValue2** - Second new-value operand

**New-Value Stores:**
- **isNVStorable** - Store can become new-value store
- **isNVStore** - Is a new-value store

**Current-Value Loads:**
- **isCVLoadable** - Load can become current-value load
- **isCVLoad** - Is a current-value load

### 5.3 Immediate Extension

**Extendable Instructions:**
- **isExtendable** - Instruction may be extended
- **isExtended** - Instruction must be extended
- **opExtendable** - Which operand may be extended (3 bits)
- **isExtentSigned** - Signed or unsigned range
- **opExtentBits** - Number of bits before extending (5 bits)
- **opExtentAlign** - Alignment exponent (2 bits)

### 5.4 Slot and Execution Restrictions

**Solo Restrictions:**
- **isSolo** - Cannot be in packet with others
- **isSoloAX** - Packed only with A or X-type instructions
- **isRestrictSlot1AOK** - Restricts slot 1 to ALU-only

**Store Restrictions:**
- **isRestrictNoSlot1Store** - No store in slot 1

**Slot Preferences:**
- **prefersSlot3** - Complex XU, prefers slot 3

### 5.5 Other Features

**Compound Instructions:**
- **isCompound** - Use compound instructions (two operations in one encoding)

**Accumulator:**
- **isAccumulator** - Accumulator instruction

**Branch Prediction:**
- **isTaken** - Branch predicted taken

**Floating-Point:**
- **isFP** - Floating-point instruction

**HVX Features:**
- **hasHvxTmp** - Vector register vX.tmp false-write
- **isCVI** - CVI (Compute Vector Instructions)
- **CVINew** - CVI new-value
- **isHVXALU** - HVX ALU operation
- **isHVXALU2SRC** - HVX ALU with 2 sources

**Restrictions:**
- **hasUnaryRestriction** - Has unary restriction

---

## 6. Addressing Modes

### Load/Store Addressing Modes

The architecture supports multiple addressing modes:

1. **NoAddrMode (0)** - No addressing mode
2. **Absolute (1)** - Absolute addressing
3. **AbsoluteSet (2)** - Absolute set addressing
4. **BaseImmOffset (3)** - Base register + immediate offset
5. **BaseLongOffset (4)** - Base register + long offset
6. **BaseRegOffset (5)** - Base register + register offset
7. **PostInc (6)** - Post-increment addressing

### Memory Access Sizes

1. **NoMemAccess (0)** - No memory access
2. **ByteAccess (1)** - 1 byte
3. **HalfWordAccess (2)** - 2 bytes
4. **WordAccess (3)** - 4 bytes
5. **DoubleWordAccess (4)** - 8 bytes
6. **HVXVectorAccess (5)** - Vector access (64B or 128B)

---

## 7. HVX (Hexagon Vector eXtensions)

### HVX Versions

HVX is the SIMD extension for Hexagon, evolving across processor versions:

- **HVXv60** - Initial HVX (V60)
- **HVXv62** - Enhanced HVX (V62)
- **HVXv65** - V65 HVX features
- **HVXv66** - V66 HVX features (includes ZReg)
- **HVXv67** - V67 HVX features
- **HVXv68** - V68 HVX features
- **HVXv69** - V69 HVX features
- **HVXv71** - V71 HVX features
- **HVXv73** - V73 HVX features
- **HVXv75** - V75 HVX features
- **HVXv79** - V79 HVX features
- **HVXv81** - V81 HVX features

### HVX Features

**Vector Lengths:**
- **hvx-length64b** - 64-byte vectors
- **hvx-length128b** - 128-byte vectors

**Operations:**
- **hvx-qfloat** - HVX QFloating point instructions
- **hvx-ieee-fp** - HVX IEEE floating point instructions

**Vector Instructions:**
- Vector arithmetic (VA)
- Vector permute (VP)
- Vector shift (VS)
- Vector extended (VX)
- Gather/Scatter operations
- Vector loads/stores
- Vector predicates

---

## 8. Sub-Instructions and Duplex

### Sub-Instruction Groups

Hexagon supports sub-instructions that can be paired in duplex form:

1. **HSIG_None** - No sub-instruction
2. **HSIG_L1** - Load type 1
3. **HSIG_L2** - Load type 2
4. **HSIG_S1** - Store type 1
5. **HSIG_S2** - Store type 2
6. **HSIG_A** - ALU
7. **HSIG_Compound** - Compound instruction

### Compound Groups

1. **HCG_None** - No compound
2. **HCG_A** - Compound group A
3. **HCG_B** - Compound group B
4. **HCG_C** - Compound group C

---

## 9. Target Flags and Relocations

### MachineOperand Target Flags

- **MO_PCREL** - PC-relative relocation
- **MO_GOT** - GOT-relative relocation
- **MO_LO16** - Low 16 bits of symbol
- **MO_HI16** - High 16 bits of symbol
- **MO_GPREL** - Offset from SDA base
- **MO_GDGOT** - GOT for TLS General Dynamic
- **MO_GDPLT** - PLT for TLS General Dynamic
- **MO_IE** - TLS Initial Executable (non-PIC)
- **MO_IEGOT** - TLS Initial Executable (PIC)
- **MO_TPREL** - TLS Local Executable
- **HMOTF_ConstExtended** - Constant extended operand (bit mask 0x80)

---

## 10. Implementation Considerations for Ghidra

### 10.1 Current Status in Ghidra

- **ELF Recognition:** Hexagon is recognized (EM_HEXAGON = 164 in ElfConstants.java)
- **LLDB Support:** Hexagon entries exist but are empty (no language defined)
- **Processor Module:** No Hexagon processor module exists in Ghidra/Processors/

### 10.2 Requirements for Ghidra Implementation

To implement Hexagon support in Ghidra, the following would be needed:

1. **SLEIGH Specification (.slaspec files):**
   - Define register spaces and registers
   - Define instruction encodings and semantics
   - Handle VLIW packet decoding
   - Implement predication semantics
   - Implement new-value forwarding
   - Support multiple architecture versions

2. **Processor Module Structure:**
   ```
   Ghidra/Processors/Hexagon/
   ├── Module.manifest
   ├── README.md
   ├── build.gradle
   ├── certification.manifest
   ├── data/
   │   ├── languages/
   │   │   ├── Hexagon.ldefs
   │   │   ├── Hexagon.pspec
   │   │   ├── Hexagon.slaspec
   │   │   ├── Hexagon.sinc
   │   │   ├── Hexagon_*.cspec (calling conventions)
   │   │   └── Hexagon.dwarf (DWARF register mappings)
   │   ├── manuals/
   │   └── patterns/
   └── src/
   ```

3. **Key Challenges:**
   - **VLIW Packet Handling:** Instructions grouped in packets with parallel execution
   - **Complex Instruction Encoding:** Multiple instruction classes and formats
   - **New-Value Mechanism:** Data forwarding within packets
   - **Predication:** Conditional execution with predicate registers
   - **HVX Vector Instructions:** Large SIMD instruction set
   - **Multiple Versions:** Support for V5 through V81 with incremental features
   - **Hardware Loops:** Specialized loop handling
   - **Duplex Instructions:** Two sub-instructions in one encoding

4. **LLDB Integration:**
   Update `Ghidra/Debug/Debugger-agent-lldb/src/main/py/src/ghidralldb/arch.py`:
   ```python
   'hexagon': ['Hexagon:LE:32:default'],
   'hexagonv4': ['Hexagon:LE:32:v4'],
   'hexagonv5': ['Hexagon:LE:32:v5'],
   ```

### 10.3 Reference Material

**LLVM Source Files (Key Files Examined):**
- `llvm/lib/Target/Hexagon/Hexagon.td` - Top-level target definition
- `llvm/lib/Target/Hexagon/HexagonRegisterInfo.td` - Register definitions
- `llvm/lib/Target/Hexagon/HexagonInstrFormats.td` - Instruction formats
- `llvm/lib/Target/Hexagon/HexagonDepArch.td` - Architecture versions
- `llvm/lib/Target/Hexagon/HexagonDepITypes.td` - Instruction types
- `llvm/lib/Target/Hexagon/MCTargetDesc/HexagonBaseInfo.h` - Base definitions

**Additional Resources Needed:**
- Qualcomm Hexagon Programmer's Reference Manual
- Hexagon V6x Programmer's Reference Manual (if available)
- Hexagon ABI documentation
- Hexagon ISA specification

---

## 11. Summary

The Hexagon architecture is a sophisticated VLIW DSP with:
- 32 general-purpose 32-bit registers
- 4 predicate registers for conditional execution
- Extensive SIMD capabilities through HVX extensions
- Complex packet-based parallel execution model
- Multiple instruction formats and types (50+ instruction types)
- Support for new-value forwarding within packets
- Hardware loop support
- Multiple architecture versions (V5-V81)

The LLVM implementation provides a comprehensive reference for understanding the architecture, including detailed register definitions, instruction formats, and execution semantics. However, implementing Hexagon support in Ghidra would be a substantial undertaking requiring detailed ISA documentation and careful SLEIGH specification development.

---

**Document prepared through examination of LLVM Project source code**  
**Repository:** https://github.com/llvm/llvm-project  
**Path:** llvm/lib/Target/Hexagon/
