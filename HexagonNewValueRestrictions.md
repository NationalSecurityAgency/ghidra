# Hexagon New-Value Register Usage and Restrictions
## Detailed Analysis for Scalar and Vector Registers

**Date:** January 6, 2026  
**Source:** LLVM Project (llvm/lib/Target/Hexagon)  
**Purpose:** Comprehensive documentation of new-value mechanism restrictions

---

## 1. Overview of New-Value Mechanism

The Hexagon architecture supports a "new-value" mechanism that allows instructions within the same packet to use values produced by other instructions in that packet, without waiting for the value to be written back to the register file. This feature is critical for performance in the VLIW architecture.

### Basic Concept

```assembly
{
  r1 = add(r2, r3)       // Producer: generates r1
  r4 = add(r5, r1.new)   // Consumer: uses r1.new in same packet
}
```

The `.new` suffix indicates the value is forwarded directly from the producer's execution unit to the consumer, bypassing the register file.

---

## 2. New-Value Categories

### 2.1 New-Value Register Forwarding
Direct forwarding of register values within a packet.

### 2.2 New-Value Stores
Stores that use a newly computed value:
```assembly
{
  r1 = add(r2, r3)
  memw(r10) = r1.new    // New-value store
}
```

### 2.3 New-Value Jumps
Compare-and-branch using a newly computed value:
```assembly
{
  r1 = add(r2, r3)
  if (cmp.gt(r1.new, #0)) jump .label
}
```

### 2.4 New-Value Predicates
Predicate register values used immediately:
```assembly
{
  p0 = cmp.gt(r1, r2)
  if (p0.new) r3 = add(r4, r5)
}
```

---

## 3. Scalar Register Restrictions

### 3.1 General Scalar New-Value Rules

**From HexagonVLIWPacketizer.cpp - canBeFeederToNewValueJump():**

1. **Predicated instructions cannot be feeders**
   ```cpp
   if (QII->isPredicated(*II))
     return false;
   ```
   - A predicated instruction cannot produce a new value
   - This prevents conditional execution from affecting new-value forwarding

2. **Double registers cannot feed new-value operations**
   ```cpp
   // Double regs can not feed into new value store: PRM section: 5.4.2.2.
   if (PacketRC == &Hexagon::DoubleRegsRegClass)
     return false;
   ```
   - 64-bit register pairs (D0-D15) cannot be new-value producers
   - Only 32-bit scalar registers (R0-R31) can produce new values
   - This is an architectural limitation

3. **KILL pseudo-instructions cannot be feeders**
   ```cpp
   if (II->getOpcode() == TargetOpcode::KILL)
     return false;
   ```
   - KILL instructions are compiler artifacts
   - They don't produce actual values

4. **Implicit definitions cannot be feeders**
   ```cpp
   if (II->isImplicitDef())
     return false;
   ```

5. **Solo instructions cannot be feeders**
   ```cpp
   if (QII->isSolo(*II))
     return false;
   ```
   - Solo instructions must be in their own packet
   - They cannot participate in new-value forwarding

6. **Floating-point instructions cannot be feeders**
   ```cpp
   if (QII->isFloat(*II))
     return false;
   ```
   - FP instructions have different timing characteristics
   - They cannot produce new values

7. **Only IntRegs class can produce new values**
   ```cpp
   if (!Hexagon::IntRegsRegClass.contains(Op.getReg()))
     return false;
   ```
   - Must be in the integer register class (R0-R31)
   - Control registers, system registers, etc. cannot produce new values

### 3.2 Post-Increment Register Restriction

**Critical restriction for new-value stores:**

```cpp
// Make sure it's NOT the post increment register that we are going to
// new value.
if (HII->isPostIncrement(MI) &&
    getPostIncrementOperand(MI, HII).getReg() == DepReg) {
  return false;
}
```

**Example of prohibited pattern:**
```assembly
{
  r1 = add(r1, #4)           // Modifies r1
  memw(r1) = r2.new          // Uses r1 as base - INVALID if r2.new == r1
}
```

The post-increment register (base address) cannot be the new-value source.

### 3.3 WAR Hazard Prevention

**From canBeFeederToNewValueJump():**

The code checks for Write-After-Read (WAR) hazards:

```cpp
// Make sure there is no 'def' or 'use' of any of the uses of
// feeder insn between its definition, this MI and jump, jmpInst
// skipping compare, cmpInst.
```

**Example of prohibited pattern:**
```assembly
r21 = memub(r22+r24<<#0)    // Uses r21, r22, r24
p0 = cmp.eq(r21, #0)
r4 = memub(r3+r21<<#0)      // Uses r21 again - creates WAR hazard!
if (p0.new) jump:t .label
```

Without this check, reordering for new-value would create:
```assembly
r4 = memub(r3+r21<<#0)      // Uses OLD r21
r21 = memub(r22+r24<<#0)    // Redefines r21
p0 = cmp.eq(r21, #0)
if (p0.new) jump:t .label
```

This changes the semantics - r4 would use the wrong r21 value.

### 3.4 New-Value Store Restrictions

**From canPromoteToNewValueStore():**

1. **No other stores in packet**
   ```cpp
   // New-value stores are of class NV (slot 0), dual stores require class ST
   // in slot 0 (PRM 5.5).
   for (auto *I : CurrentPacketMIs) {
     SUnit *PacketSU = MIToSUnit.find(I)->second;
     if (PacketSU->getInstr()->mayStore())
       return false;
   }
   ```
   - **Corollary:** If there is already a store in a packet, there cannot be a new-value store
   - **Architectural Spec:** Section 3.4.4.2, 5.4.2.3
   - Only ONE store allowed when using new-value stores

2. **Instruction must be marked as newifiable**
   ```cpp
   if (!HII->mayBeNewStore(MI))
     return false;
   ```
   - The TSFlags must have the mayNVStore bit set
   - Not all stores can be converted to new-value stores

3. **Dependency must be on the stored value**
   ```cpp
   const MachineOperand &Val = getStoreValueOperand(MI);
   if (Val.isReg() && Val.getReg() != DepReg)
     return false;
   ```

### 3.5 Memory Operation Restrictions

**From commonChecksToProhibitNewValueJump():**

1. **No stores in path**
   ```cpp
   if (MII->mayStore())
     return false;
   ```

2. **No calls in path**
   ```cpp
   if (MII->isCall())
     return false;
   ```

These prevent reordering that would violate memory ordering or call semantics.

---

## 4. Vector Register Restrictions (HVX)

### 4.1 Vector Double Register Restriction

**Key restriction from canPromoteToDotNew():**

```cpp
const MCInstrDesc& MCID = PI.getDesc();
const TargetRegisterClass *VecRC = HII->getRegClass(MCID, 0);
if (DisableVecDblNVStores && VecRC == &Hexagon::HvxWRRegClass)
  return false;
```

**Analysis:**
- **HvxWRRegClass** represents vector double registers (wide vector registers)
- There is a **command-line option** to disable vector double new-value stores: `-disable-vecdbl-nv-stores`
- This suggests vector double registers have issues with new-value mechanism
- **Recommendation:** Vector double register new-values are experimental/problematic

### 4.2 Vector Store Restrictions

**From isNewifiable():**

```cpp
// Vector stores can be predicated, and can be new-value stores, but
// they cannot be predicated on a .new predicate value.
if (NewRC == &Hexagon::PredRegsRegClass) {
  if (HII->isHVXVec(MI) && MI.mayStore())
    return false;
  return HII->isPredicated(MI) && HII->getDotNewPredOp(MI, nullptr) > 0;
}
```

**Critical restriction:**
- **Vector stores CAN be:**
  - New-value stores (storing a newly computed vector)
  - Predicated (conditionally executed)
  
- **Vector stores CANNOT be:**
  - Predicated on a `.new` predicate value

**Example - INVALID:**
```assembly
{
  p0 = vcmp.gt(v1, v2)
  if (p0.new) vmem(r0) = v3.new   // INVALID: .new predicate on vector store
}
```

**Example - VALID:**
```assembly
{
  v3 = vadd(v1, v2)
  if (p0) vmem(r0) = v3.new      // VALID: non-.new predicate
}
```

### 4.3 Vector Instruction Timing

**From producesStall():**

```cpp
bool HexagonInstrInfo::producesStall(const MachineInstr &ProdMI,
      const MachineInstr &ConsMI) const {
  // There is no stall when ProdMI is not a V60 vector.
  if (!isHVXVec(ProdMI))
    return false;

  // There is no stall when ProdMI and ConsMI are not dependent.
  if (!isDependent(ProdMI, ConsMI))
    return false;

  // When Forward Scheduling is enabled, there is no stall if ProdMI and ConsMI
  // are scheduled in consecutive packets.
  if (isVecUsableNextPacket(ProdMI, ConsMI))
    return false;

  return true;
}
```

**Key insights:**
- Vector instructions have **different timing** than scalar instructions
- Vector operations can cause **pipeline stalls**
- Forward scheduling can help: vectors usable in **next packet** with special handling
- This affects when vector new-values can be used

### 4.4 Vector ALU Forwarding

**From isVecUsableNextPacket():**

```cpp
if (EnableALUForwarding && (isVecALU(ConsMI) || isLateSourceInstr(ConsMI)))
  return true;

if (mayBeNewStore(ConsMI))
  return true;
```

**Vector-specific forwarding rules:**
- Vector ALU operations can use forwarding when enabled
- Late-source instructions have special handling
- New-value stores have different timing

---

## 5. Predicate Register New-Value Rules

### 5.1 General Predicate .new Rules

**From canPromoteToDotNew():**

```cpp
// predicate .new
if (RC == &Hexagon::PredRegsRegClass)
  return HII->predCanBeUsedAsDotNew(PI, DepReg);
```

Predicate registers have their own rules for `.new` usage.

### 5.2 Vector Store + Predicate .new Restriction

As documented in section 4.2, the combination is **explicitly prohibited**:
- Vector stores cannot use `.new` predicates
- This is a fundamental architectural limitation

### 5.3 Predicate Anti-Dependency

**From restrictingDepExistInPacket():**

```cpp
// Go through the packet instructions and search for an anti dependency between
// them and DepReg from MI. Consider this case:
// Trying to add
// a) %r1 = TFRI_cdNotPt %p3, 2
// to this packet:
// {
//   b) %p0 = C2_or killed %p3, killed %p0
//   c) %p3 = C2_tfrrp %r23
//   d) %r1 = C2_cmovenewit %p3, 4
//  }
// The P3 from a) and d) will be complements after
// a)'s P3 is converted to .new form
// Anti-dep between c) and b) is irrelevant for this case
```

Predicate anti-dependencies must be carefully analyzed to prevent semantic changes.

---

## 6. Implicit Dependency Restrictions

**From isImplicitDependency():**

```cpp
static bool isImplicitDependency(const MachineInstr &I, bool CheckDef,
      unsigned DepReg) {
  for (auto &MO : I.operands()) {
    if (CheckDef && MO.isRegMask() && MO.clobbersPhysReg(DepReg))
      return true;
    if (!MO.isReg() || MO.getReg() != DepReg || !MO.isImplicit())
      continue;
    if (CheckDef == MO.isDef())
      return true;
  }
  return false;
}
```

**In canPromoteToDotNew():**
```cpp
// If dependency is through an implicitly defined register, we should not
// newify the use.
if (isImplicitDependency(PI, true, DepReg) ||
    isImplicitDependency(MI, false, DepReg))
  return false;
```

**Rule:** Instructions with implicit definitions or uses of the dependency register cannot use new-values.

---

## 7. Inline Assembly Restrictions

**From canPromoteToDotNew():**

```cpp
// The "new value" cannot come from inline asm.
if (PI.isInlineAsm())
  return false;
```

**Rule:** Inline assembly cannot produce new values because:
- Compiler cannot analyze timing
- Unknown side effects
- Cannot verify correctness

---

## 8. Hardware Loop Restrictions

**From isBadForLoopN():**

```cpp
// \ref-manual (7.3.4) A loop setup packet in loopN or spNloop0 cannot
// contain a speculative indirect jump,
// a new-value compare jump or a dealloc_return.
auto isBadForLoopN = [this] (const MachineInstr &MI) -> bool {
  if (MI.isCall() || HII->isDeallocRet(MI) || HII->isNewValueJump(MI))
    return true;
```

**Rule:** Loop setup packets (loop0, loop1) cannot contain:
- New-value compare jumps
- Speculative indirect jumps
- dealloc_return instructions

**Reference:** Hexagon Programmer's Reference Manual section 7.3.4

---

## 9. Resource Availability Check

**From canPromoteToDotNew():**

```cpp
// Create a dot new machine instruction to see if resources can be
// allocated. If not, bail out now.
int NewOpcode = (RC != &Hexagon::PredRegsRegClass) ? HII->getDotNewOp(MI) :
  HII->getDotNewPredOp(MI, MBPI);
const MCInstrDesc &D = HII->get(NewOpcode);
MachineInstr *NewMI = MF.CreateMachineInstr(D, DebugLoc());
bool ResourcesAvailable = ResourceTracker->canReserveResources(*NewMI);
MF.deleteMachineInstr(NewMI);
if (!ResourcesAvailable)
  return false;
```

**Rule:** New-value instructions require specific execution resources:
- Must check if resources are available in the packet
- Different instruction types use different execution slots
- New-value variants may use different slots than base instructions

---

## 10. Summary of Restrictions

### 10.1 Scalar Register (R0-R31) Restrictions

**CAN produce/consume new values:**
- ✓ 32-bit integer registers (R0-R31)
- ✓ Non-predicated instructions
- ✓ Non-floating-point operations
- ✓ Instructions in IntRegs class

**CANNOT produce/consume new values:**
- ✗ 64-bit double registers (D0-D15)
- ✗ Predicated instructions (as producers)
- ✗ Floating-point instructions
- ✗ Solo instructions
- ✗ Inline assembly
- ✗ KILL pseudo-instructions
- ✗ Implicit definitions
- ✗ Post-increment base registers (for stores)
- ✗ Instructions with WAR hazards
- ✗ When another store exists in packet (for NV stores)
- ✗ When stores/calls exist in dependency path

### 10.2 Vector Register (HVX) Restrictions

**CAN produce/consume new values:**
- ✓ Single vector registers (standard width)
- ✓ Vector stores (as new-value stores)
- ✓ Vector ALU operations (with forwarding)

**CANNOT or RESTRICTED:**
- ✗ Vector double registers (HvxWR) - problematic/disabled
- ✗ Vector stores with `.new` predicates (fundamental restriction)
- ⚠ Vector operations may cause pipeline stalls
- ⚠ May require special forward scheduling

### 10.3 Predicate Register (P0-P3) Restrictions

**CAN produce/consume new values:**
- ✓ Predicate registers can use `.new` suffix
- ✓ Standard scalar operations can use `.new` predicates

**CANNOT:**
- ✗ Vector stores cannot use `.new` predicates
- ⚠ Must check for anti-dependencies

### 10.4 Special Context Restrictions

**Loop setup packets (loop0/loop1):**
- ✗ Cannot contain new-value jumps
- ✗ Cannot contain dealloc_return
- ✗ Cannot contain speculative indirect jumps

**New-value stores:**
- ✗ Only ONE store per packet when using NV store
- ✗ No dual stores with new-value stores
- ✗ Post-increment register cannot be the new value

---

## 11. Practical Examples

### 11.1 Valid Scalar New-Value Patterns

```assembly
# Example 1: Basic new-value use
{
  r1 = add(r2, r3)
  r4 = sub(r5, r1.new)
  r6 = and(r7, r1.new)
}

# Example 2: New-value store
{
  r1 = add(r2, r3)
  memw(r10) = r1.new
}

# Example 3: New-value predicate
{
  p0 = cmp.gt(r1, r2)
  if (p0.new) r3 = add(r4, r5)
}

# Example 4: New-value jump
{
  r1 = add(r2, r3)
  if (cmp.gt(r1.new, #0)) jump .label
}
```

### 11.2 Invalid Scalar New-Value Patterns

```assembly
# INVALID Example 1: Double register producer
{
  r1:0 = add(r3:2, r5:4)
  r6 = add(r7, r0.new)      # ERROR: D0 (r1:0) cannot produce .new
}

# INVALID Example 2: Multiple stores
{
  r1 = add(r2, r3)
  memw(r10) = r1.new
  memw(r11) = r4            # ERROR: Two stores in packet
}

# INVALID Example 3: Predicated producer
{
  if (p0) r1 = add(r2, r3)  # ERROR: Predicated
  r4 = sub(r5, r1.new)      # Cannot use .new from predicated producer
}

# INVALID Example 4: Post-increment conflict
{
  r1 = add(r1, #4)
  memw(r10) = r1.new        # ERROR: r1 used as post-inc base
}
```

### 11.3 Valid Vector New-Value Patterns

```assembly
# Example 1: Vector new-value store
{
  v1 = vadd(v2, v3)
  vmem(r0) = v1.new
}

# Example 2: Vector with non-.new predicate
{
  v1 = vadd(v2, v3)
  if (p0) vmem(r0) = v1.new    # OK: predicate is not .new
}
```

### 11.4 Invalid Vector New-Value Patterns

```assembly
# INVALID Example 1: Vector store with .new predicate
{
  p0 = vcmp.gt(v1, v2)
  if (p0.new) vmem(r0) = v3.new   # ERROR: .new predicate on vector store
}

# INVALID Example 2: Vector double register (if disabled)
{
  v1:0 = vcombine(v2, v3)
  vmem(r0) = v0.new          # ERROR: Double vector register
}
```

---

## 12. Implementation Guidelines for Ghidra

### 12.1 Disassembly Considerations

When implementing Hexagon disassembly in Ghidra:

1. **Detect `.new` suffix** on operands
2. **Validate packet context** - check if producer exists in same packet
3. **Flag violations** of restrictions as warnings or errors
4. **Display packet boundaries** clearly to show parallel execution

### 12.2 Analysis Considerations

When performing data flow analysis:

1. **Track new-value dependencies** within packets
2. **Recognize that `.new` values bypass register file** - different data flow
3. **Check restriction violations** that might indicate:
   - Corrupted code
   - Incompatible architecture version
   - Hand-written assembly errors

4. **Special handling for vector operations** - different timing model

### 12.3 Decompilation Considerations

When generating high-level code:

1. **Merge new-value operations** into single expressions where possible
2. **Maintain packet boundaries** that affect correctness
3. **Handle vector operations specially** due to timing restrictions
4. **Document restrictions** in comments for complex patterns

---

## 13. References

### 13.1 LLVM Source Files Examined

- `HexagonVLIWPacketizer.cpp` - Packetization and new-value promotion
- `HexagonNewValueJump.cpp` - New-value jump optimization
- `HexagonInstrInfo.cpp` - Instruction classification and queries
- `HexagonInstrInfo.h` - Instruction query interfaces
- `HexagonInstrFormats.td` - Instruction format definitions
- `HexagonBaseInfo.h` - TSFlags and instruction properties

### 13.2 Hexagon Architecture References

- **Hexagon Programmer's Reference Manual**
  - Section 3.4.4.2 - New-value store restrictions
  - Section 5.4.2.2 - Double register restrictions  
  - Section 5.4.2.3 - Packet store restrictions
  - Section 5.5 - Execution slot requirements
  - Section 7.3.4 - Hardware loop restrictions

### 13.3 Key Architectural Constraints

1. **Double registers cannot produce new values** (PRM 5.4.2.2)
2. **Only one store per packet with new-value stores** (PRM 3.4.4.2, 5.4.2.3)
3. **Vector stores cannot use .new predicates** (implementation-specific)
4. **Loop setup packets restrict new-value jumps** (PRM 7.3.4)

---

**Document prepared through detailed examination of LLVM Project source code**  
**Repository:** https://github.com/llvm/llvm-project  
**Path:** llvm/lib/Target/Hexagon/
