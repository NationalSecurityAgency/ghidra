# Hexagon Conditional Execution and New-Value Interactions
## Detailed Analysis of Predicated Instructions with New-Value Stores

**Date:** January 6, 2026  
**Source:** LLVM Project (llvm/lib/Target/Hexagon/HexagonVLIWPacketizer.cpp)  
**Purpose:** Answer specific questions about conditional register updates and new-value access

---

## Executive Summary

### Key Questions Answered:

**Q1: When a conditional instruction updates a scalar register, does the new value store get updated?**

**A1: YES, but only if BOTH instructions have matching predicates.**

The new-value register **is updated** when the conditional instruction executes (i.e., when its predicate evaluates to true). However, for a new-value store to be valid, **both the producer and the consumer must be predicated on the exact same condition.**

---

**Q2: If there are two instructions within the same packet with opposite conditions which update the same register, what restrictions exist?**

**A2: They CAN coexist in the same packet, but with strict restrictions:**

1. **The instructions must use COMPLEMENT predicates** (e.g., `if (p0)` vs `if (!p0)`)
2. **Both must use the same .new/.old form** (both `.new` or both `.old`)
3. **They cannot both feed a new-value operation** in the same packet
4. **Special transitive dependency rules apply** to prevent certain patterns

---

**Q3: How does the new value get accessed within the same packet?**

**A3: Through strict predicate matching rules:**

When a conditional instruction produces a value that will be used as a new-value in the same packet:
- **Producer and consumer must use the SAME predicate register** (e.g., both use `p0`)
- **Producer and consumer must use the SAME predicate sense** (both true or both false)
- **Producer and consumer must use the SAME .new/.old form** (both `.new` or both `.old`)

The hardware ensures that the new-value forwarding only occurs when the predicates match, guaranteeing correctness.

---

## 1. Architectural Background

### 1.1 Conditional Execution in Hexagon

Hexagon supports **predicated execution** where instructions can be conditionally executed based on predicate registers (P0-P3):

```assembly
if (p0) r1 = add(r2, r3)      // Execute only if p0 is true
if (!p0) r1 = add(r4, r5)     // Execute only if p0 is false
```

Both instructions can be in the same packet and will execute in parallel, but only one will actually write its result.

### 1.2 Predicate Forms

Instructions can use two forms of predicates:

1. **`.old` form** (default): Uses the predicate value from a previous packet
   ```assembly
   {
     p0 = cmp.gt(r1, r2)
   }
   {
     if (p0) r3 = add(r4, r5)   // Uses p0 from previous packet
   }
   ```

2. **`.new` form**: Uses the predicate value from the current packet
   ```assembly
   {
     p0 = cmp.gt(r1, r2)
     if (p0.new) r3 = add(r4, r5)   // Uses p0 from same packet
   }
   ```

---

## 2. Conditional Instructions and New-Value Stores

### 2.1 The Core Rule (Arch Spec 5.4.2.3)

**From the LLVM source code comments:**

> "If the instruction that sets the new-value register is conditional, then the instruction that uses the new-value register must also be conditional, and both must always have their predicates evaluate identically."

### 2.2 Detailed Requirements

**From `canPromoteToNewValueStore()` in HexagonVLIWPacketizer.cpp:**

```cpp
// If the source that feeds the store is predicated, new value store must
// also be predicated.
if (HII->isPredicated(PacketMI)) {
  if (!HII->isPredicated(MI))
    return false;
  
  // New-value register producer and user (store) need to satisfy these
  // constraints:
  // 1) Both instructions should be predicated on the same register.
  // 2) If producer of the new-value register is .new predicated then store
  // should also be .new predicated and if producer is not .new predicated
  // then store should not be .new predicated.
  // 3) Both new-value register producer and user should have same predicate
  // sense, i.e, either both should be negated or both should be non-negated.
  
  if (predRegNumDst != predRegNumSrc ||
      HII->isDotNewInst(PacketMI) != HII->isDotNewInst(MI) ||
      getPredicateSense(MI, HII) != getPredicateSense(PacketMI, HII))
    return false;
}
```

### 2.3 What This Means

For a conditional instruction to produce a new-value that's used in a new-value store:

| Requirement | Description | Example |
|-------------|-------------|---------|
| **Same Predicate Register** | Both must use the same predicate (e.g., both use `p0`) | ✓ `if (p0)` ... `if (p0)` |
| **Same .new/.old Form** | Both must be `.new` or both must be `.old` | ✓ Both use `p0.new` OR both use `p0` |
| **Same Sense** | Both must be true or both must be false | ✓ Both `if (p0)` OR both `if (!p0)` |

### 2.4 Valid Examples

#### Example 1: Both predicated, same conditions
```assembly
{
  if (p0) r1 = add(r2, r3)        // Producer: predicated on p0 (true)
  if (p0) memw(r10) = r1.new      // Consumer: predicated on p0 (true)
}
```
✅ **VALID**: Same predicate register, same sense (true), same .old form

#### Example 2: Both with .new predicate
```assembly
{
  p0 = cmp.gt(r5, r6)
  if (p0.new) r1 = add(r2, r3)    // Producer: predicated on p0.new
  if (p0.new) memw(r10) = r1.new  // Consumer: predicated on p0.new
}
```
✅ **VALID**: Same predicate register, same sense, same .new form

#### Example 3: Both with negated predicate
```assembly
{
  if (!p0) r1 = add(r2, r3)       // Producer: predicated on !p0
  if (!p0) memw(r10) = r1.new     // Consumer: predicated on !p0
}
```
✅ **VALID**: Same predicate register, same sense (false), same .old form

### 2.5 Invalid Examples

#### Example 1: Mismatched predicates
```assembly
{
  if (p0) r1 = add(r2, r3)        // Producer: p0
  if (p1) memw(r10) = r1.new      // Consumer: p1
}
```
❌ **INVALID**: Different predicate registers

#### Example 2: Mismatched sense
```assembly
{
  if (p0) r1 = add(r2, r3)        // Producer: p0 (true)
  if (!p0) memw(r10) = r1.new     // Consumer: !p0 (false)
}
```
❌ **INVALID**: Different predicate sense

#### Example 3: Mismatched .new/.old form
```assembly
{
  p0 = cmp.gt(r5, r6)
  if (p0.new) r1 = add(r2, r3)    // Producer: p0.new
  if (p0) memw(r10) = r1.new      // Consumer: p0 (old)
}
```
❌ **INVALID**: Different .new/.old form

#### Example 4: Producer predicated, consumer not
```assembly
{
  if (p0) r1 = add(r2, r3)        // Producer: predicated
  memw(r10) = r1.new              // Consumer: unconditional
}
```
❌ **INVALID**: Producer is predicated but consumer is not

---

## 3. Opposite Predicates in Same Packet

### 3.1 The Complement Predicates Scenario

When two instructions in the same packet update the same register with **complement** (opposite) predicates:

```assembly
{
  if (p0) r1 = add(r2, r3)      // Updates r1 if p0 is true
  if (!p0) r1 = sub(r4, r5)     // Updates r1 if p0 is false
}
```

### 3.2 Why This Is Allowed

**From `arePredicatesComplements()` logic:**

The architecture allows this because:
1. **Mutually exclusive execution**: Only ONE instruction will actually execute
2. **No data race**: At most one write to r1 will occur
3. **Deterministic result**: The final value of r1 is well-defined

**From the packetizer code:**
```cpp
// For predicated instructions, if the predicates are complements then
// there can be no dependence.
if (HII->isPredicated(I) && HII->isPredicated(J) &&
    arePredicatesComplements(I, J)) {
  // ... allow packetization
  continue;
}
```

### 3.3 Requirements for Complement Predicates

**From `arePredicatesComplements()`:**

Two instructions have complement predicates if:
1. **Same predicate register**: Both use the same predicate (e.g., `p0`)
2. **Opposite sense**: One uses true, the other false (e.g., `p0` vs `!p0`)
3. **Same .new/.old form**: Both use `.new` or both use `.old`

```cpp
return PReg1 == PReg2 &&
       Hexagon::PredRegsRegClass.contains(PReg1) &&
       Hexagon::PredRegsRegClass.contains(PReg2) &&
       getPredicateSense(MI1, HII) != getPredicateSense(MI2, HII) &&
       HII->isDotNewInst(MI1) == HII->isDotNewInst(MI2);
```

### 3.4 Valid Complement Examples

#### Example 1: Simple complement
```assembly
{
  if (p0) r1 = #10       // True branch
  if (!p0) r1 = #20      // False branch
}
```
✅ **VALID**: Complement predicates, same register

#### Example 2: Complement with .new
```assembly
{
  p0 = cmp.gt(r5, r6)
  if (p0.new) r1 = add(r2, r3)
  if (!p0.new) r1 = sub(r2, r3)
}
```
✅ **VALID**: Complement predicates with .new form

### 3.5 The Critical Corner Case

**From the LLVM comments - the "corner case":**

```assembly
# Trying to add:
a) r24 = tfrt p0, r25          # Transfer if p0 true

# To this packet:
{
  b) r25 = tfrf p0, r24        # Transfer if p0 false
  c) p0 = cmpeqi r26, 1        # Sets p0
}
```

**Why this is problematic:**
1. Initially, `a)` and `b)` appear to be complements
2. However, `c)` sets p0 in the same packet
3. This would convert `a)` to use `p0.new`
4. After conversion, `a)` would use `p0.new` but `b)` uses `p0.old`
5. **They are no longer complements!**

**The solution:**
The packetizer checks for **anti-dependencies** on the predicate register. If instruction `c)` has a true data dependency to the candidate and there's an anti-dependency in the packet, the complementarity check fails.

```cpp
// Check if there is an anti dependency from c) to any other instruction 
// in the same packet on the pred reg of interest.
if (restrictingDepExistInPacket(*I, Dep.getReg()))
  return false;
```

### 3.6 Transitive Dependency Limitation

**From the packetizer code:**

```cpp
// Not always safe to do this translation.
// DAG Builder attempts to reduce dependence edges using transitive
// nature of dependencies. Here is an example:
//
// r0 = tfr_pt ... (1)
// r0 = tfr_pf ... (2)
// r0 = tfr_pt ... (3)
//
// There will be an output dependence between (1)->(2) and (2)->(3).
// However, there is no dependence edge between (1)->(3). This results
// in all 3 instructions going in the same packet. We ignore dependence
// only once to avoid this situation.
```

**The rule:**
When complement predicates allow ignoring a dependency, **it can only be done once per packet**. This prevents three instructions with alternating predicates from being incorrectly packetized together.

---

## 4. Accessing New Values with Conditional Instructions

### 4.1 How Hardware Handles It

When both producer and consumer are predicated with matching conditions:

1. **Predicate evaluation**: Both predicates evaluate to the same value
2. **Conditional forwarding**: The new-value path is only activated when both predicates are true
3. **No forwarding when predicates false**: If predicates are false, neither instruction executes

### 4.2 Example: Matching Predicates

```assembly
{
  p0 = cmp.gt(r10, r11)           // Set predicate
  if (p0.new) r1 = add(r2, r3)    // Producer: only executes if p0 true
  if (p0.new) memw(r20) = r1.new  // Consumer: only executes if p0 true
}
```

**Execution scenarios:**

| p0 value | Producer executes? | r1 updated? | Consumer executes? | Store happens? |
|----------|-------------------|-------------|-------------------|----------------|
| **true** | ✓ Yes | ✓ Yes | ✓ Yes | ✓ Yes, stores new r1 |
| **false** | ✗ No | ✗ No | ✗ No | ✗ No store |

The hardware ensures correctness because:
- When p0 is true: Both execute, new-value forwarding works
- When p0 is false: Neither executes, no forwarding needed

### 4.3 Why Mismatched Predicates Are Prohibited

```assembly
{
  if (p0) r1 = add(r2, r3)        // Producer
  if (p1) memw(r20) = r1.new      // Consumer
}
```

**This is INVALID because:**

| p0 | p1 | Producer? | Consumer? | Problem |
|----|----|-----------|-----------| --------|
| T | T | Execute | Execute | OK - would work |
| T | F | Execute | Skip | OK - no store |
| F | T | Skip | Execute | ❌ **ERROR**: Store would use undefined r1.new |
| F | F | Skip | Skip | OK - no problem |

The case where p0=false and p1=true is **undefined behavior** - the store would try to use a new-value that was never produced!

---

## 5. Summary of Rules

### 5.1 For Conditional New-Value Stores

✅ **ALLOWED** when producer and consumer have:
1. Same predicate register (both use p0, p1, p2, or p3)
2. Same predicate sense (both true OR both false)
3. Same .new/.old form (both .new OR both .old)

❌ **PROHIBITED** when:
1. Different predicate registers
2. Different predicate sense (one true, one false)
3. Different .new/.old form (one .new, one .old)
4. Producer predicated but consumer not
5. Consumer predicated but producer not

### 5.2 For Complement Predicates (Opposite Conditions)

✅ **ALLOWED** when updating same register with:
1. Same predicate register
2. Opposite sense (one true, one false)
3. Same .new/.old form
4. No predicate-defining instruction in same packet causing .new conversion

❌ **PROHIBITED** when:
1. More than two instructions with alternating predicates (transitive dependency issue)
2. Predicate-defining instruction causes .new conversion mismatch
3. Trying to use both results as new-values in same packet

### 5.3 Quick Reference Table

| Scenario | Producer | Consumer | Valid? | Reason |
|----------|----------|----------|--------|--------|
| Matching conditions | `if (p0)` | `if (p0)` + `.new` | ✅ Yes | Perfect match |
| Matching .new | `if (p0.new)` | `if (p0.new)` + `.new` | ✅ Yes | Perfect match |
| Matching negated | `if (!p0)` | `if (!p0)` + `.new` | ✅ Yes | Same sense |
| Different registers | `if (p0)` | `if (p1)` + `.new` | ❌ No | Different predicates |
| Different sense | `if (p0)` | `if (!p0)` + `.new` | ❌ No | Opposite sense |
| Mixed .new/.old | `if (p0.new)` | `if (p0)` + `.new` | ❌ No | Different forms |
| Unconditional consumer | `if (p0)` | unconditional + `.new` | ❌ No | Mismatch |
| Complement (no .new) | `if (p0)` r1=A | `if (!p0)` r1=B | ✅ Yes | Complements OK |
| Complement with .new | `if (p0.new)` r1=A | `if (!p0.new)` r1=B | ✅ Yes | Complements OK |
| Three alternating | `if (p0)` r1=A | `if (!p0)` r1=B<br>`if (p0)` r1=C | ❌ No | Transitive issue |

---

## 6. Practical Examples

### 6.1 Example: Conditional Selection with New-Value Store

**Scenario:** Store a value that depends on a condition

```assembly
{
  p0 = cmp.gt(r10, #0)              // Test if r10 > 0
  if (p0.new) r5 = add(r1, r2)      // r5 = r1 + r2 if positive
  if (p0.new) memw(r20) = r5.new    // Store result if positive
}
```
✅ **VALID**: All three match on p0.new

### 6.2 Example: If-Then-Else Pattern

**Scenario:** r1 gets one of two values

```assembly
{
  p0 = cmp.eq(r2, #0)
  if (p0.new) r1 = #42              // r1 = 42 if r2 == 0
  if (!p0.new) r1 = #99             // r1 = 99 if r2 != 0
}
```
✅ **VALID**: Complement predicates, no new-value usage

**But this would be INVALID:**
```assembly
{
  p0 = cmp.eq(r2, #0)
  if (p0.new) r1 = add(r3, r4)
  if (!p0.new) r1 = sub(r5, r6)
  memw(r20) = r1.new                // ❌ Which r1.new?
}
```
❌ **INVALID**: Cannot use r1.new when r1 has complement definitions

### 6.3 Example: Cascaded Conditionals

**Scenario:** Multiple operations on same condition

```assembly
{
  p0 = cmp.gt(r10, r11)
  if (p0.new) r1 = add(r2, r3)
  if (p0.new) r4 = add(r1.new, r5)  // Use previous result
  if (p0.new) memw(r20) = r4.new    // Store final result
}
```
✅ **VALID**: All instructions match on p0.new, new-values cascade correctly

### 6.4 Example: Predicate Modified in Packet

**Dangerous pattern:**
```assembly
{
  if (p0) r1 = add(r2, r3)          // Uses p0.old
  p0 = cmp.gt(r4, r5)               // Modifies p0
  if (p0.new) r6 = add(r1.new, r7)  // Uses p0.new
}
```

This creates complexity because:
- First instruction uses `p0.old` (from previous packet)
- Third instruction uses `p0.new` (from current packet)
- They reference **different** predicate values!

The packetizer must carefully analyze such cases.

---

## 7. Implementation Guidance for Ghidra

### 7.1 Disassembly Considerations

When disassembling Hexagon code with conditional new-values:

1. **Check predicate matching**: Verify producer and consumer have matching predicates
2. **Flag violations**: Highlight any mismatches as potential errors
3. **Show packet context**: Display full packet to show predicate relationships
4. **Annotate .new/.old**: Clearly distinguish between `.new` and `.old` forms

### 7.2 Data Flow Analysis

When analyzing data flow:

1. **Conditional new-value edges**: Create data flow edges only when predicates match
2. **Complement handling**: Recognize that complement predicates mean "at most one executes"
3. **Predicate definitions**: Track where predicates are defined in packets
4. **Multiple definitions**: Handle cases where a register has multiple conditional definitions

### 7.3 Decompilation Strategies

When decompiling to high-level code:

**For matching predicates:**
```assembly
{
  if (p0.new) r1 = add(r2, r3)
  if (p0.new) memw(r20) = r1.new
}
```
Could decompile to:
```c
if (condition) {
  temp = r2 + r3;
  *r20 = temp;
}
```

**For complement predicates:**
```assembly
{
  if (p0.new) r1 = add(r2, r3)
  if (!p0.new) r1 = sub(r4, r5)
}
```
Could decompile to:
```c
r1 = condition ? (r2 + r3) : (r4 - r5);
```

---

## 8. References

### 8.1 LLVM Source Files

- **HexagonVLIWPacketizer.cpp**
  - `canPromoteToNewValueStore()` - Lines documenting conditional constraints
  - `arePredicatesComplements()` - Complement predicate detection
  - `getPredicateSense()` - Predicate sense determination
  - `restrictingDepExistInPacket()` - Anti-dependency checking

### 8.2 Hexagon Architecture Manual References

- **Section 5.4.2.3**: "If the instruction that sets the new-value register is conditional..."
- **Section 5.4.2.1**: Auto-increment and absolute-set restrictions
- **Section 5.4.2.2**: Double register restrictions
- **Section 3.4.4.2**: Store coexistence restrictions

### 8.3 Key Constraints Summary

1. **Arch Spec 5.4.2.3**: Conditional producer requires matching conditional consumer
2. **Same predicate register**: Both must use same p0/p1/p2/p3
3. **Same .new/.old form**: Both must be .new or both must be .old
4. **Same sense**: Both true or both false
5. **Complement allowance**: Opposite sense allowed for definitions, but not for new-value use
6. **Transitive limitation**: Complement dependency-ignoring only works once per packet

---

## Conclusion

The Hexagon architecture's handling of conditional instructions with new-values is sophisticated and has strict rules:

1. **Conditional new-values require matching predicates** - producer and consumer must be identically predicated
2. **Complement predicates can update the same register** - but cannot both feed new-value operations
3. **The hardware enforces correctness** through predicate evaluation that controls both execution and forwarding

These rules ensure that new-value forwarding never accesses undefined or incorrect values, maintaining the correctness of the VLIW parallel execution model even with conditional operations.

---

**Document prepared through examination of LLVM Project source code**  
**Repository:** https://github.com/llvm/llvm-project  
**Path:** llvm/lib/Target/Hexagon/HexagonVLIWPacketizer.cpp
