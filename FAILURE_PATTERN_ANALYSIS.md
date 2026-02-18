# Failure Pattern Analysis - Iteration 3 Results

## 📊 Overall Statistics

**Total indirect calls analyzed:** 7,525  
**Successfully resolved:** 0 (0%)  
**Failed to resolve:** 7,525 (100%)

---

## 🎯 Failure Pattern Breakdown

### Top 20 Failure Patterns

| Count | % | Pattern | Type |
|-------|---|---------|------|
| 3,671 | 48.8% | No lw instruction found within 100 instructions | **Distance** |
| 288 | 3.8% | Register-relative load: 0x10(sp) | **Stack** |
| 275 | 3.7% | Register-relative load: 0x18(sp) | **Stack** |
| 275 | 3.7% | Register-relative load: 0x14(sp) | **Stack** |
| 84 | 1.1% | Register-relative load: 0x20(sp) | **Stack** |
| 72 | 1.0% | Register-relative load: 0x1c(sp) | **Stack** |
| 37 | 0.5% | Register-relative load: 0x4(v0) | **Return value** |
| 33 | 0.4% | Register-relative load: 0x8(v0) | **Return value** |
| 33 | 0.4% | Register-relative load: 0x0(v0) | **Return value** |
| 31 | 0.4% | Register-relative load: 0x34(sp) | **Stack** |
| 31 | 0.4% | Register-relative load: 0x28(sp) | **Stack** |
| 30 | 0.4% | Register-relative load: 0xc(sp) | **Stack** |
| 26 | 0.3% | Register-relative load: 0x24(sp) | **Stack** |
| 26 | 0.3% | Register-relative load: 0x0(s1) | **Saved reg** |
| 21 | 0.3% | Register-relative load: 0x40(sp) | **Stack** |
| 20 | 0.3% | Register-relative load: 0x0(s2) | **Saved reg** |
| 18 | 0.2% | Register-relative load: 0x38(sp) | **Stack** |
| 17 | 0.2% | Register-relative load: 0x78(sp) | **Stack** |
| 17 | 0.2% | Register-relative load: 0x30(sp) | **Stack** |
| 16 | 0.2% | Register-relative load: 0x230(s0) | **Saved reg** |

**Remaining patterns:** ~2,500 (33%) - Various other register-relative loads

---

## 📈 Pattern Categories

### Category 1: Distance Issues (48.8%)
**Pattern:** "No lw instruction found within 100 instructions"  
**Count:** 3,671 (48.8%)

**Root cause:**
- The `lw` instruction is >100 instructions before the `jalr`/`jr`
- OR the register wasn't loaded by `lw` at all (e.g., function argument, computed value)

**Solutions:**
1. **Increase search limit** to 200-300 instructions
2. **Use SymbolicPropagator** for unlimited backward tracking
3. **Check function parameters** - register might be a function argument

**Priority:** 🔥 **HIGH** - Affects nearly half of all failures

**Quick win:** Increase search limit from 100 to 300

---

### Category 2: Stack-Relative Loads (12.5%)
**Pattern:** `lw $reg, offset($sp)`  
**Count:** ~940 (12.5%)

**Examples:**
- `lw s0, 0x10(sp)` - 288 occurrences
- `lw s0, 0x18(sp)` - 275 occurrences
- `lw s0, 0x14(sp)` - 275 occurrences
- Many more with different offsets

**Root cause:**
Function pointer is stored on the stack, either:
1. **Local variable** - Saved to stack in function prologue
2. **Function parameter** - Arguments 5+ are passed on stack in MIPS O32 ABI
3. **Spilled register** - Compiler saved a register to stack

**Example assembly:**
```assembly
# Function prologue
addiu   $sp, $sp, -0x50      # Allocate stack frame
sw      $s0, 0x10($sp)       # Save $s0 to stack
...
# Later in function
lw      $s0, 0x10($sp)       # Restore $s0 from stack
jalr    $s0                  # Call function pointer
```

**Solutions:**
1. **Track stack stores** - Find `sw` instruction that wrote to `offset($sp)`
2. **Follow the value** - Track what was stored
3. **Check function parameters** - If offset is in parameter area, it's an argument

**Priority:** 🔥 **MEDIUM-HIGH** - Affects 12.5%, potentially resolvable

**Complexity:** Medium - Requires tracking `sw` instructions

---

### Category 3: Return Value Loads (1.3%)
**Pattern:** `lw $reg, offset($v0)`  
**Count:** ~103 (1.3%)

**Examples:**
- `lw $t9, 0x4($v0)` - 37 occurrences
- `lw $t9, 0x8($v0)` - 33 occurrences
- `lw $t9, 0x0($v0)` - 33 occurrences

**Root cause:**
Function returns a pointer to a struct, then we load a function pointer from that struct.

**Example assembly:**
```assembly
jal     get_device           # Returns device pointer in $v0
nop
lw      $t9, 0x8($v0)       # Load function pointer from device->ops
jalr    $t9                  # Call the function pointer
```

**Solutions:**
1. **Track function return values** - Analyze what the previous function returns
2. **Use SymbolicPropagator** - Track $v0 through the call
3. **Pattern matching** - Detect common patterns like `jal` followed by `lw $reg, offset($v0)`

**Priority:** 🟡 **MEDIUM** - Affects 1.3%, complex to implement

**Complexity:** High - Requires inter-procedural analysis

---

### Category 4: Saved Register Loads (0.9%)
**Pattern:** `lw $reg, offset($s0-$s7)`  
**Count:** ~70 (0.9%)

**Examples:**
- `lw $t9, 0x0($s1)` - 26 occurrences
- `lw $t9, 0x0($s2)` - 20 occurrences
- `lw $t9, 0x230($s0)` - 16 occurrences

**Root cause:**
Saved register holds a pointer to a struct, and we're loading a function pointer from that struct.

**Example assembly:**
```assembly
# $s0 holds device pointer throughout function
lw      $t9, 0x230($s0)     # Load function pointer from device->callback
jalr    $t9                  # Call the callback
```

**Solutions:**
1. **Track saved register values** - Find where $s0-$s7 were loaded
2. **Multi-level tracking** - Track through multiple `lw` instructions
3. **Use SymbolicPropagator** - Full data flow analysis

**Priority:** 🟡 **MEDIUM** - Affects 0.9%, requires multi-level tracking

**Complexity:** Medium-High - Requires tracking register values across function

---

### Category 5: Other Register-Relative (36.5%)
**Pattern:** Various other `lw $reg, offset($base)` patterns  
**Count:** ~2,750 (36.5%)

**Examples:**
- `lw $t9, 0x1c($a0)` - Your test case pattern
- `lw $t9, offset($gp)` - Global pointer relative
- Many others

**Root cause:**
Complex patterns that require sophisticated tracking.

**Priority:** 🟢 **LOW-MEDIUM** - Many different patterns, each requires specific handling

---

## 🎯 Recommended Priority Order

### Priority 1: Increase Search Limit (Quick Win)
**Impact:** Could resolve up to 48.8% of current "No lw found" failures  
**Effort:** 5 minutes  
**Code change:** Change `searchLimit` from 100 to 300

**Expected result:** Many "No lw found" will become register-relative failures, giving us better data

---

### Priority 2: Stack-Relative Tracking
**Impact:** Could resolve up to 12.5% of failures  
**Effort:** 2-4 hours  
**Complexity:** Medium

**Implementation:**
1. Detect `lw $reg, offset($sp)` pattern
2. Search backward for `sw $source, offset($sp)`
3. Track the `$source` register value
4. Recursively resolve

**Example:**
```assembly
lw      $s0, offset($gp)     # Load from global
sw      $s0, 0x10($sp)       # Store to stack
...
lw      $t9, 0x10($sp)       # Load from stack
jalr    $t9                  # Call
```

**Benefit:** Stack loads are common and often traceable

---

### Priority 3: Global Pointer ($gp) Resolution
**Impact:** Unknown (need better data after Priority 1)  
**Effort:** 1-2 hours  
**Complexity:** Low-Medium

**Implementation:**
1. Get $gp value from program context
2. For `lw $reg, offset($gp)`, calculate address = $gp + offset
3. Read function pointer from memory
4. Create reference

**Benefit:** $gp-relative loads are common in MIPS and should be easy to resolve

---

### Priority 4: Multi-Level Tracking
**Impact:** Could resolve 10-20% of failures  
**Effort:** 4-8 hours  
**Complexity:** High

**Implementation:**
Use SymbolicPropagator with ContextEvaluator for full data flow analysis.

**Benefit:** Handles complex patterns automatically

---

## 📊 Expected Results After Priority 1 (Increase Search Limit)

### Current:
```
3,671 (48.8%) - No lw instruction found within 100 instructions
```

### After increasing to 300:
```
~1,000 (13%) - No lw instruction found within 300 instructions
~2,671 (35%) - Register-relative load: ... (newly discovered patterns)
```

**Benefit:** Better understanding of actual failure patterns

---

## 🔍 Specific Examples from Logs

### Example 1: Stack Load Pattern
```
INFO  Found jalr call at 00043f64
INFO    Found lw at 00043ddc: lw s0,0x38(sp)
INFO    Register-relative load: 0x38(sp) (base=sp)
INFO    Failure: Register-relative load: 0x38(sp) (base=sp)
```

**What we need to do:**
1. Find `sw $source, 0x38($sp)` before address 0x43ddc
2. Track what's in `$source`
3. Resolve the function pointer

---

### Example 2: Multiple Calls, Same Register
```
INFO  Found jalr call at 00044318
INFO    Found lw at 000442ac: lw s0,0x14(sp)
INFO  Found jalr call at 0004433c
INFO    Found lw at 000442ac: lw s0,0x14(sp)
INFO  Found jalr call at 0004437c
INFO    Found lw at 000442ac: lw s0,0x14(sp)
```

**Pattern:** Same `lw` instruction found for multiple calls  
**Meaning:** Register loaded once, used multiple times (our fix is working!)  
**Issue:** Still can't resolve because it's stack-relative

---

### Example 3: Distance Issue
```
INFO  Found jalr call at 00044024
INFO    Failure: No lw instruction found within 100 instructions
```

**What we need to do:**
1. Increase search limit
2. Find the actual `lw` instruction
3. Determine why it's so far away

---

## ✅ Success Metrics

### Minimum Success (Priority 1 only):
- [ ] Search limit increased to 300
- [ ] "No lw found" reduced from 48.8% to <20%
- [ ] Better visibility into actual patterns

### Good Success (Priority 1 + 2):
- [ ] Stack-relative tracking implemented
- [ ] 5-10% of indirect calls resolved
- [ ] Clear pattern distribution

### Excellent Success (Priority 1 + 2 + 3):
- [ ] $gp resolution implemented
- [ ] 10-20% of indirect calls resolved
- [ ] Most common patterns handled

---

## 🚀 Next Steps

1. **Increase search limit** (5 minutes)
2. **Rebuild and re-analyze** (10 minutes)
3. **Analyze new failure patterns** (5 minutes)
4. **Implement stack tracking** (2-4 hours)
5. **Implement $gp resolution** (1-2 hours)

---

## 📝 Key Insights

1. **Distance is the #1 issue** - Nearly half of failures are just "didn't search far enough"
2. **Stack loads are common** - 12.5% of failures, potentially resolvable
3. **Our bug fix worked!** - We're now finding the `lw` instructions (see Example 2)
4. **Still 0 resolutions** - Because all found patterns are register-relative
5. **Need multi-level tracking** - Most patterns require tracking through multiple instructions

---

**Status:** 📊 Analysis complete  
**Next:** Implement Priority 1 (increase search limit)  
**Expected impact:** 🔥 Better data for next iteration

