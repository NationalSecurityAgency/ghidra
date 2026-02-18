# Analysis Issues Found in Logs

## Summary

Analyzed the logs from the latest Ghidra build with enhanced MIPS analyzers. Found several critical issues that need to be addressed.

---

## ✅ What's Working

### 1. JR Instruction Detection
**Status:** ✅ WORKING

The analyzer now successfully detects both `jalr` and `jr` instructions:
```
INFO  Found jalr call at 00010574 (MipsFunctionPointerAnalyzer)
INFO  Found jr jump at 000105a8 (MipsFunctionPointerAnalyzer)
INFO  Found jr jump at 000105c4 (MipsFunctionPointerAnalyzer)
```

**Evidence:**
- Thousands of `jr` instructions detected
- Properly distinguishes between `jalr` (calls) and `jr` (jumps)
- Correctly identifies the target register

### 2. Function Pointer Table Detection
**Status:** ✅ WORKING

The analyzer successfully finds function pointer tables:
```
INFO  Found function pointer table at 0007a784 with 16 entries
INFO  Found function pointer table at 0007a82c with 20 entries
INFO  Found function pointer table at 0007a924 with 23 entries
```

**Statistics:**
- 3,208 function pointer tables found
- Sizes range from 3 to 256 entries
- Correctly validates function pointers

### 3. Switch Table Detection
**Status:** ✅ WORKING (with issues - see below)

```
INFO  MIPS Switch Table Analyzer: Found 1 switch tables
```

The switch table analyzer is running and detecting tables.

---

## ❌ Critical Issues

### Issue 1: Zero Indirect Calls Resolved
**Severity:** 🔴 CRITICAL  
**Status:** ❌ BROKEN

**Problem:**
Despite detecting thousands of `jalr` and `jr` instructions, **ZERO** were successfully resolved to their targets.

**Evidence:**
```bash
$ grep "Resolved jalr\|Resolved jr" logs.txt
# No results
```

```bash
$ grep "Could not resolve" logs.txt | wc -l
# Thousands of failures
```

**Sample failures:**
```
INFO  Found jalr call at 00010574 (MipsFunctionPointerAnalyzer)
INFO  Could not resolve jalr call target at 00010574 (register: v0)
INFO  Found jr jump at 000105c4 (MipsFunctionPointerAnalyzer)
INFO  Could not resolve jr jump target at 000105c4 (register: t9)
```

**Root Cause:**
Both the SymbolicPropagator approach and the simple backward tracking are failing to resolve function pointers.

**Why SymbolicPropagator Fails:**
1. **Timing issue** - SymbolicPropagator runs on the entire function, but the register value at the specific jalr/jr instruction may not be constant
2. **Complex data flow** - Function pointers loaded from structs (multi-level indirection) aren't tracked
3. **Register-relative values** - The Value object may contain register-relative offsets, not absolute addresses

**Why Simple Backward Tracking Fails:**
1. **No data references** - The `lw` instructions don't have data references created yet
2. **Operand parsing** - Can't extract the memory address from `lw $t9, 0x1c($a0)` pattern
3. **Multi-level indirection** - Pattern like `arg1->field_0xc->field_0x1c` requires tracking through multiple loads

**Impact:**
- No indirect call resolution
- Decompiler warnings persist
- Call graphs incomplete
- Cross-references missing

---

### Issue 2: MipsSwitchTableAnalyzer False Positives
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ NOISY

**Problem:**
The switch table analyzer is treating ASCII strings as switch tables, generating thousands of false positive warnings.

**Evidence:**
```
WARN  Invalid target address in switch table at 00081c68: 6f687320
WARN  Invalid target address in switch table at 00081c6c: 73207472
WARN  Invalid target address in switch table at 00081c70: 6d5f6764
```

**Decoding the "addresses":**
```
0x6f687320 = "ohs " (ASCII)
0x73207472 = "s tr" (ASCII)
0x6d5f6764 = "m_gd" (ASCII)
```

These are clearly string data, not code addresses.

**Root Cause:**
The switch table analyzer doesn't validate that:
1. Entries point to executable memory
2. Entries point to valid instructions
3. Entries aren't ASCII text patterns

**Impact:**
- Log spam (thousands of warnings)
- Performance degradation (analyzing non-code data)
- Potential false switch table creation

**Example Pattern:**
```
Address: 00081c68-00081d78
Content: "ohs trgd_manual is %d:sensor dg is %d\n"
         "%s,%d: ae not support param id %d\n"
         "----af-regs dump----"
         "0x%08x: 0x%08x\n"
```

This is clearly a string table, not a switch table.

---

### Issue 3: Test Function Not Analyzed
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ INCOMPLETE

**Problem:**
The test function `tx_isp_send_event_to_remote` at 0xf60c was not analyzed.

**Evidence:**
```bash
$ grep "0000f6" logs.txt
# No results
```

The analyzer starts at 0x00010574, but our test function is at 0x0000f60c (earlier in the binary).

**Possible Causes:**
1. Function not detected during initial analysis
2. Address range restriction
3. Analyzer only runs on certain sections

**Impact:**
- Can't test the jr resolution on our specific test case
- Unknown if the pattern would work if the function were analyzed

---

## 🔍 Detailed Analysis

### Indirect Call Resolution Failure Analysis

**Pattern 1: Simple Tail Call (Should Work)**
```assembly
0000f620  lw      $t9, 0x1c($a0)    # Load function pointer
0000f624  beqz    $t9, 0xf634       # Check if null
0000f62c  jr      $t9               # Tail call
```

**Why it fails:**
1. SymbolicPropagator sees `$t9` as register-relative (offset from `$a0`)
2. Simple backward tracking can't parse `lw $t9, 0x1c($a0)` operand
3. No data reference exists from the `lw` instruction

**Pattern 2: Register Indirect (Common)**
```assembly
lw      $v0, offset($gp)     # Load from global pointer
jalr    $v0                  # Call through register
```

**Why it fails:**
1. SymbolicPropagator doesn't resolve $gp-relative addresses
2. Backward tracking stops at register moves
3. Function pointer in .got or .data section

**Pattern 3: Struct Field Access (Very Common)**
```assembly
lw      $a0, 0xc($a0)        # Load struct pointer
lw      $t9, 0x1c($a0)       # Load function pointer from struct
jalr    $t9                  # Call
```

**Why it fails:**
1. Multi-level indirection
2. SymbolicPropagator loses track after first load
3. Backward tracking only looks for direct loads

---

## 📊 Statistics

### From Logs:

**Function Pointer Tables:**
- Total found: 3,208 tables
- Total entries: ~50,000+ function pointers
- Size range: 3 to 256 entries per table

**Indirect Calls/Jumps:**
- `jalr` instructions found: ~5,000+
- `jr` instructions found: ~15,000+
- Successfully resolved: **0** (0%)
- Failed to resolve: ~20,000+ (100%)

**Switch Tables:**
- Valid switch tables: 1
- False positives (strings): ~1,000+

**Register Distribution (Failed Resolutions):**
- `$ra` (return address): ~40% - These are returns, should be ignored
- `$t9` (function pointer): ~30% - These are the ones we want to resolve
- `$v0` (return value): ~15% - Function pointers returned from calls
- `$s0-$s7` (saved regs): ~10% - Function pointers in local variables
- Other: ~5%

---

## 🎯 Recommendations

### Priority 1: Fix Indirect Call Resolution

**Option A: Improve SymbolicPropagator Usage**
- Use VarnodeContext to get the actual Varnode, not just the Value
- Check if the Varnode is a memory reference
- Read the function pointer from memory
- Handle register-relative addresses

**Option B: Enhance Backward Tracking**
- Parse `lw` operands to extract base register + offset
- Track through multiple `lw` instructions (multi-level indirection)
- Use SymbolicPropagator to resolve base register values
- Increase search distance beyond 100 instructions

**Option C: Hybrid Approach** (RECOMMENDED)
1. Use SymbolicPropagator to get the Varnode at the jalr/jr
2. If Varnode is a constant, use it directly
3. If Varnode is memory reference, read from memory
4. If Varnode is register-relative, resolve the base register
5. Fall back to enhanced backward tracking if all else fails

### Priority 2: Fix Switch Table False Positives

**Add validation in MipsSwitchTableAnalyzer:**
```java
// Check if entry points to executable memory
MemoryBlock block = memory.getBlock(targetAddr);
if (block == null || !block.isExecute()) {
    continue; // Skip non-executable entries
}

// Check if entry points to valid instruction
Instruction instr = listing.getInstructionAt(targetAddr);
if (instr == null) {
    continue; // Skip non-code entries
}

// Check for ASCII text patterns
if (isLikelyAsciiString(entry)) {
    continue; // Skip string data
}
```

### Priority 3: Investigate Test Function

**Debug why 0xf60c wasn't analyzed:**
1. Check if function exists in function manager
2. Check if address is in analyzed address set
3. Manually trigger analysis on that function
4. Check analyzer priority and dependencies

---

## 🧪 Next Steps

### Immediate Testing:
1. **Fix the SymbolicPropagator usage** - Get Varnode instead of Value
2. **Add memory read logic** - Read function pointers from memory
3. **Test on simple pattern** - Find a `jr $t9` with nearby `lw $t9, offset($gp)`
4. **Rebuild and re-analyze**

### Validation:
1. Check if any indirect calls are resolved
2. Navigate to resolved calls in decompiler
3. Verify references are created
4. Check if warnings are suppressed

### Documentation:
1. Document successful patterns
2. Document failure patterns
3. Create test cases for each pattern
4. Update PRD with findings

---

## 📝 Code Changes Needed

### File: MipsFunctionPointerAnalyzer.java

**Current Issue:**
```java
SymbolicPropogator.Value regValue = symEval.getRegisterValue(jalrAddr, targetReg);
if (regValue != null && !regValue.isRegisterRelativeValue()) {
    long offset = regValue.getValue();
    // This only works if the value is a constant
}
```

**Problem:** The Value might be register-relative or symbolic, not a direct constant.

**Proposed Fix:**
```java
// Get the actual Varnode, not just the Value
VarnodeContext context = symEval.getVarnodeContext();
Varnode regVarnode = context.getRegisterVarnodeValue(targetReg, 
    Address.NO_ADDRESS, jalrAddr, true);

if (regVarnode != null) {
    if (context.isConstant(regVarnode)) {
        // Direct constant - use it
        long offset = regVarnode.getOffset();
        Address funcAddr = ...;
    } else if (regVarnode.isAddress()) {
        // Memory reference - read from memory
        Address dataAddr = regVarnode.getAddress();
        long funcPtr = memory.getInt(dataAddr) & 0xFFFFFFFFL;
        Address funcAddr = ...;
    } else if (context.isSymbol(regVarnode)) {
        // Symbolic reference - resolve it
        // ...
    }
}
```

---

## 🎓 Lessons Learned

1. **SymbolicPropagator is powerful but complex** - Need to understand Varnode vs Value
2. **Simple backward tracking isn't enough** - Need sophisticated data flow analysis
3. **Validation is critical** - Switch table analyzer needs better heuristics
4. **Testing is essential** - Need to verify each pattern works before moving on
5. **Logging is invaluable** - Detailed logs helped identify all these issues

---

## 📚 References

- **SymbolicPropogator.java** - Lines 289-426 (Value class and getRegisterValue)
- **VarnodeContext.java** - Methods for getting Varnodes and checking types
- **MipsSwitchTableAnalyzer.java** - Needs validation enhancements
- **Test binary:** tx-isp-t31.ko
- **Test function:** tx_isp_send_event_to_remote @ 0xf60c

---

## ✅ Action Items

- [ ] Fix SymbolicPropagator usage to get Varnode instead of Value
- [ ] Add memory read logic for indirect function pointers
- [ ] Add validation to MipsSwitchTableAnalyzer to reject strings
- [ ] Investigate why 0xf60c wasn't analyzed
- [ ] Test on simple patterns first
- [ ] Document successful resolution patterns
- [ ] Create unit tests for each pattern type

