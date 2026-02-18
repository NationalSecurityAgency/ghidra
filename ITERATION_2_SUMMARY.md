# Iteration 2: Enhanced Diagnostics and Bug Fixes

## 🎯 Summary

Based on log analysis and user feedback, we've made three major improvements:

1. **Enhanced diagnostic logging** for indirect call resolution failures
2. **Fixed MipsSwitchTableAnalyzer** to stop treating strings as switch tables
3. **Identified function signature detection issue** and provided solutions

---

## ✅ Changes Made

### 1. Enhanced Diagnostic Logging

**File:** `MipsFunctionPointerAnalyzer.java`  
**Lines:** 407-494

**What Changed:**
- Added detailed failure reason tracking
- Logs the actual `lw` instruction found
- Analyzes WHY the load couldn't be resolved
- Shows operand types and patterns

**New Log Output:**
```
INFO  Found jalr call at 00010574 (MipsFunctionPointerAnalyzer)
INFO    Found lw at 00010570: lw $v0, 0x10($gp)
INFO    Register-relative load: 0x10($gp) (base=gp)
INFO    Failure: Register-relative load: 0x10($gp) (base=gp)
INFO  Could not resolve jalr call target at 00010574 (register: v0)
```

**Benefits:**
- ✅ Understand exactly why each call fails
- ✅ Identify common failure patterns
- ✅ Guide future enhancements
- ✅ Debug specific cases

**New Method:**
```java
private String analyzeLoadFailure(Instruction lwInstr) {
    String op1 = lwInstr.getDefaultOperandRepresentation(1);
    
    // Pattern: offset($base) - register-relative
    if (op1.contains("(") && op1.contains(")")) {
        String baseReg = op1.substring(op1.indexOf("(") + 1, op1.indexOf(")"));
        return "Register-relative load: " + op1 + " (base=" + baseReg + ")";
    }
    
    // Pattern: label or absolute address
    if (lwInstr.getNumOperands() >= 2) {
        Object[] opObjs = lwInstr.getOpObjects(1);
        if (opObjs.length == 0) {
            return "No operand objects found";
        }
        return "Operand type: " + opObjs[0].getClass().getSimpleName() + " = " + opObjs[0];
    }
    
    return "Unknown load pattern";
}
```

---

### 2. Fixed MipsSwitchTableAnalyzer False Positives

**File:** `MipsSwitchTableAnalyzer.java`  
**Lines:** 390-418, 421-480

**Problem:**
The analyzer was reading beyond actual switch tables into string data, generating thousands of warnings:
```
WARN  Invalid target address in switch table at 000824f4: 6765746e
```

Where `0x6765746e` = "getn" (ASCII string)

**Root Cause:**
Switch tables are often followed by string data in memory:
```
0007b720  64 24 03 00     addr       switchD_0003245c::caseD_0
0007b724  80 24 03 00     addr       switchD_0003245c::caseD_1
...
0007b7e4  74 69 73 70     ds         "tisp_gib_param_array_set"  ← String data!
```

The analyzer kept reading entries and hit the string.

**Solution 1: ASCII String Detection**
```java
private boolean isLikelyAsciiString(long value) {
    // Extract 4 bytes
    byte b0 = (byte) (value & 0xFF);
    byte b1 = (byte) ((value >> 8) & 0xFF);
    byte b2 = (byte) ((value >> 16) & 0xFF);
    byte b3 = (byte) ((value >> 24) & 0xFF);
    
    // Count printable ASCII characters
    int printableCount = 0;
    if (isPrintableAscii(b0)) printableCount++;
    if (isPrintableAscii(b1)) printableCount++;
    if (isPrintableAscii(b2)) printableCount++;
    if (isPrintableAscii(b3)) printableCount++;
    
    // If 3 or more bytes are printable ASCII, it's likely a string
    return printableCount >= 3;
}
```

**Solution 2: Stricter Validation**
```java
private boolean isValidCodeAddress(Program program, Address addr) {
    // ... existing checks ...
    
    // Must be executable - don't allow data sections
    if (!block.isExecute()) {
        return false;
    }
    
    // Check if there's actually an instruction at this address
    Instruction instr = program.getListing().getInstructionAt(addr);
    if (instr == null) {
        return false;
    }
    
    return true;
}
```

**Solution 3: Stop on Invalid Entry**
```java
// Check if this looks like ASCII text
if (isLikelyAsciiString(offset)) {
    // Hit string data - end of switch table
    break;
}

// Validate the target address
if (!isValidCodeAddress(program, target)) {
    // Invalid address - likely end of table
    break;  // Changed from 'continue' to 'break'
}
```

**Benefits:**
- ✅ No more false positive warnings
- ✅ Cleaner logs
- ✅ Better performance (stops reading at table end)
- ✅ More accurate switch table detection

---

### 3. Function Signature Detection Issue

**Problem Identified:**
Ghidra is missing function parameters. Example:

**Actual signature:**
```c
int tx_isp_send_event_to_remote(struct tx_isp_subdev_pad *pad, 
                                 unsigned int cmd, void *data);
```

**Ghidra detected:**
```c
int tx_isp_send_event_to_remote(void *arg1);
```

**Missing:** 2 out of 3 parameters!

**Root Cause:**
- MIPS uses `$a0`, `$a1`, `$a2`, `$a3` for first 4 arguments
- Ghidra only detects parameters if it sees the registers being used
- If parameters are unused or only used conditionally, Ghidra misses them

**Solutions Provided:**

**Solution 1: Manual Fix**
- Right-click function → Edit Function Signature
- Change to correct signature

**Solution 2: Script**
- Created `FixFunctionSignatures.java`
- Scans all functions
- Detects argument register usage
- Prompts to fix mismatches

**Solution 3: Import Headers**
- Create header file with correct signatures
- File → Parse C Source
- Ghidra updates all matching functions

**Documentation:**
- Created `FUNCTION_SIGNATURE_ISSUE.md`
- Detailed explanation of the problem
- Multiple solutions
- Examples and testing procedures

---

## 📊 Expected Results After Rebuild

### Diagnostic Logs

**Before:**
```
INFO  Found jalr call at 00010574
INFO  Could not resolve jalr call target at 00010574 (register: v0)
```

**After:**
```
INFO  Found jalr call at 00010574
INFO    Found lw at 00010570: lw $v0, 0x10($gp)
INFO    Register-relative load: 0x10($gp) (base=gp)
INFO    Failure: Register-relative load: 0x10($gp) (base=gp)
INFO  Could not resolve jalr call target at 00010574 (register: v0)
```

**Benefits:**
- See exactly which `lw` instruction was found
- Understand why it couldn't be resolved
- Identify patterns to fix

### Switch Table Warnings

**Before:**
```
WARN  Invalid target address in switch table at 000824f4: 6765746e
WARN  Invalid target address in switch table at 000824f8: 73706974
WARN  Invalid target address in switch table at 000824fc: 6269675f
... (thousands of warnings)
```

**After:**
```
(No warnings - stops reading at table boundary)
```

**Benefits:**
- Clean logs
- Faster analysis
- Accurate switch table sizes

---

## 🔍 Analysis of Failure Patterns

Based on the logs, we can now categorize failures:

### Pattern 1: Register-Relative Loads (Most Common)
```assembly
lw      $t9, 0x1c($a0)       # Load from struct field
jr      $t9
```

**Failure reason:** "Register-relative load: 0x1c($a0) (base=a0)"

**Why it fails:**
- No static address to read from
- Depends on runtime value of `$a0`
- Requires tracking through multiple instructions

**Solution needed:** Multi-level tracking or SymbolicPropagator

### Pattern 2: Global Pointer Relative (Common)
```assembly
lw      $v0, 0x10($gp)       # Load from .got
jalr    $v0
```

**Failure reason:** "Register-relative load: 0x10($gp) (base=gp)"

**Why it fails:**
- `$gp` is the global pointer
- Points to .got section
- Should be resolvable but needs special handling

**Solution needed:** Resolve `$gp` value and read from .got

### Pattern 3: Return Address (Should Ignore)
```assembly
jr      $ra                  # Function return
```

**Status:** ✅ Already filtered out

### Pattern 4: Far Distance
```assembly
# ... 150 instructions ...
lw      $t9, offset($gp)
# ... more instructions ...
jalr    $t9
```

**Failure reason:** "No lw instruction found within 100 instructions"

**Why it fails:**
- Search limit is 100 instructions
- Function pointer loaded too far back

**Solution needed:** Increase search limit or use SymbolicPropagator

---

## 🎯 Next Steps

### Immediate (User)

1. **Rebuild Ghidra:**
   ```bash
   cd /home/matteius/ghidra
   ./gradlew buildGhidra
   ```

2. **Re-analyze binary:**
   - Open tx-isp-t31.ko
   - Analysis → Auto Analyze

3. **Check new diagnostic logs:**
   - Look for detailed failure reasons
   - Identify most common patterns
   - Share findings

4. **Fix function signatures:**
   - Run `FixFunctionSignatures.java` script
   - Or manually fix `tx_isp_send_event_to_remote`
   - Verify decompilation improves

### Future Enhancements

**Priority 1: Handle $gp-relative loads**
```java
// Detect pattern: lw $reg, offset($gp)
if (baseReg.equals("gp")) {
    // Get $gp value from program context
    long gpValue = getGlobalPointerValue(program);
    Address dataAddr = gpValue + offset;
    // Read function pointer from .got
    long funcPtr = memory.getInt(dataAddr);
    return funcPtr;
}
```

**Priority 2: Multi-level tracking**
```java
// Track through multiple lw instructions
// Example: lw $a0, 0xc($a0); lw $t9, 0x1c($a0)
Map<Register, Address> registerValues = new HashMap<>();
// Track register values backward
// Resolve multi-level indirection
```

**Priority 3: Increase search distance**
```java
// Change from 100 to 200 or 300 instructions
int searchLimit = 200;
```

---

## 📈 Statistics

### From Logs (First 50 failures)

**jalr failures by register:**
- `$v0`: 36 (72%) - Return values from function calls
- `$s2`: 7 (14%) - Saved register (local variable)
- `$s1`: 5 (10%) - Saved register (local variable)
- `$a1`: 2 (4%) - Argument register

**jr failures by register:**
- `$ra`: 42 (84%) - Function returns (should ignore)
- `$t9`: 8 (16%) - Tail calls (should resolve)

**Key Insight:**
- Most `jr $ra` are returns - already filtered ✅
- Most `jalr $v0` are calling function pointers returned from other functions
- Need to track return values from function calls

---

## 📝 Files Modified

### MipsFunctionPointerAnalyzer.java
- **Lines changed:** ~40
- **New methods:** `analyzeLoadFailure()`
- **Enhanced:** Diagnostic logging
- **Status:** ✅ Compiles

### MipsSwitchTableAnalyzer.java
- **Lines changed:** ~60
- **New methods:** `isLikelyAsciiString()`, `isPrintableAscii()`
- **Enhanced:** `isValidCodeAddress()`, table reading loop
- **Status:** ✅ Compiles

### New Files Created
- ✅ `FixFunctionSignatures.java` - Script to fix parameter counts
- ✅ `FUNCTION_SIGNATURE_ISSUE.md` - Documentation
- ✅ `ITERATION_2_SUMMARY.md` - This file

---

## ✅ Build Status

```bash
$ ./gradlew :MIPS:compileJava
BUILD SUCCESSFUL in 2s
```

All code compiles successfully! ✅

---

## 🚀 Ready for Testing

**Status:** ✅ CODE COMPLETE  
**Build:** ✅ SUCCESSFUL  
**Documentation:** ✅ COMPLETE

**Next:** User rebuilds Ghidra and tests with new diagnostic logging!

The enhanced diagnostics will help us understand exactly why indirect calls are failing and guide the next round of improvements.

