# Removed Search Limit - Unlimited Backward Tracking

## ✅ Change Made

**Removed all search limits** - Now searches backward to the start of the function (unlimited)

### Before:
```java
int searchLimit = 300;
while (current != null && count < searchLimit) {
    // Search only 300 instructions back
}
```

### After:
```java
// Search backwards to the start of the function (no limit)
Function function = program.getFunctionManager().getFunctionContaining(jalrInstr.getAddress());
Address functionStart = (function != null) ? function.getEntryPoint() : null;

while (current != null) {
    count++;
    
    // Stop if we've left the function
    if (functionStart != null && current.getAddress().compareTo(functionStart) < 0) {
        failureReason = "No lw instruction found within function (searched " + count + " instructions)";
        break;
    }
    // ... search for lw ...
}
```

---

## 🎯 What This Achieves

### 1. Unlimited Search Within Function
- Searches ALL instructions from the `jalr`/`jr` back to the function start
- No arbitrary limit (was 100, then 300)
- Will find the `lw` instruction no matter how far back it is

### 2. Function Boundary Detection
- Stops at function entry point (doesn't search into previous functions)
- Reports how many instructions were searched
- More accurate failure messages

### 3. Better Diagnostics
- "No lw instruction found within function (searched 1234 instructions)"
- Shows actual search distance
- Helps identify if the register wasn't loaded by `lw` at all

---

## 📊 Expected Impact

### Before (with 300 instruction limit):
```
3,671 (48.8%) - No lw instruction found within 300 instructions
```

### After (unlimited search):
```
~500 (7%) - No lw instruction found within function
~4,100 (54%) - Register-relative loads (newly discovered)
```

**Key improvement:** We'll find the `lw` instruction in almost ALL cases where it exists!

---

## 🔍 What We'll Learn

### Pattern 1: Found lw (register-relative)
```
INFO  Found jalr call at 00043f64
INFO    Found lw at 00043ddc: lw s0,0x38(sp)
INFO    Register-relative load: 0x38(sp) (base=sp)
INFO    Failure: Register-relative load: 0x38(sp) (base=sp)
```

**Meaning:** The `lw` exists, but it's loading from stack/register  
**Next step:** Implement stack tracking or multi-level tracking

### Pattern 2: No lw found
```
INFO  Found jalr call at 00043f64
INFO    Failure: No lw instruction found within function (searched 456 instructions)
```

**Meaning:** The register was NOT loaded by `lw` in this function  
**Possible reasons:**
- Register is a function parameter (passed in by caller)
- Register was set by a different instruction (e.g., `move`, `addiu`)
- Register value came from a function call return value

---

## 🚀 Build & Test

### Step 1: Rebuild Ghidra
```bash
cd /home/matteius/ghidra
./gradlew buildGhidra
```

### Step 2: Re-analyze Binary
```
1. Open tx-isp-t31.ko
2. Analysis → One Shot → Clear Code Bytes
3. Analysis → Auto Analyze
4. Wait for completion
```

### Step 3: Check Results

**"No lw found" count (should be MUCH lower):**
```bash
grep "No lw instruction found" logs.txt | wc -l
```

**Register-relative count (should be MUCH higher):**
```bash
grep "Register-relative load" logs.txt | wc -l
```

**Top patterns:**
```bash
grep "Failure:" logs.txt | sort | uniq -c | sort -rn | head -20
```

**Average search distance:**
```bash
grep "searched.*instructions" logs.txt | head -20
```

---

## 📈 Success Metrics

### Minimum Success:
- [ ] "No lw found" reduced from 3,671 to <1,000
- [ ] Register-relative loads increased to >3,000
- [ ] Can see actual search distances

### Good Success:
- [ ] "No lw found" reduced to <500
- [ ] Register-relative loads >4,000
- [ ] Clear pattern distribution

### Excellent Success:
- [ ] "No lw found" reduced to <200
- [ ] Register-relative loads >5,000
- [ ] Some patterns might be resolved (>0)

---

## 🎯 Next Steps After This

Based on the new failure patterns, we'll implement:

### Priority 1: Stack-Relative Tracking
**Pattern:** `lw $reg, offset($sp)`  
**Count:** Expected ~1,500-2,000  
**Solution:** Track backward to find `sw $source, offset($sp)`, then track `$source`

### Priority 2: $gp-Relative Resolution
**Pattern:** `lw $reg, offset($gp)`  
**Count:** Expected ~500-1,000  
**Solution:** Get $gp value, calculate address, read function pointer from memory

### Priority 3: Multi-Level Tracking
**Pattern:** `lw $reg, offset($base)` where `$base` is also loaded  
**Count:** Expected ~1,000-2,000  
**Solution:** Recursively track through multiple `lw` instructions

### Priority 4: Function Parameter Detection
**Pattern:** "No lw found" where register is a function parameter  
**Count:** Expected ~200-500  
**Solution:** Check if register is $a0-$a3 or loaded from stack parameter area

---

## 🔮 Predictions

### Conservative:
- "No lw found" drops to ~800 (11%)
- Stack-relative: ~1,500 (20%)
- $gp-relative: ~500 (7%)
- Other register-relative: ~2,500 (33%)
- Still 0 resolutions

### Realistic:
- "No lw found" drops to ~400 (5%)
- Stack-relative: ~2,000 (27%)
- $gp-relative: ~800 (11%)
- Other register-relative: ~3,000 (40%)
- 0-10 resolutions (if any simple global patterns exist)

### Optimistic:
- "No lw found" drops to ~200 (3%)
- Stack-relative: ~2,500 (33%)
- $gp-relative: ~1,000 (13%)
- Other register-relative: ~3,500 (47%)
- 10-50 resolutions (0.1-0.7%)

---

## 💡 Key Insight

**Removing the search limit is critical** because:

1. **MIPS functions can be LONG** - Especially in kernel modules
2. **Saved registers loaded once** - At function start, used throughout
3. **Arbitrary limits hide the truth** - We need to see the REAL patterns

**Example:**
```assembly
# Function start (address 0x1000)
addiu   $sp, $sp, -0x100
sw      $ra, 0xfc($sp)
sw      $s0, 0xf8($sp)
lw      $s0, offset($gp)        # Load function pointer

# ... 500 instructions of code ...

# Near end of function (address 0x2000)
jalr    $s0                     # Call function pointer
```

With a 300 instruction limit, we'd never find the `lw` at the function start!

---

## ✅ Build Status

```bash
$ ./gradlew :MIPS:compileJava
BUILD SUCCESSFUL in 2s
```

**Ready for testing!**

---

## 📝 Files Modified

### MipsFunctionPointerAnalyzer.java
- **Lines 422-442:** Removed search limit, added function boundary detection
- **Lines 476-482:** Removed searchLimit reference
- **Status:** ✅ Compiles successfully

---

## 🎉 This Is a Game Changer!

**Before:** Arbitrary 100/300 instruction limit  
**After:** Search entire function  

**Impact:** We'll finally see the TRUE failure patterns and can implement the right fixes!

---

**Status:** ✅ CODE COMPLETE  
**Build:** ✅ SUCCESSFUL  
**Impact:** 🔥 **CRITICAL** - This should reveal the real patterns!  
**Next:** Rebuild Ghidra and re-analyze! 🚀

