# Fresh Agent Briefing - MIPS Indirect Call Resolution

## 🎯 Mission

Fix MIPS indirect call resolution in Ghidra for the binary `tx-isp-t31.ko`. Currently **0 out of 7,588 indirect calls are resolved**. The root cause has been identified: **function signature issues**.

---

## 📊 Current Status

### What Works ✅
- Switch table detection (MipsSwitchTableAnalyzer) - working
- Function pointer table detection - 3,208 tables found
- Pattern detection - we can identify the patterns
- Decompiler warnings suppressed via jump table overrides

### What Doesn't Work ❌
- **0 indirect calls resolved** (out of 7,588)
- Function signature analyzer finds 0 patterns (logic bug)
- $gp-relative resolution not working (can't find $gp value)
- Register-relative tracking not implemented

---

## 🔍 Root Cause Analysis

### Pattern Distribution (from logs):

| Pattern | Count | % | Status |
|---------|-------|---|--------|
| `$v0` return value | 1,492 | 19.7% | ❌ Not resolved - **FUNCTION SIGNATURE ISSUE** |
| Register-relative `$v0` | 138 | 1.8% | ❌ Not resolved - struct from function |
| Stack-relative `$sp` | ~118 | 1.6% | ❌ Not implemented |
| $gp-relative | 28 | 0.4% | ❌ $gp detection failing |
| Other register-relative | ~3,400 | 44.8% | ❌ Not implemented |
| Other "No lw found" | ~2,440 | 32.1% | ❌ Various issues |

**Key Insight:** 21.5% of failures (1,630 cases) are due to functions returning function pointers, but Ghidra doesn't know this!

---

## 🐛 The Core Problem

### Pattern Example:
```assembly
jal     get_callback        # Function returns callback in $v0
nop
jalr    $v0                 # Call the returned callback
```

**What Ghidra thinks:**
```c
void* callback = get_callback();  // Returns void*
(*callback)();  // Wrong!
```

**Reality:**
```c
typedef int (*callback_t)(void*, int, void*);
callback_t get_callback(void);  // Returns function pointer!
callback_t cb = get_callback();
cb(pad, cmd, data);  // Correct!
```

**Why resolution fails:**
1. We search for `lw $v0, ...` but there is none
2. `$v0` was set by the `jal` instruction's return value
3. We don't know the function returns a function pointer
4. We can't resolve the indirect call

---

## 📁 Relevant Files

### Analyzers (in `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/`):

1. **MipsFunctionPointerAnalyzer.java** (~766 lines)
   - Detects jalr/jr instructions
   - Tries to resolve targets by tracking backward
   - Creates jump table overrides to suppress warnings
   - **Status:** Working but can't resolve due to signature issues

2. **MipsFunctionSignatureAnalyzer.java** (~220 lines)
   - **BROKEN:** Finds 0 patterns (should find 1,492+)
   - Supposed to detect functions that return function pointers
   - Supposed to fix their signatures automatically
   - **Bug:** Logic issue - not finding the `jal` before `jalr $v0`

3. **MipsSwitchTableAnalyzer.java** (~663 lines)
   - Detects switch tables
   - **Status:** Working correctly

4. **MipsInlineCodeAnalyzer.java** (~282 lines)
   - Handles inline code
   - **Status:** Working

### Test Binary:
- **Path:** `/home/matteius/ghidra/tx-isp-t31.ko`
- **Type:** MIPS kernel module (mipsel32, linux-mipsel)
- **Test function:** `tx_isp_send_event_to_remote` @ 0xf60c

### Logs:
- **Path:** `/home/matteius/ghidra/logs.txt`
- **Contains:** Full analysis output with all patterns and failures

---

## 🎯 Immediate Tasks

### Task 1: Fix MipsFunctionSignatureAnalyzer (CRITICAL)

**Problem:** Finds 8,533 jalr/jr instructions but 0 patterns

**Debug needed:**
1. Add logging to show what it's checking
2. Check if it's actually looking at `$v0` register correctly
3. Check if `findFunctionThatReturnsPointer()` is working
4. Verify the backward search is finding `jal` instructions

**Expected result:** Should find ~1,500 patterns where `jal` is followed by `jalr $v0`

**File:** `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsFunctionSignatureAnalyzer.java`

### Task 2: Fix $gp Value Detection

**Problem:** All 28 $gp-relative loads fail with "Could not determine $gp value for section"

**Known $gp values (from loader):**
- `.text` section: `gp=0xe3ff0`
- `.init.text` section: `gp=0xf3ff0`
- `.exit.text` section: `gp=0x103ff0`

**Current code tries 4 methods but all fail:**
1. Program context register
2. GOT memory blocks
3. Program properties
4. .got section

**Debug needed:**
1. Check what's actually available in the program
2. Print all memory block names
3. Print all program properties
4. Check if context register exists

**File:** `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsFunctionPointerAnalyzer.java` (lines 676-744)

### Task 3: Verify Jump Table Overrides

**Check:** Are jump table overrides actually being created?

**Command:**
```bash
grep "Created.*jump table override" logs.txt | wc -l
```

**Expected:** ~7,500 (one for each unresolved indirect call)
**Actual:** Unknown - need to check

---

## 🔧 Quick Diagnostic Commands

```bash
cd /home/matteius/ghidra

# Check signature analyzer results
grep "MipsFunctionSignatureAnalyzer" logs.txt | grep "Found.*patterns"

# Check $gp resolution attempts
grep "Could not determine \$gp value" logs.txt | wc -l

# Check pattern distribution
grep "Failure:" logs.txt | sort | uniq -c | sort -rn | head -20

# Check $v0 usage
grep "register: v0" logs.txt | wc -l

# Check jump table overrides
grep "jump table override" logs.txt | wc -l
```

---

## 🚀 Success Criteria

### Minimum Success:
- [ ] MipsFunctionSignatureAnalyzer finds >1,000 patterns
- [ ] At least 100 function signatures fixed
- [ ] At least 100 indirect calls resolved

### Good Success:
- [ ] 1,500+ patterns found
- [ ] 1,500+ signatures fixed
- [ ] 1,500+ indirect calls resolved (21.5%)
- [ ] $gp-relative resolution working (28 cases)

### Excellent Success:
- [ ] All above PLUS
- [ ] Stack-relative tracking implemented
- [ ] 2,000+ indirect calls resolved (26%+)
- [ ] Clean decompilation of `tx_isp_send_event_to_remote`

---

## 📝 Build & Test Commands

```bash
# Compile MIPS module
./gradlew :MIPS:compileJava --console=plain

# Build full Ghidra (if needed)
./gradlew buildGhidra

# Check compilation
echo $?  # Should be 0

# After re-analysis in Ghidra, check results
grep "Fixed.*function signatures" logs.txt
grep "Resolved.*jalr\|Resolved.*jr" logs.txt | wc -l
```

---

## 🎓 Key Technical Concepts

### MIPS Registers:
- `$v0, $v1` - Return value registers
- `$a0-$a3` - Argument registers (first 4 parameters)
- `$t0-$t9` - Temporary registers
- `$s0-$s7` - Saved registers
- `$gp` - Global pointer (points to GOT)
- `$sp` - Stack pointer
- `$ra` - Return address

### MIPS Instructions:
- `jal target` - Jump and link (call function)
- `jalr $reg` - Jump and link register (indirect call)
- `jr $reg` - Jump register (indirect jump/tail call)
- `lw $dest, offset($base)` - Load word from memory

### Ghidra Concepts:
- **Analyzer** - Runs during auto-analysis
- **AnalysisPriority** - Controls execution order
- **JumpTable.writeOverride()** - Suppresses decompiler warnings
- **Function.setReturnType()** - Updates function signature
- **SourceType.ANALYSIS** - Marks changes as from analysis

---

## 💡 Debugging Strategy

### Step 1: Add Verbose Logging
Add detailed logging to MipsFunctionSignatureAnalyzer:
- Log each jalr/jr found with register name
- Log when checking for $v0/$v1
- Log when searching backward for jal
- Log each jal instruction found
- Log why pattern matching fails

### Step 2: Test on Single Function
Pick one function that should work:
- Find a `jalr $v0` in the logs
- Manually trace back to find the `jal`
- Verify the pattern exists
- Debug why the analyzer doesn't find it

### Step 3: Fix and Iterate
- Fix the logic bug
- Recompile
- Re-analyze
- Check logs for improvements

---

## 📞 Questions to Answer

1. **Why does MipsFunctionSignatureAnalyzer find 0 patterns?**
   - Is it checking the right register names?
   - Is the backward search working?
   - Is it finding `jal` instructions?

2. **Why can't we find $gp values?**
   - What memory blocks actually exist?
   - What program properties exist?
   - Is the context register set?

3. **Are jump table overrides being created?**
   - Check the logs
   - Verify decompiler warnings are suppressed

---

## 🎯 Expected Outcome

After fixing MipsFunctionSignatureAnalyzer:
- **1,500+ function signatures fixed** to return function pointers
- **1,500+ indirect calls resolved** (21.5% of total)
- **Clean decompilation** with proper function pointer types
- **Foundation for further improvements** (stack tracking, etc.)

---

## 📚 Reference Documents

- `FUNCTION_SIGNATURE_ROOT_CAUSE.md` - Detailed root cause analysis
- `DECOMPILER_WARNINGS_FIX.md` - Jump table override implementation
- `GP_RESOLUTION_IMPLEMENTED.md` - $gp resolution attempt
- `logs.txt` - Full analysis output

---

**Status:** 🔴 **BLOCKED** - MipsFunctionSignatureAnalyzer has logic bug  
**Priority:** 🔥 **CRITICAL** - This blocks 21.5% of resolutions  
**Next Agent:** Debug and fix MipsFunctionSignatureAnalyzer pattern detection

---

## 🎬 Starting Point for New Agent

**First command to run:**
```bash
cd /home/matteius/ghidra
grep -A5 "Found jalr call at 00010554" logs.txt
```

This will show a real example of a `jalr $v0` that should have a `jal` before it. Use this to understand the actual pattern and debug why the analyzer doesn't find it.

**Good luck!** 🚀

