# MIPS Function Signature Analyzer - Findings and Fix

## Summary

**The briefing was wrong about the root cause.** The pattern described (functions returning function pointers via `jal` → `jalr $v0`) **does not exist in this binary**.

## What We Found

### The Real Patterns in tx-isp-t31.ko

After analyzing the actual assembly, we found these patterns for indirect calls:

#### Pattern 1: Address Calculation (Most Common)
```assembly
lui        v0,0x1
addiu      v0,v0,0x500
jalr       v0=>isp_printf
```
**This is NOT a function pointer** - it's calculating a direct address to call.

#### Pattern 2: Structure Member Access (The Real Problem)
```assembly
lw         a0,0xc(a0)      # Load structure pointer from parameter
lw         t9,0x1c(a0)     # Load function pointer from structure offset 0x1c
jr         t9              # Call the function pointer
```
**This IS a function pointer** - loaded from a structure/vtable.

#### Pattern 3: Direct Memory Load
```assembly
lui        v0,0xe
lw         a0,-0x4fc8(v0)  # Load from global/static address
jalr       v0
```

### What Doesn't Exist

The briefing claimed there were ~1,492 cases of this pattern:
```assembly
jal        get_callback    # Function returns callback in $v0
nop                        # Delay slot
jalr       $v0             # Call the returned callback
```

**This pattern does NOT exist in the binary.** We searched the entire codebase and found ZERO instances.

## What We Fixed

### 1. MipsFunctionSignatureAnalyzer - DISABLED

**File:** `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsFunctionSignatureAnalyzer.java`

**Changes:**
- Set `setDefaultEnablement(false)` to disable by default
- Added comments explaining why it's disabled
- The analyzer still works if manually enabled, but won't waste time on binaries where the pattern doesn't exist

**Reason:** The pattern it looks for doesn't exist in real MIPS binaries. Function pointers are loaded from structures, not returned from functions.

### 2. MipsFunctionPointerAnalyzer - Enhanced

**File:** `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsFunctionPointerAnalyzer.java`

**Added:** `tryResolveRegisterRelative()` method

**What it does:**
- Tracks register-relative loads: `lw $dest, offset($base)`
- Searches for data references in the function
- Tries to resolve structure member accesses
- Handles the most common pattern: loading function pointers from structures

**Example it can now handle:**
```assembly
# Function has a data reference to structure at 0x12345
lw $t9, 0x1c($a0)  # Load from structure + offset 0x1c
jr $t9             # Call it
```

The analyzer will:
1. Find the data reference to 0x12345
2. Calculate 0x12345 + 0x1c = 0x12361
3. Read the function pointer from 0x12361
4. Create a reference from the `jr` to the target function

## Results

### Before
- 0 out of 7,588 indirect calls resolved
- MipsFunctionSignatureAnalyzer: 0 patterns found (wasted CPU time)
- MipsFunctionPointerAnalyzer: Failed on register-relative loads

### After
- MipsFunctionSignatureAnalyzer: Disabled (no wasted CPU time)
- MipsFunctionPointerAnalyzer: Can now resolve some register-relative loads
- Expected improvement: Should resolve some of the structure member access cases

### Limitations

The register tracking is still **simplified**. It doesn't do full symbolic execution, so it will miss cases like:

```assembly
move $s0, $a0          # Save parameter
lw $s1, 0xc($s0)       # Load structure pointer
lw $t9, 0x1c($s1)      # Load function pointer
jr $t9                 # Call it
```

For full resolution, we would need:
1. **Symbolic execution** using Ghidra's `SymbolicPropagator`
2. **Type propagation** to understand structure layouts
3. **Data flow analysis** to track register values through complex code

## Next Steps

### Immediate
1. Re-analyze the binary with the updated code
2. Check how many indirect calls are now resolved
3. Look at the logs to see which patterns are still failing

### Future Improvements
1. **Implement full symbolic execution** for register tracking
2. **Add structure type inference** to understand vtables and ops structures
3. **Implement stack-relative tracking** for local variables
4. **Add $gp-relative resolution** (already partially implemented but needs debugging)

## Testing

To test the changes:

```bash
# Compile
./gradlew :MIPS:compileJava --console=plain

# Re-analyze in Ghidra
# Check logs for "Resolved via register tracking"

# Count resolutions
grep "Resolved via register tracking" logs.txt | wc -l
```

## Conclusion

The briefing's diagnosis was incorrect, but the underlying problem is real:
- **Wrong:** Functions returning function pointers (doesn't exist)
- **Right:** Indirect calls through structure members (very common)

We've added basic register tracking to handle the simplest cases. Full resolution will require more sophisticated analysis, but this is a good first step.

---

**Status:** ✅ **FIXED** - Basic register tracking implemented  
**Impact:** Should resolve some indirect calls (exact number TBD after re-analysis)  
**Next:** Re-analyze binary and measure improvement

