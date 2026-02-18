# Enhanced Function Pointer Tracking Implementation

## 📋 Summary

Implemented enhanced backward tracking for MIPS indirect calls (`jalr` and `jr` instructions). The analyzer now properly detects both instruction types and uses improved heuristics to resolve function pointer targets.

---

## ✅ Changes Made

### 1. Added JR Instruction Support
**File:** `MipsFunctionPointerAnalyzer.java`  
**Lines:** 288-297, 329-357

**What Changed:**
- Analyzer now detects both `jalr` (jump and link register) and `jr` (jump register)
- Creates appropriate reference types:
  - `jalr` → `COMPUTED_CALL` (function call)
  - `jr` → `COMPUTED_JUMP` (tail call or indirect jump)
- Skips `jr $ra` (function returns) - these are not indirect calls

**Code:**
```java
String mnemonic = instr.getMnemonicString();
boolean isJalr = mnemonic.equals("jalr") || mnemonic.equals("_jalr");
boolean isJr = mnemonic.equals("jr") || mnemonic.equals("_jr");

if (isJalr || isJr) {
    // Skip jr $ra (function returns)
    if (isJr && targetReg.getName().equals("ra")) {
        continue;
    }
    
    // Process indirect call/jump
    RefType refType = isJalr ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP;
    // ...
}
```

### 2. Enhanced Backward Tracking
**File:** `MipsFunctionPointerAnalyzer.java`  
**Lines:** 407-525

**What Changed:**
- Increased search distance from 30 to 100 instructions
- Added detailed debug logging
- Split resolution into three methods:
  1. `tryResolveFromReferences()` - Check existing data references
  2. `tryResolveFromOperands()` - Parse instruction operands
  3. Main loop - Coordinate the search

**Improvements:**
- Better error messages explaining why resolution failed
- Stops search when finding earlier writes to target register
- Validates that resolved addresses point to actual code

### 3. Removed Broken SymbolicPropagator Code
**File:** `MipsFunctionPointerAnalyzer.java`  
**Lines:** 397-405

**What Changed:**
- Removed the SymbolicPropagator approach (was returning 0 results)
- Added TODO comment for future implementation
- Simplified to use only the enhanced backward tracking

**Reason:**
SymbolicPropagator requires a ContextEvaluator callback to access the VarnodeContext. The simple approach of calling `getRegisterValue()` doesn't work for register-relative or symbolic values.

---

## 🔍 How It Works

### Detection Phase

**Step 1: Find jalr/jr Instructions**
```java
for (Instruction instr : listing.getInstructions(true)) {
    String mnemonic = instr.getMnemonicString();
    boolean isJalr = mnemonic.equals("jalr");
    boolean isJr = mnemonic.equals("jr");
    
    if (isJalr || isJr) {
        // Get target register (e.g., $t9, $v0, $s1)
        Register targetReg = instr.getRegister(0);
        
        // Try to resolve the function pointer
        Address target = findFunctionPointerTarget(program, instr, targetReg);
    }
}
```

### Resolution Phase

**Step 2: Search Backward for Load Instruction**
```java
Instruction current = jalrInstr.getPrevious();
int searchLimit = 100;

while (current != null && count < searchLimit) {
    if (current.getMnemonicString().equals("lw")) {
        Register destReg = current.getRegister(0);
        
        if (destReg.equals(targetReg)) {
            // Found: lw $t9, offset($base)
            // Try to resolve the address
        }
    }
    current = current.getPrevious();
}
```

**Step 3: Try Multiple Resolution Methods**

**Method 1: Existing Data References**
```java
Reference[] refs = lwInstr.getReferencesFrom();
for (Reference ref : refs) {
    if (ref.getReferenceType().isData()) {
        Address dataAddr = ref.getToAddress();
        // Read function pointer from memory
        long funcPtr = memory.getInt(dataAddr);
        // Validate and return
    }
}
```

**Method 2: Parse Operands**
```java
Object[] opObjs = lwInstr.getOpObjects(1);
for (Object obj : opObjs) {
    if (obj instanceof Address) {
        Address dataAddr = (Address) obj;
        // Read function pointer from memory
        long funcPtr = memory.getInt(dataAddr);
        // Validate and return
    }
}
```

### Reference Creation Phase

**Step 4: Create Reference and Suppress Warnings**
```java
if (targetFunc != null) {
    // Create appropriate reference type
    RefType refType = isJalr ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP;
    refMgr.addMemoryReference(instr.getAddress(), targetFunc,
        refType, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
    
    // Create single-entry jump table override to suppress decompiler warnings
    suppressSwitchTableRecovery(program, instr, targetFunc);
}
```

---

## 📊 Expected Results

### Patterns That Should Work

**Pattern 1: Global Function Pointer**
```assembly
lui     $gp, 0x8000          # Load upper immediate
lw      $t9, offset($gp)     # Load function pointer from .got
jalr    $t9                  # Call function
```

**Why it works:**
- `lw` has a data reference to the .got entry
- Method 1 (tryResolveFromReferences) will find it
- Function pointer is read from memory
- Reference created successfully

**Pattern 2: Direct Load**
```assembly
lw      $t9, function_ptr    # Load from absolute address
jalr    $t9                  # Call function
```

**Why it works:**
- `lw` operand contains the address directly
- Method 2 (tryResolveFromOperands) will find it
- Function pointer is read from memory
- Reference created successfully

### Patterns That Won't Work (Yet)

**Pattern 1: Register-Relative (Our Test Case)**
```assembly
lw      $a0, 0xc($a0)        # Load struct pointer
lw      $t9, 0x1c($a0)       # Load function pointer from struct
jr      $t9                  # Tail call
```

**Why it fails:**
- `lw $t9, 0x1c($a0)` has no data reference (runtime-dependent)
- Operand doesn't contain an Address object (it's register + offset)
- Would need to track $a0 value through multiple instructions
- Requires SymbolicPropagator or multi-level tracking

**Pattern 2: Computed Address**
```assembly
sll     $v0, $v0, 2          # Multiply index by 4
addu    $v0, $v0, $gp        # Add to base
lw      $t9, 0($v0)          # Load from computed address
jalr    $t9                  # Call
```

**Why it fails:**
- Function pointer address is computed at runtime
- No static address to read from
- Requires symbolic execution

**Pattern 3: Far Distance**
```assembly
# ... 150 instructions ...
lw      $t9, offset($gp)     # Load function pointer
# ... more instructions ...
jalr    $t9                  # Call (>100 instructions away)
```

**Why it fails:**
- Search limit is 100 instructions
- Could increase limit, but risks performance issues

---

## 🧪 Testing Strategy

### Phase 1: Find Working Patterns

**Goal:** Find at least one indirect call that resolves successfully

**Method:**
1. Rebuild Ghidra: `./gradlew buildGhidra`
2. Re-analyze tx-isp-t31.ko
3. Check logs for: `INFO  Resolved jalr call at ...` or `INFO  Resolved jr jump at ...`
4. If found, navigate to that address and verify:
   - Reference exists in assembly listing
   - Decompiler shows clean call (no warnings)
   - Can navigate from jalr/jr to target function

### Phase 2: Analyze Failures

**Goal:** Understand why most calls still fail

**Method:**
1. Enable debug logging: `Msg.debug()` → `Msg.info()`
2. Look for patterns in failures:
   - "Found lw instruction at ..." - Did we find the load?
   - "Could not resolve lw at ..." - Why did resolution fail?
   - No lw found - Is the function pointer loaded too far back?

### Phase 3: Implement Fixes

**Based on failure analysis:**

**If: "Found lw but couldn't resolve"**
- Add more resolution methods
- Check if operand parsing is working
- Verify memory reads are succeeding

**If: "No lw found within 100 instructions"**
- Increase search limit
- Or implement SymbolicPropagator approach

**If: "lw is register-relative"**
- Implement multi-level tracking
- Track base register value
- Resolve through multiple loads

---

## 📈 Success Metrics

### Minimum Success (Phase 7 Goal)
- ✅ Analyzer detects both jalr and jr instructions
- ✅ Analyzer compiles without errors
- ⏳ At least 1% of indirect calls resolved (200+ out of 20,000)
- ⏳ Test function tx_isp_send_event_to_remote analyzed
- ⏳ At least one pattern type working

### Good Success
- 10% of indirect calls resolved (2,000+ out of 20,000)
- Multiple pattern types working
- Decompiler warnings reduced significantly

### Excellent Success
- 50%+ of indirect calls resolved (10,000+ out of 20,000)
- Most common patterns working
- Decompiler warnings mostly eliminated

---

## 🔧 Next Steps

### Immediate (User Responsibility)
1. **Rebuild Ghidra:**
   ```bash
   cd /home/matteius/ghidra
   ./gradlew buildGhidra
   ```

2. **Re-analyze binary:**
   - Open tx-isp-t31.ko in Ghidra
   - Analysis → Auto Analyze (or clear and re-analyze)

3. **Check results:**
   - Look for "Resolved" messages in console/logs
   - Navigate to resolved calls
   - Verify decompilation improved

### Future Enhancements

**Priority 1: Multi-Level Tracking**
Implement tracking through multiple `lw` instructions for patterns like:
```assembly
lw      $a0, 0xc($a0)        # First level
lw      $t9, 0x1c($a0)       # Second level
jr      $t9
```

**Priority 2: SymbolicPropagator Integration**
Implement proper ContextEvaluator to use SymbolicPropagator:
```java
class FunctionPointerEvaluator implements ContextEvaluator {
    @Override
    public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
        if (instr is jalr/jr) {
            Varnode regVarnode = context.getRegisterVarnode(targetReg);
            // Resolve function pointer from Varnode
        }
        return false;
    }
}
```

**Priority 3: Fix MipsSwitchTableAnalyzer**
Add validation to reject string data:
```java
// Check if entry points to executable memory
if (!memory.getBlock(targetAddr).isExecute()) {
    continue;
}

// Check if entry is ASCII text
if (isLikelyAsciiString(entry)) {
    continue;
}
```

---

## 📝 Files Modified

### MipsFunctionPointerAnalyzer.java
**Total Lines:** 525 (was 510)  
**Lines Added:** ~50  
**Lines Modified:** ~30

**Key Methods:**
- `findFunctionPointerTarget()` - Simplified to use backward tracking only
- `findFunctionPointerTargetSimple()` - Enhanced with better logging and structure
- `tryResolveFromReferences()` - NEW - Try existing data references
- `tryResolveFromOperands()` - NEW - Try parsing operands

**Build Status:** ✅ SUCCESS

---

## 🎯 Summary

**Status:** ✅ CODE COMPLETE - Ready for testing  
**Build:** ✅ SUCCESSFUL  
**Documentation:** ✅ COMPLETE

The analyzer now:
1. ✅ Detects both `jalr` and `jr` instructions
2. ✅ Creates appropriate reference types
3. ✅ Uses enhanced backward tracking (100 instruction limit)
4. ✅ Has detailed debug logging
5. ✅ Validates resolved addresses point to code
6. ✅ Suppresses decompiler warnings with jump table overrides

**Next:** User needs to rebuild Ghidra and re-analyze to see results! 🚀

The success rate will depend on how many indirect calls use patterns that can be resolved with simple backward tracking (global function pointers, direct loads). Register-relative patterns will require future enhancements.

