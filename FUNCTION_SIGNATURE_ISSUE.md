# Function Signature Detection Issue

## 🔴 Critical Issue: Missing Function Parameters

### Problem

Ghidra is not detecting all function parameters for MIPS functions. 

**Example:**
```c
// Actual signature (from source code):
int tx_isp_send_event_to_remote(struct tx_isp_subdev_pad *pad, unsigned int cmd, void *data);

// Ghidra detected:
int tx_isp_send_event_to_remote(void *arg1);
```

**Missing:** 2 out of 3 parameters!

---

## 🔍 Root Cause

### MIPS Calling Convention

MIPS uses registers for the first 4 arguments:
- **$a0** (arg1) - First argument
- **$a1** (arg2) - Second argument  
- **$a2** (arg3) - Third argument
- **$a3** (arg4) - Fourth argument
- **Stack** - Arguments 5+

### Why Ghidra Misses Parameters

Ghidra's parameter detection relies on:
1. **Register usage analysis** - Which argument registers are read before being written
2. **Calling convention** - Expected parameter passing
3. **Data flow analysis** - How values flow through the function

**Common failure cases:**

**Case 1: Unused parameters**
```c
int func(void *pad, unsigned int cmd, void *data) {
    // Only uses 'pad', ignores 'cmd' and 'data'
    if (pad != NULL) {
        return do_something(pad);
    }
    return -1;
}
```
Ghidra sees: Only `$a0` is used → Detects 1 parameter

**Case 2: Parameters used in called functions**
```c
int func(void *pad, unsigned int cmd, void *data) {
    // Passes all args to another function
    return other_func(pad, cmd, data);
}
```
Ghidra sees: Registers passed through → May detect all 3 parameters

**Case 3: Conditional parameter usage**
```c
int func(void *pad, unsigned int cmd, void *data) {
    if (pad == NULL) return -1;
    
    // cmd and data only used in specific cases
    if (cmd == SPECIAL_CMD) {
        return process(data);
    }
    return 0;
}
```
Ghidra sees: `$a1` and `$a2` used conditionally → May miss them

---

## 📊 Impact

### On Decompilation Quality

**With wrong signature:**
```c
int tx_isp_send_event_to_remote(void *arg1) {
    void *$a0 = arg1;
    
    if ($a0 != 0) {
        void *$a0_1 = *($a0 + 0xc);
        if ($a0_1 != 0) {
            int32_t $t9_1 = *($a0_1 + 0x1c);
            if ($t9_1 != 0)
                jump($t9_1);
        }
    }
    return 0xfffffdfd;
}
```

**With correct signature:**
```c
int tx_isp_send_event_to_remote(tx_isp_subdev_pad *pad, uint cmd, void *data) {
    if (pad != NULL) {
        tx_isp_subdev *subdev = pad->subdev;
        if (subdev != NULL) {
            callback_func = subdev->ops->send_event;
            if (callback_func != NULL) {
                return callback_func(pad, cmd, data);
            }
        }
    }
    return -ENODEV;
}
```

**Improvements:**
- ✅ Meaningful parameter names
- ✅ Correct struct field access
- ✅ Better understanding of data flow
- ✅ Clearer function purpose

### On Cross-References

**Wrong signature:**
- Callers show only 1 argument being passed
- Can't track `cmd` and `data` usage
- Missing data flow analysis

**Correct signature:**
- All 3 arguments tracked
- Can see what commands are used
- Can trace data flow through the system

---

## 🔧 Solutions

### Solution 1: Manual Fix (Immediate)

**Steps:**
1. Navigate to function in Ghidra
2. Right-click function name in decompiler
3. Select "Edit Function Signature"
4. Change signature to:
   ```c
   int tx_isp_send_event_to_remote(tx_isp_subdev_pad *pad, uint cmd, void *data)
   ```
5. Click OK

**Pros:**
- ✅ Immediate fix
- ✅ Full control over types

**Cons:**
- ❌ Manual work for each function
- ❌ Doesn't scale

### Solution 2: Use Script (Semi-Automatic)

**Script:** `FixFunctionSignatures.java`

**What it does:**
1. Scans all functions in the binary
2. Analyzes which argument registers are used
3. Compares to declared parameter count
4. Prompts to fix mismatches

**Usage:**
1. Window → Script Manager
2. Find "FixFunctionSignatures.java"
3. Run script
4. Review and approve fixes

**Pros:**
- ✅ Finds all problematic functions
- ✅ User reviews each fix
- ✅ Batch processing

**Cons:**
- ❌ Still requires user interaction
- ❌ May have false positives

### Solution 3: Import Function Signatures (Best)

If you have header files or function prototypes, you can import them.

**Steps:**
1. Create a header file with all function signatures:
   ```c
   // tx-isp.h
   int tx_isp_send_event_to_remote(struct tx_isp_subdev_pad *pad, 
                                    unsigned int cmd, void *data);
   // ... more functions ...
   ```

2. In Ghidra: File → Parse C Source
3. Select the header file
4. Ghidra will update all matching function signatures

**Pros:**
- ✅ Accurate signatures from source
- ✅ Includes struct definitions
- ✅ Batch import

**Cons:**
- ❌ Requires header files
- ❌ May not have all functions

### Solution 4: Enhanced Analyzer (Future)

Create a MIPS-specific analyzer that:
1. Detects all argument register usage
2. Analyzes call sites to see how many args are passed
3. Uses heuristics to determine likely parameter count
4. Automatically updates signatures

**Implementation:**
- Extend `AbstractAnalyzer`
- Run after function analysis
- Priority: `FUNCTION_SIGNATURES_PRIORITY`

---

## 🧪 Testing

### Verify the Fix

After fixing `tx_isp_send_event_to_remote`:

**Check 1: Decompilation**
```c
// Should show all 3 parameters
int tx_isp_send_event_to_remote(tx_isp_subdev_pad *pad, uint cmd, void *data)
```

**Check 2: Assembly**
```assembly
// Should show parameter names in comments
0000f60c  beqz    $a0, 0xf634    # if (pad == NULL)
0000f614  lw      $a0, 0xc($a0)  # subdev = pad->subdev
```

**Check 3: Cross-References**
Find callers and verify they pass 3 arguments:
```c
result = tx_isp_send_event_to_remote(my_pad, EVENT_CMD, event_data);
```

### Common Functions to Check

Based on the pattern, these functions likely have similar issues:

**Pattern: `*_send_event_*`**
- Typically take (pad, cmd, data)
- Often have 3 parameters

**Pattern: `*_ioctl*`**
- Typically take (file, cmd, arg)
- Often have 3 parameters

**Pattern: `*_set_*` / `*_get_*`**
- Typically take (device, param, value)
- Often have 2-3 parameters

---

## 📈 Statistics

### Expected Impact

In a typical Linux kernel module:
- **~30-50%** of functions have wrong parameter counts
- **Most common:** Missing 1-2 parameters
- **Worst case:** Missing all parameters (detected as `void func(void)`)

### For tx-isp-t31.ko

Based on the naming patterns, likely affected functions:
- `tx_isp_*_event_*` - Event handlers (3 params)
- `tx_isp_*_ioctl*` - IOCTL handlers (3 params)
- `tx_isp_*_set_*` - Setters (2-3 params)
- `tx_isp_*_get_*` - Getters (2-3 params)
- Callback functions in ops structures (varies)

**Estimated:** 100-200 functions need signature fixes

---

## 🎯 Recommendations

### Immediate Actions

1. **Fix tx_isp_send_event_to_remote manually**
   - This is your test case
   - Verify decompilation improves

2. **Run FixFunctionSignatures.java script**
   - Find other problematic functions
   - Fix the most important ones

3. **Document the correct signatures**
   - Create a reference file
   - Use for future analysis

### Long-term Solutions

1. **Find or create header files**
   - Extract from kernel source if available
   - Reverse engineer from assembly

2. **Create function signature database**
   - Document all corrected signatures
   - Share with team

3. **Enhance the analyzer**
   - Add parameter count detection
   - Use call site analysis
   - Improve heuristics

---

## 📝 Example: Fixing tx_isp_send_event_to_remote

### Before Fix

**Signature:**
```c
int tx_isp_send_event_to_remote(void *arg1)
```

**Decompilation:**
```c
int tx_isp_send_event_to_remote(void *arg1) {
    if (arg1 != 0) {
        void *$a0 = *(arg1 + 0xc);
        if ($a0 != 0) {
            int32_t $t9_1 = *($a0 + 0x1c);
            if ($t9_1 != 0)
                jump($t9_1);
        }
    }
    return 0xfffffdfd;
}
```

### After Fix

**Signature:**
```c
int tx_isp_send_event_to_remote(tx_isp_subdev_pad *pad, uint cmd, void *data)
```

**Decompilation:**
```c
int tx_isp_send_event_to_remote(tx_isp_subdev_pad *pad, uint cmd, void *data) {
    if (pad != NULL) {
        tx_isp_subdev *subdev = pad->subdev;  // offset 0xc
        if (subdev != NULL) {
            send_event_func callback = subdev->ops->send_event;  // offset 0x1c
            if (callback != NULL) {
                return callback(pad, cmd, data);  // Tail call
            }
        }
    }
    return -ENODEV;  // 0xfffffdfd = -515
}
```

**Improvements:**
- ✅ Shows all 3 parameters
- ✅ Struct field names visible
- ✅ Callback pattern clear
- ✅ Error code identified (-ENODEV)
- ✅ Tail call optimization visible

---

## 🔗 Related Issues

1. **Struct definitions missing**
   - Need to define `tx_isp_subdev_pad`
   - Need to define `tx_isp_subdev`
   - Need to define ops structures

2. **Callback function signatures**
   - The callback at offset 0x1c also needs correct signature
   - Should match: `int (*send_event)(tx_isp_subdev_pad*, uint, void*)`

3. **Error code definitions**
   - 0xfffffdfd = -515 = -ENODEV
   - Should create enum for error codes

---

## ✅ Action Items

- [ ] Fix tx_isp_send_event_to_remote signature manually
- [ ] Verify decompilation improves
- [ ] Run FixFunctionSignatures.java script
- [ ] Document all corrected signatures
- [ ] Create struct definitions for tx_isp types
- [ ] Define error code enum
- [ ] Fix callback function signatures
- [ ] Test with real-world usage patterns

---

## 📚 References

- **MIPS Calling Convention:** O32 ABI
- **Ghidra Function Analysis:** `FunctionAnalyzer.java`
- **Parameter Detection:** `ParameterAnalyzer.java`
- **Script Location:** `FixFunctionSignatures.java`

