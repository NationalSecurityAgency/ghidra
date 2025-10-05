# MIPS Switch Table Analysis - Key Findings

## Current Implementation Analysis

### MipsAddressAnalyzer.java - Existing Switch Table Support

**Location:** Lines 452-709

**Current Behavior:**
- Switch table detection is **DISABLED by default** (`OPTION_DEFAULT_SWITCH_TABLE = false`)
- Only triggers on `jr` instruction (line 454)
- Uses backward search pattern to find:
  1. `sltiu` instruction → table size (lines 629-639)
  2. `addiu` instruction → table address (lines 643-651)
  3. `sll` instruction → value size (lines 655-658)
  4. `lw` instruction → alternative value size detection (lines 660-662)

**Limitations Identified:**

1. **Too Restrictive Pattern Matching:**
   - Only looks for exact sequence: `sltiu` → `addiu` → `jr`
   - Fails if compiler reorders instructions
   - Doesn't handle PIC code patterns ($gp-relative)
   - Doesn't handle LLVM patterns

2. **Limited Bounds Detection:**
   - Only recognizes `sltiu` for bounds (line 629)
   - Misses `sltu`, `bne`, `beq` patterns
   - Table size limited to 255 entries (line 636) - too restrictive!

3. **No Inline Handler Detection:**
   - Assumes all targets are already disassembled
   - Doesn't check if targets are in "data" regions

4. **Weak Table Address Detection:**
   - Relies on existing lui/addiu markup (line 642)
   - Fails if constant propagation didn't find the pair
   - No fallback mechanisms

### JvmSwitchAnalyzer.java - Good Patterns to Adopt

**Key Strengths:**
1. **Explicit Reference Creation** (lines 226-228):
   ```java
   program.getReferenceManager().addMemoryReference(
       switchInstruction.getMinAddress(), target,
       RefType.COMPUTED_JUMP, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
   ```

2. **Namespace Organization** (lines 232-243):
   - Creates namespace for each switch statement
   - Groups all case labels together
   - Makes navigation easier

3. **Function Body Fixup** (lines 252-274):
   - Adds all case targets to function body
   - Calls `CreateFunctionCmd.fixupFunctionBody()`
   - Ensures complete control flow

### AddressTable.java - Core Infrastructure

**Key Methods:**
- `getEntry()` - Validates and creates address tables
- `createSwitchTable()` - Creates references and labels
- Handles shifted pointers, negative tables, index tables

## Real-World Test Case: tx-isp-t31.ko

### Function: ispcore_irq_fs_work @ 0x665f8

**Decompiled Output (Broken):**
```c
if (i u< 7)
    jump((&data_6de20)[i])
```

**Expected Pattern in Assembly:**
```mips
# Bounds check
sltiu   $v0, $s0, 7        # if (i < 7)
beqz    $v0, default_case  # branch if out of bounds

# Table load
lui     $v1, %hi(data_6de20)
addiu   $v1, $v1, %lo(data_6de20)
sll     $v0, $s0, 2        # i * 4 (pointer size)
addu    $v0, $v0, $v1      # table_base + offset
lw      $v0, 0($v0)        # load jump target
jr      $v0                # indirect jump
nop                        # delay slot
```

**Why Current Analyzer Fails:**
1. May not find the `lui/addiu` pair if constant propagation failed
2. Pattern matching is too rigid - expects exact instruction order
3. Doesn't handle case where table is in data section
4. No verification that targets are valid code

## Proposed Enhancements

### 1. Enhanced Pattern Recognition

**Support Multiple Compiler Patterns:**

#### GCC -O2/-O3 Pattern:
```mips
sltiu   $reg, $index, SIZE
beqz    $reg, default
lui     $base, %hi(table)
addiu   $base, $base, %lo(table)
sll     $offset, $index, 2
addu    $target, $base, $offset
lw      $target, 0($target)
jr      $target
```

#### PIC Code Pattern:
```mips
sltiu   $reg, $index, SIZE
beqz    $reg, default
lw      $base, %got(table)($gp)  # $gp-relative
sll     $offset, $index, 2
addu    $target, $base, $offset
lw      $target, 0($target)
jr      $target
```

#### LLVM Pattern (may vary):
```mips
sltu    $reg, $index, SIZE  # Note: sltu not sltiu
bnez    $reg, in_range
# ... different table access pattern
```

### 2. Improved Detection Algorithm

```java
public class MipsSwitchTableAnalyzer extends AbstractAnalyzer {
    
    private SwitchTableInfo detectSwitchTable(Program program, Instruction jrInstr) {
        // 1. Verify this is a jr instruction
        if (!jrInstr.getMnemonicString().equals("jr")) {
            return null;
        }
        
        // 2. Find bounds check (multiple patterns)
        BoundsCheck bounds = findBoundsCheck(program, jrInstr);
        if (bounds == null || bounds.size > 1024) {  // Increased limit
            return null;
        }
        
        // 3. Find table base (multiple strategies)
        Address tableBase = findTableBase(program, jrInstr, bounds);
        if (tableBase == null) {
            return null;
        }
        
        // 4. Extract targets with validation
        List<Address> targets = extractAndValidateTargets(
            program, tableBase, bounds.size);
        if (targets.isEmpty()) {
            return null;
        }
        
        // 5. Check for inline handlers
        for (Address target : targets) {
            if (isInDataRegion(program, target)) {
                if (looksLikeCode(program, target)) {
                    disassembleInlineHandler(program, target);
                }
            }
        }
        
        return new SwitchTableInfo(jrInstr.getAddress(), 
                                   tableBase, targets, bounds);
    }
    
    private BoundsCheck findBoundsCheck(Program program, Instruction jrInstr) {
        // Search backward for bounds check patterns
        // Support: sltiu, sltu, bne, beq, bgtz, etc.
        // Look within reasonable distance (e.g., 20 instructions)
        // Handle both direct and inverted comparisons
    }
    
    private Address findTableBase(Program program, Instruction jrInstr, 
                                   BoundsCheck bounds) {
        // Strategy 1: Look for lui/addiu pair
        // Strategy 2: Look for $gp-relative load
        // Strategy 3: Use symbolic propagation
        // Strategy 4: Search for data references near jr
    }
    
    private boolean looksLikeCode(Program program, Address addr) {
        // Use PseudoDisassembler to check if bytes look like valid MIPS
        // Check for valid instruction patterns
        // Avoid false positives on data
    }
}
```

### 3. Integration Points

**MipsAddressAnalyzer.java modifications:**
```java
// Line 452-457: Replace simple check with enhanced analyzer
if (trySwitchTables) {
    String mnemonic = instruction.getMnemonicString();
    if (mnemonic.equals("jr")) {
        // Use new enhanced analyzer
        MipsSwitchTableAnalyzer switchAnalyzer = 
            new MipsSwitchTableAnalyzer();
        switchAnalyzer.analyzeSwitchTable(program, instruction, 
                                          context, monitor);
    }
}
```

## Success Criteria

For tx-isp-t31.ko `ispcore_irq_fs_work`:
- ✅ Detect jump table at data_6de20
- ✅ Identify 7 case targets
- ✅ Create proper switch statement in decompiler
- ✅ Show case labels (case 0-6)
- ✅ Handle case 5 (continue/empty case)

## Next Steps

1. ✅ Complete analysis of existing code
2. ⏳ Create MipsSwitchTableAnalyzer.java skeleton
3. ⏳ Implement enhanced pattern detection
4. ⏳ Test against tx-isp-t31.ko
5. ⏳ Iterate until decompilation matches expected output

