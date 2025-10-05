# Test Case Analysis: tx-isp-t31.ko - ispcore_irq_fs_work

## Function Details
- **Address:** 0x665f8
- **Name:** ispcore_irq_fs_work
- **Binary:** tx-isp-t31.ko (MIPS kernel module)

## Assembly Analysis

### Key Instructions (Switch Table Pattern)

```mips
# Function prologue
665f8:  8c7500d4    lw      s5,212(v1)          # Load pointer
665fc:  12a00036    beqz    s5,666d8            # Check if null

# Setup
66604:  3c130000    lui     s3,0x0              # Load high part of table base
66620:  26733b70    addiu   s3,s3,15216         # s3 = 0x3b70 (table base offset)

# Loop iteration
66624:  8e420000    lw      v0,0(s2)            # Load value
66628:  50400028    beqzl   v0,666cc            # Skip if zero

# Special case: i == 5
66630:  12360025    beq     s1,s6,666c8         # if (i == 5) goto continue

# BOUNDS CHECK - This is what we need to detect!
66634:  2e220007    sltiu   v0,s1,7             # v0 = (s1 < 7) ? 1 : 0
66638:  10400016    beqz    v0,66694            # if (v0 == 0) goto default

# TABLE LOAD - This is the switch table access!
6663c:  00111080    sll     v0,s1,0x2           # v0 = s1 * 4 (index * sizeof(ptr))
66640:  02621021    addu    v0,s3,v0            # v0 = table_base + offset
66644:  8c420000    lw      v0,0(v0)            # v0 = table[index]

# INDIRECT JUMP - This is what triggers our analyzer!
66648:  00400008    jr      v0                  # jump to v0
6664c:  00000000    nop                         # delay slot

# Case handlers (inline code after the jump table logic)
66650:  3c100200    lui     s0,0x200            # case 0: s0 = 0x200
66654:  1000000f    b       66694               # goto common_code
66658:  26100008    addiu   s0,s0,8             # s0 = 0x200 + 8 (delay slot)

6665c:  3c100200    lui     s0,0x200            # case 1: s0 = 0x200
66660:  1000000c    b       66694               # goto common_code
66664:  26100009    addiu   s0,s0,9             # s0 = 0x200 + 9 (delay slot)

66668:  3c100200    lui     s0,0x200            # case 2: s0 = 0x200
6666c:  10000009    b       66694               # goto common_code
66670:  26100005    addiu   s0,s0,5             # s0 = 0x200 + 5 (delay slot)

66674:  3c100200    lui     s0,0x200            # case 3: s0 = 0x200
66678:  10000006    b       66694               # goto common_code
6667c:  26100006    addiu   s0,s0,6             # s0 = 0x200 + 6 (delay slot)

66680:  3c100200    lui     s0,0x200            # case 4: s0 = 0x200
66684:  10000003    b       66694               # goto common_code
66688:  26100016    addiu   s0,s0,22            # s0 = 0x200 + 22 (delay slot)

6668c:  3c100200    lui     s0,0x200            # case 6: s0 = 0x200
66690:  26100007    addiu   s0,s0,7             # s0 = 0x200 + 7

# Common code after switch
66694:  8e420004    lw      v0,4(s2)            # Continue execution
```

## Jump Table Data

### Table Location
- **Virtual Address:** 0x6de40 (calculated from 0x0 + 0x3b70 offset, but actual is 0x6de40)
- **File Offset:** 0x6de40
- **Section:** .rodata
- **Size:** 7 entries × 4 bytes = 28 bytes

### Table Contents (Little Endian)

```
Offset    Bytes (LE)      Address     Target Function/Label
------    ----------      -------     ---------------------
0x6de40:  8c 66 06 00  →  0x06668c    case 0 handler
0x6de44:  50 66 06 00  →  0x066650    case 1 handler  
0x6de48:  5c 66 06 00  →  0x06665c    case 2 handler
0x6de4c:  68 66 06 00  →  0x066668    case 3 handler
0x6de50:  74 66 06 00  →  0x066674    case 4 handler
0x6de54:  94 66 06 00  →  0x066694    case 5 handler (default/continue)
0x6de58:  80 66 06 00  →  0x066680    case 6 handler
```

### Note on Table Address Discrepancy
The code shows:
```mips
3c130000    lui     s3,0x0              # s3 = 0x0 << 16
26733b70    addiu   s3,s3,15216         # s3 = 0x0 + 0x3b70 = 0x3b70
```

But the actual table is at 0x6de40. This suggests:
1. The `lui s3,0x0` will be **relocated** by the kernel module loader
2. The relocation will set it to `lui s3,0x6` so that 0x60000 + 0x3b70 = 0x63b70
3. OR there's a base address that gets added

Actually, looking more carefully at the disassembly, the table should be at:
- Base from `lui s3,0x0` + `addiu s3,s3,15216` = 0x3b70
- But this is a **kernel module** with relocations
- The actual loaded address will be different

Let me recalculate: 0x3b70 in the context of the module... The table is in .rodata at offset 0x3b70 from the start of .rodata section (0x6a2d0), so:
- 0x6a2d0 + 0x3b70 = 0x6de40 ✓ This matches!

## Pattern Detection Requirements

### What Our Analyzer Must Detect:

1. **Indirect Jump Pattern:**
   - `jr $reg` instruction at 0x66648

2. **Bounds Check (within 30 instructions before jr):**
   - `sltiu v0, s1, 7` at 0x66634
   - Immediate value = 7 (table size)
   - Index register = s1

3. **Table Base Calculation:**
   - `lui s3, 0x0` (will be relocated)
   - `addiu s3, s3, 15216` at 0x66620
   - Reference to address 0x6de40 (after relocation)

4. **Table Access Pattern:**
   - `sll v0, s1, 0x2` (multiply index by 4)
   - `addu v0, s3, v0` (add base + offset)
   - `lw v0, 0(v0)` (load target address)

5. **Inline Handlers:**
   - All case handlers are inline code (not separate functions)
   - Located immediately after the jump table logic
   - Each handler is 2-3 instructions followed by branch to common code

## Expected Decompiler Output

### Current (Broken):
```c
if (i u< 7)
    jump((&data_6de20)[i])  // Raw jump - not recognized as switch
```

### Expected (Fixed):
```c
switch (i) {
    case 0:
        s0 = 0x200 + 8;
        break;
    case 1:
        s0 = 0x200 + 9;
        break;
    case 2:
        s0 = 0x200 + 5;
        break;
    case 3:
        s0 = 0x200 + 6;
        break;
    case 4:
        s0 = 0x200 + 22;
        break;
    case 5:
        // continue (handled specially before switch)
        break;
    case 6:
        s0 = 0x200 + 7;
        break;
}
```

## Challenges for Our Analyzer

1. **Relocation Handling:**
   - The `lui s3, 0x0` will be relocated at runtime
   - We need to follow the relocation to find the actual table address
   - Ghidra should have already processed relocations

2. **Inline Handler Detection:**
   - Handlers are not separate functions
   - They're inline code that looks like data
   - Need to use PseudoDisassembler to verify they're valid code

3. **Special Case Handling:**
   - Case 5 is handled specially (beq check before the switch)
   - The table still has 7 entries including case 5

4. **Table Address Resolution:**
   - Need to find the reference created by lui/addiu pair
   - Ghidra's constant propagation should have created this reference
   - Our `findTableBase()` should look for references from the addiu instruction

## Testing Strategy

1. **Load tx-isp-t31.ko in Ghidra**
2. **Navigate to function ispcore_irq_fs_work (0x665f8)**
3. **Run our MipsSwitchTableAnalyzer**
4. **Verify it detects:**
   - jr instruction at 0x66648
   - Bounds check: sltiu with size 7
   - Table base at 0x6de40 (or 0x6de20 depending on relocation)
   - 7 target addresses
5. **Verify it creates:**
   - Switch table structure
   - References from jr to all 7 targets
   - Labels for each case
6. **Verify decompiler shows proper switch statement**

## Success Criteria

✅ Analyzer detects the switch table pattern
✅ Creates 7 references from jr instruction to case handlers
✅ Labels created: case_0 through case_6
✅ Decompiler shows `switch(i)` instead of `jump((&data_6de20)[i])`
✅ All case handlers properly recognized as code
✅ Control flow graph shows proper switch structure

