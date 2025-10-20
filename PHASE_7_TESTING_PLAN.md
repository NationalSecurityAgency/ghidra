# Phase 7: Testing & Validation Plan

## 📋 Overview

**Phase:** 7/9 (Testing & Validation)  
**Status:** IN_PROGRESS  
**Tasks:** 12 total  
**Objective:** Validate all analyzer implementations through comprehensive testing

---

## 🎯 Testing Strategy

### 1. Real-World Binary Testing (Priority 1)
**Why First:** Provides immediate feedback on practical effectiveness

**Test Binary:** `tx-isp-t31.ko` (MIPS kernel module)
- **Target Function:** `ispcore_irq_fs_work` @ 0x665f8
- **Switch Table:** 7 entries at 0x6de40
- **Pattern:** GCC -O2 with lui/addiu table base calculation

**Success Criteria:**
- ✅ Switch table detected at 0x6de40
- ✅ All 7 case targets identified
- ✅ Decompiler generates proper switch statement
- ✅ No false positives in surrounding code

### 2. Unit Tests (Priority 2)
**Why Second:** Validates individual components in isolation

**Test Coverage:**
- Pattern detection algorithms
- Bounds check recognition
- Table base calculation
- Constant propagation
- Reference creation

### 3. Integration Tests (Priority 3)
**Why Third:** Validates end-to-end analyzer workflows

**Test Binaries Needed:**
- `gcc_o0_switch.elf` - GCC -O0 optimization
- `gcc_o3_switch.elf` - GCC -O3 optimization
- `llvm_switch.elf` - LLVM compiler
- `pic_switch.elf` - Position-independent code
- `inline_handlers.elf` - Inline case handlers
- `vtable_example.elf` - Virtual function tables
- `callback_struct.elf` - Function pointer structs

### 4. Performance Benchmarking (Priority 4)
**Why Last:** Ensures implementation meets performance requirements

**Metrics:**
- Analysis time increase (must be <10%)
- Memory usage
- Detection rate (target >95%)
- False positive rate (target <0.1%)

---

## 📊 Test Task Breakdown

### Task 1: Real-World Binary Testing ⏳
**Status:** IN_PROGRESS  
**Binary:** `tx-isp-t31.ko`  
**Steps:**
1. ✅ Build Ghidra with new analyzers
2. ⏳ Import `tx-isp-t31.ko` into Ghidra
3. ⏳ Run auto-analysis with new analyzers enabled
4. ⏳ Navigate to `ispcore_irq_fs_work` @ 0x665f8
5. ⏳ Verify switch table detection at 0x6de40
6. ⏳ Check decompiler output for switch statement
7. ⏳ Validate all 7 case targets are correct
8. ⏳ Check for false positives

**Expected Results:**
```c
// Before (current Ghidra):
void ispcore_irq_fs_work(void) {
    // Unrecognized control flow
    // Missing case handlers
}

// After (with our analyzers):
void ispcore_irq_fs_work(void) {
    switch (irq_type) {
        case 0: handle_case_0(); break;
        case 1: handle_case_1(); break;
        case 2: handle_case_2(); break;
        case 3: handle_case_3(); break;
        case 4: handle_case_4(); break;
        case 5: handle_case_5(); break;
        case 6: handle_case_6(); break;
    }
}
```

### Task 2: Create Unit Tests for Pattern Detection
**Status:** NOT_STARTED  
**Files to Create:**
- `MipsSwitchTableAnalyzerTest.java`
- `MipsInlineCodeAnalyzerTest.java`
- `MipsFunctionPointerAnalyzerTest.java`

**Test Cases:**
1. **GCC Non-PIC Pattern:**
   - lui/addiu table base calculation
   - sltiu bounds check
   - jr $reg indirect jump

2. **GCC PIC Pattern:**
   - $gp-relative addressing
   - lw with $gp offset
   - jr $reg indirect jump

3. **LLVM Pattern:**
   - sltu bounds check (register comparison)
   - Different table base calculation
   - jr $reg indirect jump

4. **Edge Cases:**
   - Empty switch (no cases)
   - Single case switch
   - Large switch (>255 entries)
   - Nested switches
   - Switch with default case only

### Task 3: Create Unit Tests for PCode Generation
**Status:** NOT_STARTED  
**Objective:** Verify PCode generation for switch statements

**Note:** Based on Phase 5 findings, we discovered that:
- ✅ SLEIGH already generates correct BRANCHIND PCode for `jr` instructions
- ✅ No PCode modifications needed
- ✅ JumpTable.writeOverride() mechanism handles decompiler integration

**Test Approach:**
- Verify that JumpTable.writeOverride() creates correct labels
- Verify that decompiler reads override labels correctly
- Test with various switch table sizes

### Task 4: Create Unit Tests for Control Flow Graph
**Status:** NOT_STARTED  
**Objective:** Validate CFG construction for switch statements

**Test Cases:**
1. Verify COMPUTED_JUMP references update CFG
2. Verify all case targets appear in CFG
3. Verify fall-through relationships preserved
4. Verify default case handling

### Task 5-9: Integration Tests
**Status:** NOT_STARTED  
**Binaries Needed:** 7 test binaries (see list above)

**For Each Binary:**
1. Import into Ghidra
2. Run auto-analysis
3. Verify detection rate
4. Check decompiler output
5. Validate no false positives

### Task 10: Real-World Binary Testing (Extended)
**Status:** NOT_STARTED  
**Additional Binaries:**
- Linux kernel modules (various architectures)
- Embedded firmware (routers, IoT devices)
- Game console executables (PSP, PS2, etc.)
- Network equipment firmware

### Task 11: Performance Benchmarking
**Status:** NOT_STARTED  
**Metrics to Measure:**
- Analysis time (before vs after)
- Memory usage (before vs after)
- Detection rate (% of switches found)
- False positive rate (% of incorrect detections)

**Benchmark Binaries:**
- Small binary (~100 functions)
- Medium binary (~1000 functions)
- Large binary (~10000 functions)

### Task 12: Validate Success Metrics
**Status:** NOT_STARTED  
**Success Criteria:**
- ✅ Detection rate >95%
- ✅ False positive rate <0.1%
- ✅ Code coverage >90%
- ✅ Analysis time increase <10%
- ✅ Qualitative improvement in decompiler output

---

## 🔧 Testing Tools

### Ghidra Headless Analyzer
For automated testing:
```bash
analyzeHeadless /path/to/project ProjectName \
  -import /path/to/binary \
  -postScript TestScript.java \
  -scriptPath /path/to/scripts
```

### JUnit Tests
For unit testing:
```java
@Test
public void testGccNonPicPattern() {
    // Test implementation
}
```

### Manual Testing
For qualitative validation:
1. Open binary in Ghidra GUI
2. Run auto-analysis
3. Navigate to test functions
4. Verify decompiler output

---

## 📈 Progress Tracking

### Completed
- ✅ Build verification (compileJava successful)

### In Progress
- ⏳ Real-world binary testing (tx-isp-t31.ko)

### Not Started
- ⏸️ Unit tests
- ⏸️ Integration tests
- ⏸️ Performance benchmarking
- ⏸️ Success metrics validation

---

## 🚀 Next Steps

1. **Immediate:** Test against `tx-isp-t31.ko`
   - Import binary into Ghidra
   - Run auto-analysis
   - Verify switch table detection
   - Check decompiler output

2. **Short-term:** Create unit tests
   - MipsSwitchTableAnalyzerTest.java
   - MipsInlineCodeAnalyzerTest.java
   - MipsFunctionPointerAnalyzerTest.java

3. **Medium-term:** Integration tests
   - Create test binaries
   - Run comprehensive test suite
   - Validate detection rates

4. **Long-term:** Performance benchmarking
   - Measure analysis time
   - Validate success metrics
   - Document results

---

## 📝 Notes

### Build Status
- ✅ All Java code compiles successfully
- ✅ No compilation errors
- ✅ MIPS module builds correctly
- ✅ Analyzers registered in .pspec files

### Known Limitations
- Test binaries need to be created (gcc_o0_switch.elf, etc.)
- Unit test framework needs to be set up
- Performance baseline needs to be established

### Dependencies
- Ghidra installation: `/home/matteius/ghidra`
- Test binary: `/home/matteius/ghidra/tx-isp-t31.ko`
- Gradle build system: Working correctly

---

## ✅ Success Indicators

When testing is complete, we should see:
1. ✅ Switch tables detected in real-world binaries
2. ✅ Decompiler generates proper switch statements
3. ✅ No false positives
4. ✅ Performance within acceptable bounds
5. ✅ All unit tests passing
6. ✅ All integration tests passing
7. ✅ Success metrics validated

**Current Status:** Ready to begin real-world binary testing! 🎯

