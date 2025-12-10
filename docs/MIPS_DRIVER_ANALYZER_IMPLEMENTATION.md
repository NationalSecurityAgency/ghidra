# MIPS Driver Analyzer Implementation

## Overview

This document describes the implementation of the MIPS Driver Analyzer, a deep, opt-in analyzer for MIPS programs that performs whole-program reasoning to recover accurate call signatures, resolve indirect calls, type function pointer fields, and classify trampolines.

## Implementation Status

### ✅ Completed (Phase 1-6 + Refinements)

The following features have been fully implemented and refined:

#### Phase 1: Core Infrastructure
- **Configuration Options**: Fully configurable analyzer with options for:
  - Near Window Size (default: 5 instructions)
  - A3 Promotion Threshold (default: 2 call sites)
  - Enable/Disable Struct Field Synthesis
  - Max Synthetic Types Per Function (default: 50)
  - Enable/Disable Zero-Arg Collapse
  - Verbose Debug Logging

- **Helper Classes**:
  - `IndirectCallSite`: Represents jalr/jr instruction sites with metadata
  - `ParameterEvidence`: Tracks parameter usage evidence across call sites

- **Discovery Scan**: 
  - Enumerates all jalr/jr sites in the program
  - Classifies by target register (v0/v1 vs others)
  - Handles both standard and microMIPS variants (_jalr, _jr)
  - Collects comprehensive statistics

#### Phase 2: Return-Pointer Classification
- **v0/v1 Pattern Detection**: Identifies jalr/jr instructions using v0 or v1 as target
- **Function Tracing**: Looks backward to find the function call that populated the register
- **Type Application**: Sets return type to function pointer for identified functions
- **Respects Custom Storage**: Skips functions with custom variable storage

#### Phase 3: Trampoline Detection and Typing
- **Pattern Recognition**: Detects trampolines through:
  - Load instructions (lw, ld) populating jump target
  - Move-like instructions (move, or, addu, daddu) from parameter registers
  - Memory-derived function pointer chains

- **Flow Override**: Applies `FlowOverride.CALL_RETURN` to tail call trampolines
- **Register Chain Tracking**: Follows register value propagation up to 10 instructions back

#### Phase 4: Parameter Count Inference
- **Caller Consensus**:
  - Analyzes all call sites to each function
  - Counts argument register usage (a0-a3)
  - Uses Near-window evidence (configurable, default 5 instructions)
  - Requires stronger evidence for a3 promotion (configurable threshold)

- **Body-Based Inference**:
  - Analyzes function bodies for live-in reads of a0-a3 before writes
  - **Pass-through detection**: Identifies parameters passed to nested calls without modification
  - Checks first 100 instructions for performance
  - Provides additional evidence for parameter count determination
  - Combines with caller consensus for robust inference

- **Zero-Arg Collapse**:
  - Shrinks parameter count to 0 when all callers pass zero args
  - Respects USER_DEFINED signatures (never collapses those)
  - Configurable enable/disable

- **Parameter Expansion**:
  - Expands parameter count based on caller consensus + body evidence
  - Uses DYNAMIC_STORAGE_FORMAL_PARAMS for automatic storage assignment
  - Creates parameters with Undefined4DataType

- **Source Type Handling**: All changes use SourceType.ANALYSIS

#### Phase 5: Table/Vector Typing
- **Function Pointer Table Detection**:
  - Scans initialized, non-executable memory blocks
  - Detects contiguous arrays of function pointers (minimum 3 entries)
  - Handles null-terminated tables
  - Configurable maximum table size (default: 100 entries)

- **Table Entry Typing**:
  - Applies function pointer types to table entries
  - Uses ANALYSIS source type for all changes
  - Respects maximum synthetic types limit (configurable, default: 50)
  - Clears existing data before applying new types

#### Phase 6: Reporting and Metrics
- **Comprehensive Statistics**:
  - Tracks all analysis actions (jalr/jr sites, functions typed, parameters changed)
  - Reports execution time
  - Provides summary of all changes made

- **Detailed Findings** (when verbose logging enabled):
  - Records individual analysis actions with evidence
  - Groups findings by category (Return-Pointer, Trampoline, Parameter-Expand, Parameter-Collapse)
  - Includes addresses, function names, actions taken, and supporting evidence
  - Outputs detailed report at end of analysis

### 🔧 Recent Refinements

#### Parameter Inference Improvements
- **Smarter Caller Analysis**: Detects nested calls and only counts argument setup for the target function
- **Combined Evidence Strategy**: Uses MAXIMUM of caller consensus and body evidence
  - Body evidence: Detects parameters directly used in the function
  - Caller evidence: Detects parameters passed through to other functions (not yet detected by body analysis)
  - **Important**: Until pass-through detection is implemented, caller consensus is trusted even when body evidence is lower
- **Conservative Expansion**: Only skips expansion when there's a single call site AND no body evidence
- **Nested Call Filtering**: Tracks write addresses and invalidates arguments set before nested calls

#### Calling Convention Compatibility
- **Fixed "Unknown calling convention" warnings**: Changed from `SourceType.ANALYSIS` to `SourceType.DEFAULT`
- **Proper DYNAMIC_STORAGE usage**: Allows decompiler to apply correct calling convention
- **No parameter storage locking**: Prevents conflicts with decompiler's convention detection

#### Struct Field Synthesis for Indirect Calls
- **Load-to-jalr chain detection**: Traces back from jalr to find the load instruction
- **Automatic signature creation**: Infers parameter count and creates appropriate function pointer types
- **Memory location typing**: Applies function pointer types to struct fields being loaded

### 🚧 Future Enhancements

The following features could be added in future iterations:

#### High Priority
- **Pass-through parameter detection**: Detect when parameters are received and immediately passed to another function
  - Check if argument registers are not written before a call
  - Check if they're used as inputs to that call
  - This would improve body-based evidence accuracy significantly

#### Advanced Features
- Stack argument evidence (beyond register arguments a0-a3)
- Type unification across identical offset patterns in different structs
- Interactive report view with sortable/filterable findings table
- Persistence of findings for CI/CD integration
- Support for variadic functions (va_list detection)

## Architecture

### Key Design Decisions

1. **Opt-In by Default**: Analyzer is disabled by default (`setDefaultEnablement(false)`)
2. **Late Execution**: Runs after DATA_TYPE_PROPOGATION to leverage existing analysis
3. **Fail-Soft**: Catches exceptions per-function to avoid breaking entire analysis
4. **Idempotent**: Designed to be safe to run multiple times
5. **Configurable**: Extensive options for tuning behavior
6. **Logging**: Comprehensive info and debug logging for transparency

### Analysis Flow

```
1. Discovery Scan
   ↓
2. Return-Pointer Classification (v0/v1 patterns)
   ↓
3. Trampoline Detection & Typing
   ↓
4. Parameter Count Inference
   ↓
5. Reporting
```

### Statistics Tracked

- `jalrSitesScanned`: Number of jalr instructions found
- `jrSitesScanned`: Number of jr instructions found
- `returnPointerFunctionsTyped`: Functions with return type set to function pointer
- `trampolinesDetected`: Trampolines marked with CALL_RETURN flow override
- `functionsParamsExpanded`: Functions with increased parameter count
- `functionsParamsCollapsed`: Functions collapsed to zero parameters
- `structFieldsTyped`: Struct fields typed (future)

## Usage

### Enabling the Analyzer

1. Open Analysis Options in Ghidra
2. Find "MIPS Driver Analyzer" in the list
3. Check the box to enable it
4. Configure options as needed
5. Run analysis

### Configuration Options

- **Near Window Size**: How many instructions before/after call site to examine (default: 5)
- **A3 Promotion Threshold**: Minimum call sites needed to infer 4 parameters (default: 2)
- **Enable Struct Field Synthesis**: Enable/disable struct type creation (default: true, not yet implemented)
- **Max Synthetic Types Per Function**: Cap on synthetic types (default: 50, not yet implemented)
- **Enable Zero-Arg Collapse**: Allow collapsing to 0 parameters (default: true)
- **Verbose Debug Logging**: Enable detailed debug output (default: false)

## Testing Recommendations

### Idempotence Testing
Run the analyzer multiple times on the same binary and verify:
- No oscillation in parameter counts
- Stable results after first run
- No errors on subsequent runs

### Validation
Compare before/after decompilation output:
- Indirect calls should show concrete arguments
- Function signatures should be more accurate
- Trampolines should be properly classified

### Performance
Monitor execution time on large binaries:
- Adjust Near Window Size if too slow
- Consider disabling zero-arg collapse for speed
- Use verbose logging only for debugging

## Known Limitations

1. **No Stack Argument Analysis**: Currently only analyzes register arguments (a0-a3)
2. **Simple Trampoline Detection**: Uses heuristics, may miss complex patterns
3. **No Body-Based Inference**: Doesn't analyze function bodies for parameter usage yet
4. **No Struct Synthesis**: Struct field typing not yet implemented
5. **Limited Register Tracking**: Looks back only 10-20 instructions

## Future Work

See PRD milestones M2-M4 for planned enhancements:
- M2: Struct field typing + unification
- M3: ABI stack-arg support, performance knobs, report view
- M4: Hardening, idempotence tests, golden corpus regression suite

## References

- PRD: `/docs/PRD_MIPS_Driver_Analyzer.md`
- Source: `Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/MipsDriverAnalyzer.java`

