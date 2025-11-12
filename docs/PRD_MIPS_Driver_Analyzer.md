# PRD: MIPS Driver Analyzer — Deep, Slow, and Correct MIPS Program Understanding

## Summary
Build a full‑fledged, opt‑in analyzer for MIPS programs (e.g., SoC kernel modules and drivers) that performs slow but robust whole‑program reasoning to recover accurate call signatures, resolve indirect calls, type function pointer fields, and classify trampolines and driver init/ops routines. This analyzer complements Ghidra’s standard MIPS analyzers by running later with deeper, cross‑function analysis. Goal: correctness and generality first; runtime can be long.

## Problem Statement
Lightweight analyzers often:
- Miss or mis-render indirect calls in MIPS trampoline patterns (jalr/jr through register/memory chains).
- Over/under‑infer parameter counts (e.g., forcing 4 args; not collapsing true zero‑arg routines).
- Fail to type function pointer fields in nested structs/tables driving driver behavior.
- Treat v0/v1 as regular registers instead of understanding return‑pointer call chains.

Results: misleading decompile (calls printed as `(*pcVar)()`), wrong param counts, missing fp field types. Investigation becomes time‑consuming and error‑prone.

## Users
- Reverse engineers of MIPS firmware/drivers (kernel modules, ISP, DSP, SoC BSPs)
- Security researchers requiring robust decompilation for large MIPS codebases
- Internal tooling authors building automated pipelines from Ghidra output

## Goals
- Robustly resolve indirect calls in driver trampolines and return‑pointer patterns
- Infer parameter counts from caller consensus + body evidence, support true zero‑arg collapse
- Type function‑pointer returns (v0/v1) and fp fields in driver structs/tables
- Work across O32/N32/N64 ABIs; tolerate register aliasing and PIC/T9 usage
- Deterministic, auditable, log‑rich; correctness > runtime

## Non‑Goals
- General-purpose, whole‑program pointer analysis beyond pragmatic MIPS needs
- Reliance on symbol names or vendor‑specific conventions
- Manual MCP typing — analyzer must be self‑contained

## Scope and Features

### 1) Indirect Call Resolution and Trampoline Handling
- Detect jalr/jr targets via:
  - Move‑like chains (move/addu/daddu/or with zero), multi‑hop
  - Limited spills/fills on stack
  - Memory‑derived expressions, e.g., `*(code **)(*(int *)(a0 + C) + 0x1C)`
- Apply FlowOverride.CALL_RETURN on trampolines (tail calls)
- Annotate the actual operand the decompiler uses (register or memory expression) so arguments render
- Treat jalr/jr on v0/v1 as function‑pointer returns (pattern: call → jalr v0/v1)

### 2) Parameter Count Inference (General and Trampolines)
- Caller‑consensus pass with Near‑window evidence (delay slots, ±N instructions)
  - a3 promotion requires stronger evidence (≥2 sites or strong Near evidence)
- Body‑based pass: live‑in reads of a0–a3 before writes imply minimal params (1–4)
- Zero‑arg correction: shrink to 0 when callers pass zero args (unless USER_DEFINED signature)

### 3) Function Pointer Return Inference
- Identify functions whose return (v0/v1) is immediately used by jalr/jr
- Set return type to function pointer and optionally a concrete N‑arg signature inferred from use

### 4) Struct Field and Table Typing
- When resolving `load → jalr` chains:
  - Synthesize minimal struct(s) for intermediate objects; set field at offset to `fp_sigN*`
  - Unify types across identical offset patterns to avoid type explosion
- Recognize ops‑vector patterns (fp arrays/tables) and type entries accordingly
- Write ANALYSIS‑typed artifacts; respect archives/category paths

### 5) MIPS ABI and PIC/T9 Semantics
- Handle O32/N32/N64 (a0–a3, stack args)
- Consider stack‑arg evidence near call sites (stores to call frame)
- Understand PIC/T9 patterns; don’t assume an `lw` precedes `jalr`

### 6) Logging and Reporting
- Info logs: counts of jalr/jr scanned; patterns found; functions fixed; zero‑arg collapses; field typings
- Debug logs: per‑site decode/backtrace, alias resolution, evidence tallies
- Optional report view with findings table (function, action, evidence)

## Functional Requirements
- FR1: Detect and type function‑pointer returns (v0/v1 jalr/jr)
- FR2: Detect trampolines (jalr/jr via reg/memory loaded from param/saved base) and show forwarded args
- FR3: Infer parameter counts using caller consensus + body reads; preserve USER_DEFINED params
- FR4: Collapse to 0 params when all callers pass zero (unless user‑defined)
- FR5: Synthesize and apply struct‑field types for indirect call memory expressions
- FR6: Support O32/N32/N64; consider stack‑arg evidence
- FR7: Deterministic logs and summaries; idempotent reanalysis
- FR8: Opt‑in; allowed to run long on large binaries

## Non‑Functional Requirements
- Stability (fail soft), idempotence (no oscillation), performance knobs (limits, windows)
- Interop: run late; cooperate with existing MIPS analyzers

## Architecture and Execution Plan

### Phases
1. Discovery Scan: enumerate jalr/jr sites; classify by target (v0/v1 vs others)
2. Return‑Ptr Classification: mark functions whose returns feed jalr; set return type
3. Trampoline Detection/Typing: set CALL_RETURN; type register chain and memory expression via struct fields
4. Parameter Inference: caller consensus + body reads; expand to min; shrink to 0 on caller signal
5. Table/Vector Typing: identify fp tables; type entries and link to consumers
6. Reporting: emit summary and optional detail view

### Integration Points
- Program/Listing/Instruction iteration; FlowOverride
- Function updates (DYNAMIC_STORAGE_FORMAL_PARAMS)
- Local variables on registers; DataTypeManager (FunctionDefinitionDataType + PointerDataType)
- References and xrefs to enumerate callers

## Configurability
- Scan distances; Near window; a3 thresholds
- Enable/disable struct field synthesis; caps on synthetic types per function/offset
- ABI override (auto‑detect by default); logging verbosity

## Telemetry and Metrics
- jalr/jr processed; % resolved with arguments rendered
- Functions with signatures expanded/collapsed‑to‑zero
- Function‑pointer returns typed; struct fields typed
- Runtime per phase; hot spots

## Risks/Mitigations
- Over‑typing fields → type explosion → mitigate via unification, caps, ANALYSIS source
- Param oscillation → use stable thresholds; monotonic expansion; collapse only with strong caller signal
- Performance blowups → knobs; early exit when consensus reached

## Success Criteria
- ≥90% of jalr sites that forward a0–a3 display concrete arguments
- ≥90% precision on zero‑arg collapses on an audit set; no removal of USER_DEFINED params
- ≥90% of jalr v0/v1 patterns correctly typed as function‑pointer returns
- No regressions on existing MIPS projects

## Milestones
- M1 (1–2 weeks): Core passes (return‑ptr, trampolines, caller‑consensus) with debug logs; validate on target binaries
- M2 (1–2 weeks): Struct field typing + unification; zero‑arg collapse (caller‑consensus)
- M3 (1 week): ABI stack‑arg support; performance knobs; report view; docs
- M4 (1–2 weeks): Hardening, idempotence tests, golden corpus regression suite

## Test Plan
- Golden binaries (your modules + public samples): before/after decompile diffs
- Stress tests on large images with runtime limits/caps
- Idempotence: re-run analysis multiple times; ensure stability after first run

## Open Questions
- Persist structured findings for CI?
- Aggressiveness for >4 stack args? Default conservative?
- Optional rename pass for trivially identifiable trampolines (off by default)?

