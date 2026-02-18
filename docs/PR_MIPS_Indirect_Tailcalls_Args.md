# MIPS: Show arguments at indirect tail-calls by typing the decompiler’s call target (eliminates UNRECOVERED_JUMPTABLE at call sites)

## Summary
Adds a post-decompiler analyzer that automatically types the CALLIND target the decompiler actually uses (its synthetic/local high symbol) as an `fp_sigN*` based on the wrapper’s parameter count. As a result, `jr/jalr` trampolines render calls with arguments, e.g. `(*callTarget)(a0,a1,a2)`, instead of `(*UNRECOVERED_JUMPTABLE)()`.

If the target variable was auto-named `UNRECOVERED_JUMPTABLE`, the analyzer renames it to `callTarget` and name-locks it to prevent churn.

## Motivation
In MIPS firmware/drivers, wrappers frequently tail-call function pointers via `jr/jalr` (often `jr t9`), forwarding parameters. The decompiler resolves control flow but often prints `()` for the indirect call and labels the target as `UNRECOVERED_JUMPTABLE`, obscuring calling convention and hindering readability. Manual retyping in MCP fixes this but is tedious and non-repeatable.

## What’s included
- New analyzer: `Ghidra/Features/DecompilerDependent/src/main/java/ghidra/app/plugin/core/analysis/MipsDecompIndirectCallAnalyzer.java`
  - Runs late, MIPS-only (in DecompilerDependent so we can legally use decompiler APIs).
  - Locates CALLIND at `jr/jalr` sites, obtains the decompiler’s chosen target `HighVariable/HighSymbol`.
  - In a transaction, commits a function-pointer type `fp_sigN*` via `HighFunctionDBUtil.updateDBVariable(...)`; type-locks the symbol.
  - If the current name starts with `UNRECOVERED_JUMPTABLE`, renames to `callTarget` and name-locks it.
  - Conservative fallbacks: map by `HighVariable` name/register or sweep `pcVar*` locals, but only if the precise target path is unavailable.
  - Respects `SourceType` precedence and does not overwrite `USER_DEFINED` names/types set by users.

### Before
```c
callback *pcVar1;
code *pcVar2;
pcVar1 = (callback *)(*pcVar2)();      // no visible args
```

### After
```c
callback *pcVar1;
fp_sig3 *callTarget;
pcVar1 = (callback *)(*callTarget)(param_1, param_2, param_3);
```

## Design notes
- No core decompiler changes; implemented as a DecompilerDependent analyzer to use `HighVariable/HighSymbol/HighFunctionDBUtil`.
- Function-pointer arity N is inferred from the wrapper’s own parameter count (consistent with pass-through trampolines; no brittle "lw-before-jalr" assumptions).
- Transactions used for DB updates; types resolved via `Program`’s `DataTypeManager`; type/name locks applied to preserve the improvement across re-analysis.

## Scope and impact
- Only affects MIPS functions with indirect `jr/jalr` call sites.
- Database impact limited to setting local variable type (and optional rename when auto-generated); `SourceType.USER_DEFINED` ensures stable presentation without fighting user intent.
- Performance impact negligible; executes once per affected function post-decompile.

## Non-goals
- Not a switch/jumptable recovery change; only the variable name `UNRECOVERED_JUMPTABLE` at call sites is normalized when it is the call target. Switch recovery remains the decompiler’s domain.
- Does not attempt deep interprocedural pointer analysis; focuses on rendering correctness at common MIPS trampolines.

## Testing
- Manual: analyze a MIPS ko/elf with `jr/jalr` trampolines; verify indirect call sites print arguments and the target variable is named `callTarget` and typed `fp_sigN*`.
- Regression considerations:
  - Verify no change when user already set a `USER_DEFINED` type or name.
  - Verify no effect on non-MIPS, or on MIPS functions without `CALLIND` targets.

## Configuration
- Analyzer lives under DecompilerDependent; enabled for MIPS. Can be toggled in Auto-Analyze options if needed.

## Labels
- Area: Decompiler, Analyzer
- Arch: MIPS
- Type: Enhancement
- UX: Readability/Decomp Output Quality

