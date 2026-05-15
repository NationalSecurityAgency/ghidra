# NDS32 IFC Implementation

`ifcall` / `ifcall9` / `ifret` / `ifret16` (Inline Function Call) is a
mechanism in NDS32 V3 where the caller's continuation address is
stashed in a dedicated register `ifc_lp` instead of the standard `lp`,
letting a short `ifcall T` branch into a shared body without burning a
full-width call.  When `ifret` is reached, control returns to
`ifc_lp`.  See `Andes_Programming_Guide_for_ISA_V3_PG010_V2.1.pdf` and
gdb's `sim/nds32/interp.c` for the spec.

This plugin renders IFC code accurately in the decompiler, listing,
function graph, emulator, and stack analysis.

## Modeling principle

**IFC is per-call-site control flow, not a function-level property.**
The same machine body can be reached via `ifcall` from one site and
via direct `jal` from another; only the caller's flow decides the
mode.  The decompiler renders each caller's view independently — the
IFC body is conceptually inlined into every caller that ifcalls it,
even though there's only one physical copy of the instructions.

This means a single instruction can be part of multiple function
bodies' logical flows simultaneously.

## Architecture

### Sleigh (`nds32.sinc`)

* **`ifcall T` / `ifcall9 T`** — true CBRANCH on a synthetic register
  `IFC_CHOOSER` (offset 0x221, never written, treated as unknown by
  symbolic propagation):
  ```
  if (IFC_ON != 0) goto <nested>;    // nested: preserve outer ifc_lp
      ifc_lp = inst_next;
  <nested>
  IFC_ON = 1;
  if (IFC_CHOOSER != 0) goto inst_next;
  goto T;
  ```
  The CBRANCH gives the disassembler-level FlowType
  `CONDITIONAL_JUMP` (both target and fall-through edges).  At runtime
  `IFC_CHOOSER` is 0 so the CBRANCH never fires and control branches
  unconditionally to T.  At analysis time the propagator sees
  `IFC_CHOOSER` as unknown and follows both edges, which is essential
  for stack-depth tracking past the ifcall.  `DecompileCallback`
  emits a clean synth `ifc_lp = inst_next; IFC_ON = 1; BRANCH T;`
  to suppress the `IFC_CHOOSER` register from decompile output.

* **`ifret` / `ifret16`** — runtime-conditional `goto [ifc_lp]`:
  ```
  if (IFC_ON == 0) goto inst_next;
  IFC_ON = 0;
  goto [ifc_lp];
  ```
  FlowType `CONDITIONAL_COMPUTED_JUMP`.  Correct for both IFC mode
  (jumps to ifc_lp) and non-IFC mode (falls through, nop).
  `DecompileCallback` rewrites this per-flow (see "Synth pcode" below).

* **`jal X` / `jral` / `bgezal` / `bltzal`** — runtime-conditional
  lp:
  ```
  if (IFC_ON == 0) goto <not_ifc>;
      lp = ifc_lp; IFC_ON = 0; goto <do_call>;
  <not_ifc>
      lp = inst_next;
  <do_call>
  call X;
  ```
  `UNCONDITIONAL_CALL` flow type.  In IFC mode the callee returns
  via `lp = ifc_lp` (tail-call); in non-IFC mode via
  `lp = inst_next` (normal call).

* **Any taken branch / call / return clears `IFC_ON`** via the
  `psw_ifcon_clear()` macro.

### Pspec (`nds32.pspec`)

* `IFC_ON = 0` is a `tracked_set` default at every function entry,
  giving const-prop a known starting state for the IFC mode flag.
* `IFC_CHOOSER` is **not** in `tracked_set` — the propagator must see
  it as unknown for the dual-edge behavior to work.

### Cspec (`nds32.cspec`)

* New `ifc_call` calling convention with `ifc_lp` as the return-address
  register.  Same param/return as `__stdcall`.  Applied by the
  analyzer to functions whose visible callers are all `ifcall*` —
  produces a clean `return;` in their standalone decompile view.

### Analyzer (`NDS32IFCAnalyzer`)

`AnalyzerType.FUNCTION_ANALYZER` at `LOW_PRIORITY`.  Incremental: when
called with a non-empty `set`, iterates only instructions and
functions in `set` (so re-marking a single function doesn't reprocess
the whole program).

For each function F:

1. Walk every ifcall target's reachable body — follow fallthrough and
   JUMP/CBRANCH edges, NOT CALL targets (a `jal far` in an IFC body
   leaves the body).  Stop at ifret rather than following its
   computed-jump reference (that ref is the branch-back exit, not
   part of the body).
2. Record every ifret/ifret16, tail-call (unconditional `jal*`), or
   implicit return (ex9.it with `fall==null && !isJump && !isCall`)
   together with the caller's instruction-after-ifcall as the
   recorded branch-back target.
3. Split into single-target (one branch-back per exit) and
   multi-target (multiple ifcalls in F reach the same exit with
   different branch-back targets):
   * Single-target → `IfretBranchback:<F-entry-hex>` `LongPropertyMap`
     (`ifret-addr → caller-inst-next`).
   * Multi-target → `IfretMultiBranchback:<F-entry-hex>`
     `StringPropertyMap` (`ifret-addr → "T1,T2,..."`).
4. Publish the union of walked addresses as
   `FunctionBodyExt:<F-entry-hex>` `AddressSetPropertyMap`.
5. For ifrets in the extension whose fallthrough is filler (not live
   code in any function): clear the fallthrough and apply
   `FlowOverride.RETURN`.  Shared-body ifrets (where the fallthrough
   IS live code) keep their natural fallthrough — critical for
   normal-flow continuity in self-recursive IFC like 0xc7e.
6. Force-disassemble any IFC target that hasn't been marked code
   (covers ROMs where the loader didn't pre-scan the IFC bodies).
7. Add `COMPUTED_JUMP` cross-references from each ifret in the
   extension to its recorded branch-back targets — multi-flow
   visualization at the listing level.
8. Annotate IFC body entries with a "IFC body — ifcalled from: F, G,
   H" repeatable comment.
9. For functions visibly called only via ifcall*: seed `IFC_ON = 1`
   as program context at entry, and apply the `ifc_call` calling
   convention.

### Synth pcode (`DecompileCallback`)

Three hooks make multi-flow work at decompile time:

* **`getFunctionContaining(addr)`** — if the cached function's
  `FunctionBodyExt:` map contains `addr`, return the cached function
  (in addition to whatever the namespace map says).  Multi-owner at
  the decompile-callback level: each caller's decompile sees the
  shared body as part of its own flow.
* **`getFunctionAt(addr)`** — return `null` when `addr` is in the
  cached function's extension, so the decompiler doesn't treat a
  goto-into-body as a tail-call.
* **`getPcode(addr)`** — replace the prototype pcode with per-flow
  synth when an entry exists for `addr` in one of the cached
  function's maps:
  * `IfretBranchback` single-target: `IFC_ON = 0; BRANCH target;`
  * Tail-call (unconditional CALL flow type) single-target:
    `IFC_ON = 0; CALL real-target; BRANCH caller-inst-next;` —
    renders as `X(); …continuation;`.
  * `IfretMultiBranchback`: linear-CBRANCH switch on `ifc_lp` with N
    targets (`IFC_ON = 0; if (ifc_lp == T1) goto T1; …; BRANCH
    T_N;`).  Last arm is unconditional by exhaustion.
  * Ifret/ifret16 in cached function's body with **no** map entry:
    emit empty pcode (treat as no-op) so the natural
    `BRANCHIND[ifc_lp]` doesn't trigger spurious jumptable-recovery
    warnings on the dynamic ifc_lp target.
  * Ifcall/ifcall9: emit clean `ifc_lp = inst_next; IFC_ON = 1;
    BRANCH target;` to suppress `IFC_CHOOSER` from decompile output.

### Multi-owner API

New on `FunctionManager`:

```java
Set<Function> getFunctionsContaining(Address addr);
```

Returns primary owner plus every function whose
`FunctionBodyExt:<hex>` map contains `addr`.  Existing singular
`getFunctionContaining(addr)` is unchanged.  Supporting:
* `Program.getAddressSetPropertyMapNames()`
* `AddressSetPropertyMapDB.getPropertyMapNames(program)`

## Build workflow

Source-tree direct (no copy to `ghidra-built/`):

```bash
# After editing nds32.sinc:
ghidra/Ghidra/RuntimeScripts/Windows/support/sleigh.bat \
    ghidra/Ghidra/Processors/NDS32/data/languages/nds32le.slaspec

# After editing Java:
cd ghidra && ./gradlew :<Module>:classes   # NDS32 or Decompiler etc.
jar uf ghidra/Ghidra/<path>/<Module>.jar \
    -C ghidra/Ghidra/<path>/build/classes/java/main <class-path>

# Run from project root (which is parent of ghidra/):
ghidra/Ghidra/RuntimeScripts/Windows/support/analyzeHeadless.bat \
    "$(pwd)" <project> -process <file> -noanalysis \
    -postScript <Script>.java -scriptPath tests/ifc
```

## Validation

### IFC core
* `VerifyIFC.java` — 31 disassembly checks against `test_basic.bin`.
* `BasicAsmRegression.java` — 17 analyzer-map + decompile checks.
* `TestEmuIFC.java` — 29 emulator step-by-step checks.
* `RomRegressionSuite.java` — 14 spider_n9-specific ROM checks
  (coverage, decompile cleanliness, 0x1504 thunk pattern, 0xc7e
  shared-ifret pattern).
* `GenericRomCheck.java` — generic ROM-wide regression that works on
  any NDS32 binary; spider_n9 (691/691 covered, 0 jumptable warnings,
  1228 body annotations).
* `C7eFlowCheck.java` — 6 specific checks against the shared-ifret
  fix.
* `FullPhaseDCheck.java` — 11 multi-flow-visualization checks.

### ex9.it + multi-ITB
* `VerifyMultiItbOverride.java` — 5 checks: ROM-only-ITB-then-
  firmware-override path places bookmarks, logs diff, re-annotates.
* `VerifyManualItbOverride.java` — 5 checks: the `ITB override`
  option honors a user value over the auto-discovered one.
* `VerifyItbValidation.java` — 2 checks: bookmarks at invalid IT
  entries (recursive ex9.it, undecodable bytes).

### Pipeline (mt7663)
* `Mt7663Pipeline.java` — full workflow: load firmware bytes at
  0xdc000 (skipping the 0x1e ASCII header), bootstrap disasm,
  run data-init → run ITB.  Validates auto-resolve picks up both
  ROM ITB (0x25964) and firmware ITB (0xdc208).
* `RunDataInit.java` — minimal harness for the data-init analyzer
  with command-line reset/stop/cap.
* `BenchmarkEx9It.java` — decompile timing for the cache benchmark.

All under `tests/ifc/` (outside the git repo).  See
`tests/ifc/README.md` for run commands.

## Known issues / improvement areas

Items below are open work — neither blocking correctness nor cleanly
solvable with what we've tried so far.  Documented in detail so future
maintainers don't re-tread the same paths.

### 1. Multi-target `in_ifc_lp` leak in decompile (cosmetic)

~89 functions on spider_n9, ~1300 on mt7663.  When two or more ifcall
sites in the same caller reach the same ifret or tail-call with
different branch-back targets, `DecompileCallback` emits a
linear-CBRANCH switch on `ifc_lp`.  Per-path const-prop folds the
comparisons but the SSA phi merging `ifc_lp` across paths exposes it
as a live `in_ifc_lp` variable.

**Attempts that did not work:**

* *JumpTable.writeOverride* — wrote `switch_<addr>` labels in each
  function's namespace pointing to all the recorded branch-back
  targets, and emitted clean `BRANCHIND[ifc_lp]` pcode at the ifret
  expecting Ghidra's switch-recovery to render `switch(ifc_lp) {
  case T1: …; }`.  Rendered correctly on ~1 function (e.g. 0x307c
  showed `switch(in_ifc_lp)`), but **crashed the C++ decompiler on
  3–4 functions** ("Decompiler process died") — likely a Ghidra core
  bug with overrides where the BRANCHIND lives in another function's
  body via `FunctionBodyExt`.  Extending
  `JumpTable.getSwitchNamespace` to accept extension-body addresses
  didn't change behaviour; the crash is downstream in the
  switch-recovery code itself.  See known issue #3.
* *IFC_ON clear in synth* — adding `IFC_ON = 0` to the synth
  pcode at the ifret was neutral; the leak is from `ifc_lp` not
  `IFC_ON`.

**Partially addressed by the shared-body fall-through guard
(commit `8e373c03`):** the multi-target synth now prefixes the
linear-CBRANCH switch with `if (IFC_ON == 0) goto inst_next` so
ifret bodies that the outer function also enters via fall-through
(e.g. spider's 0x5fc8-0x5fd0 inside `FUN_ram_00005d30`) don't get
forcibly branched to a recorded caller-next, which previously
short-circuited the outer flow into an infinite loop.  This is
about flow *correctness*, not about the `in_ifc_lp` rendering —
the leak itself is unchanged.

**Alternative implementations worth considering:**

* **Per-ifcall-site body duplication.**  Instead of sharing the IFC
  body at decompile time and switching at the ifret, emit
  *per-call-site copies* of the body's pcode inline into each
  caller.  Each ifcall's `getPcode` would expand the entire IFC body
  inline + a direct BRANCH to its own caller-next.  No shared
  switch, no `ifc_lp` read.  Trade-off: code-size blow-up and
  significant `DecompileCallback` changes; multi-flow visibility in
  the listing would have to come from cross-references rather than
  the body extension.
* **Suppress `ifc_lp` from decompile output via cspec.**  No
  existing cspec attribute marks a register as "hidden from
  decompile output."  Would need a new cspec element (or use
  `<noflag>`/`<killedbycall>` with creative interpretation).  Risk:
  changing core cspec semantics for one processor.
* **Decompiler-side fix.**  The cleanest path is teaching the C++
  decompiler to elide a register whose only role is a switch index
  derived from a single dominator's write.  Out of scope for the
  Java/sleigh changes.

### 2. "Removing unreachable block" warnings (cosmetic)

~543 of 691 ifcall-containing functions on spider_n9 emit at least
one of these.  Comes from the decompiler's structural recovery on the
linear-CBRANCH switch — when `ifc_lp`'s phi is wide, some arms can't
be proved reachable and are trimmed.  Decompile output is still
semantically correct; the warnings are noise.

Resolves naturally if issue #1 is fixed via either alternative above
(per-site duplication eliminates the phi; a clean switch override
would let the decompiler structure each arm).

### 3. Decompiler crash on `JumpTable.writeOverride` for
   body-extension BRANCHIND (Ghidra core bug)

Writing a jumptable override in F's namespace for an address that
physically lives in another function's body (reachable via F's
`FunctionBodyExt`) causes the C++ decompiler to die on at least 3
functions in spider_n9.  Reproducible: every multi-target ifret where
the ifret address is not in F's primary body crashed it.  We
extended `getSwitchNamespace` to accept extension addresses but the
crash persisted, suggesting the underlying issue is in the C++
switch-recovery code's assumptions about the BRANCHIND's containing
function.

**Worth filing upstream as a Ghidra issue.**  A minimal repro might
just need an override pointing at an address outside the function's
body, no IFC needed.

### 4. Stack-depth analysis at multi-target ifret post-branch — NON-ISSUE

Originally noted as a concern that `CallDepthChangeInfo` and
`SymbolicPropogator` would read sleigh pcode directly (not
`DecompileCallback`'s per-flow synth), so the synth's linear-CBRANCH
switch on `ifc_lp` would be invisible to listing-level SP tracking.
Empirical check found that this doesn't manifest in practice:
* mt7663: 0/159406 instructions in ifcall-containing functions
  have UNKNOWN listing-level stack depth.
* spider_n9: 53/56266 (0.1%); 50 of those are in
  `FUN_ram_00008000`, a function with no standard prologue —
  unrelated to multi-target ifret.

The combination of (a) sleigh emitting `ifcall` as a real
`CBRANCH` so the propagator follows the fall-through edge into
the caller-next, (b) the IFC body's SP being preserved across the
call (no SP change inside the body), and (c) the IFC analyzer
adding `COMPUTED_JUMP` cross-references from each `ifret` to its
recorded caller-nexts (D.1) — which `SymbolicPropogator.BRANCHIND`
handler at
`Ghidra/Features/Base/.../SymbolicPropogator.java:970-978`
follows — is sufficient.

### 5. GUI hang on clear-and-remark with Function Graph open

Reported but not reproducible headlessly.  Partially mitigated by
making `NDS32IFCAnalyzer` incremental (only iterate functions in
`set`).  Open whether the remaining hang risk comes from:
* Excessive event chatter when the analyzer writes many comments /
  references / property maps.
* Function Graph rebuild cost with the D.1 cross-references in
  place.
* Some other interaction with my `Function.getFunctionsContaining`
  call sites (currently only the analyzer uses it).

Next step if it recurs: capture a thread dump and look for hot
methods on the AWT thread.

### 6. C-source roundtrip not exercised

`gcc -march=v3 -mifc -Os` + `ld --mifc` does not emit `ifcall`
instructions on small test programs — the linker's IFC-rewriting
heuristics need a sufficiently large code base before it's
profitable.  Could not produce a confirmed C-built IFC binary to
validate the round-trip decompile shape.  Real-world ROMs
(spider_n9, mt7663) are the validation oracle instead.

### 7. mt7663 ifcall to data block — RESOLVED

`FUN_ram_000048fa @ 0x4908 → 0x48e8` was a single-function coverage
gap (1856/1857) caused by `DataDB` markup at the IFC target blocking
auto-disassembly.  Resolved in the meantime — likely by one of the
subsequent IFC analyzer / data-init improvements clearing the
markup.  Coverage now 1857/1857.

### 9. Ifcall-thunk followed by same `jal` in normal flow renders as infinite loop — FIXED

`FUN_ram_00031ad6 @ 0x31afa` on spider_n9.  The function does
`ifcall9 0x31b06`; the IFC body at 0x31b06 is a single tail-call
`jal 0x43d36`, which ALSO lives in the function's primary fall-
through path (the natural flow goes 0x31afc → 0x31b00 → 0x31b04
→ 0x31b06 → 0x31b0a).  Before the fix, `DecompileCallback`'s
tail-call synth at 0x31b06 emitted an unconditional `IFC_ON = 0;
CALL X; BRANCH 0x31afc;` regardless of whether 0x31b06 was reached
via ifcall (IFC mode) or via natural fall-through (non-IFC).  The
unconditional `BRANCH 0x31afc` short-circuited the natural flow
back to caller_next, forming a cycle 0x31b06 → 0x31afc → 0x31b00
→ 0x31b04 → 0x31b06 → ... which the decompiler structured as
`do { ... } while( true );` — an infinite loop with no exit.

Fix in `DecompileCallback.getPcode`: for the tail-call shape
where the body instruction lives in the cached function's PRIMARY
body (shared-body case), capture the pre-clear `IFC_ON` value
into a temp and replace the unconditional `BRANCH caller_next`
with a `CBRANCH caller_next if preIfcVn`.  Now:
* IFC entry (preIfcVn = 1): CBRANCH fires → branches to
  caller_next; semantics match runtime (call X, return to
  caller_next via ifc_lp).
* Fall-through entry (preIfcVn = 0): CBRANCH doesn't fire →
  natural fall-through to inst_next; semantics match runtime
  (call X, return to inst_next via lp = inst_next).

For pure-IFC-body cases (the body lives ONLY in the function's
body extension, not its primary body — e.g. spider's
`FUN_ram_00034542` whose body at 0x34826 is in another function
entirely), the original unconditional `BRANCH caller_next` is
preserved.  Adding the CBRANCH guard there would leave a fall-
through edge to an address outside the function's flow, breaking
decompile.

**Inline-call optimization** (commit `448645df`): for the specific
sub-case where the IFC body is exactly one instruction (an
unconditional CALL — i.e. a thunking pattern) AND the body lives
in the caller's primary body, the `NDS32IFCAnalyzer` records an
`IfcInlineCall:<F-entry>` map entry at the ifcall address with the
tail-call's call target.  `DecompileCallback` then emits the
ifcall's pcode as a direct `CALL X; BRANCH inst_next;` — semantic
equivalent of inlining the body at the ifcall site.  The body's
natural sleigh pcode handles the separate non-IFC fall-through
pass.  Net result: instead of a 2-iteration `while( true ) { ...
break; }` shell around a single `X()` call, the decompile shows
two distinct `X(); ... ; X(); ...` lines, matching the source's
intent (the ifcall is a code-size-only thunking pattern; the
function logically does two consecutive calls to `X`).

For shared-body cases that aren't single-instruction tail-calls
(longer bodies, bodies ending in `ifret` rather than tail-call,
multi-target shared bodies), the CBRANCH-guarded synth above
remains in effect — producing the loop-with-break shape rather
than the infinite loop, but not the fully-cleaned two-call shape.

Regression test: `runCase31ad6` in `RomRegressionSuite.java`
verifies the function decompiles, reaches the post-ifcall code
(jal 0x30e04, jal 0x327a0), and does NOT have an unbounded
while-true loop.  Initial fix commit `799e2f49`; inline-call
optimization commit `448645df`.

### 8. ex9.it follow-up project (out of scope for IFC)

Per user direction, ex9.it improvements are tracked separately.
Status of each identified item:

1. **ITB.HW (hardware-set ITB) mode** — deferred (no real-world
   examples of `ITB.HW=1` observed).
2. **PC-relative substituted-instruction target loss** — confirmed
   expected behavior (hardware decodes IT-entry branches as if
   `PC=0`; `InjectEX9IT.java:129–136` matches that).
3. **Single global ITB assumption** — FIXED.  `NDS32ITBAnalyzer` now
   discovers every `mtusr,itb` writer, logs all candidates, defaults
   to the highest-address writer, and exposes an analyzer option
   `"ITB override (hex)"` so the user can pick a specific value (or
   one the analyzer can't auto-discover).  When a re-run detects
   that the active ITB has changed (e.g. a firmware overlay loaded
   over a ROM), a `WARNING` bookmark is placed at the new writer,
   `INFO` bookmarks are placed at every ex9.it site whose decoded
   instruction differs, the full IT-entry diff is logged, EOL
   comments are re-annotated, and the pcode cache is invalidated.
   See `SelectNDS32Itb.java` (Ghidra script) for an interactive
   chooser.
4. **Indirect/computed ITB load** — FIXED (for the
   `lwi.gp + addi + mtusr` shape).  The constant-trace now walks
   through `addi` chains and, on hitting a terminal
   `lwi.gp`/`lwi`/`lw`, reads the loaded 4-byte slot from program
   memory.  Two prerequisites:
   * The base register (`gp` for `lwi.gp`, explicit for `lwi`) must
     have a tracked value at the load site — provided by Ghidra's
     constant-prop or by a manual seed.
   * The slot's memory block must be initialized.  Reading from an
     uninitialized SRAM region returns null rather than propagating
     a bogus zero through the trace.  This is exactly what
     `NDS32DataInitAnalyzer` (default-off, see §10 below) enables:
     once the CRT trace populates SRAM with `.data`, downstream
     re-analysis resolves the ITB.
   On mt7663 with firmware loaded raw at 0xdc000: discovers both
   ROM ITB (0x25964 from `0x241ec`) and firmware ITB (0xdc208 from
   `*0x02001fe8 + 0x208` at `0xdd21a`/`0xdf458`) and picks the
   highest-address writer (firmware) by default.

   Also added: a hardware-enforced 4-byte alignment sanity-check.
   The NDS32 ITB USR forces the low two bits to zero on every read;
   we canonicalize non-aligned candidates to the aligned form and
   drop candidates below 0x100 (typically pre-init junk like
   `movi rt, 0`).
5. **No ITB-entry validation** — FIXED.  Unmapped entries, recursive
   ex9.it, and undecodable bytes now produce `WARNING` bookmarks in
   the `"NDS32 ITB"` category at the offending ex9.it site.
6. **Recursive ex9.it and unmapped entries fail silently** — FIXED
   (covered by #5 above).
7. **No call/jump cross-references at ex9.it sites** — already
   present.  `NDS32ITBAnalyzer.rewriteReferences` adds
   `UNCONDITIONAL_CALL` / `UNCONDITIONAL_JUMP` refs to the ex9.it
   site for substituted control-flow instructions; e.g. on
   spider_n9 4118 ex9.it sites have call xrefs and 278 have jump
   xrefs.
8. **FlowType not updated** — investigated; remains a known
   limitation.  Sleigh emits a plain `CALLOTHER` for `ex9(imm)` and
   `FlowOverride.getModifiedFlowType` is a no-op when the original
   `FlowType` is `FALL_THROUGH`.  References on the instruction do
   not feed back into `Instruction.getFlowType()`.  Fixing this
   would require either a sleigh restructure (e.g. injecting a
   synthetic CBRANCH the way `IFCALL` does with `IFC_CHOOSER`) or
   a Ghidra core change to let references override FlowType.  The
   IFC walker is now resilient to this (see #9), so the practical
   impact is limited to consumers that read FlowType for ex9.it
   sites in non-IFC contexts.
9. **Walker miscategorization for ex9.it → jump** — FIXED.  The IFC
   walker now classifies each ex9.it site by inspecting its
   outgoing call/jump references (added by `NDS32ITBAnalyzer`),
   not by `FlowType`.  This makes ex9.it→`j` follow the jump like
   any other jump, ex9.it→`jal` count as a tail-call, and only
   ex9.it→`ret`/`jr` get treated as implicit returns.
10. **5-bit form `ex9.it5` regression coverage** — low priority,
    still unaddressed.
11. **Pcode injection performance** — FIXED.  `InjectEX9IT` now
    caches the parsed `InstructionPrototype` per (program, IT-entry
    address) and re-validates against the stored entry bytes on
    each lookup so cache hits are safe across memory edits.
    Measured ~7% warm-pass speedup on mt7663 (~4500 ex9.it-
    containing functions).

#### Alternative implementation approaches

Considered after the above items shipped:

* **Crossbuild sleigh directive** (`tests/crossbuild_experiment.patch`,
  ~1350 lines, previously reverted).  Adds an `instr_body` sentinel
  section + a context register pair (`itMode`, `itb_value`) so the
  sleigh `:ex9.it` constructor can crossbuild the IT entry's main
  pcode body inline.  Pros: native sleigh expression — `FlowType`
  would be correct (#8), single pcode path for all consumers.  Cons:
  invasive (sleigh.cc, slghsymbol.cc, Constructor.java,
  SleighCompile.java), requires ITB known at sleigh-parse time,
  crossbuild target must be a constant address (works because the IT
  entry address is computed from `itb_value` + `imm*4`, both
  available at decode time).  Worth revisiting if the FlowType limit
  ever becomes painful; for now the pcode-injection approach plus
  the analyzer's reference-based fixups cover most needs.
* **New sleigh primitive `indirect_execute(addr)`** — a hypothetical
  pcodeop that means "inline-execute the instruction at addr."  Would
  let consumers expand it the way they want without needing
  crossbuild's per-section machinery.  Out of scope (would touch
  the entire pcode runtime: sleigh, decompiler, emulator,
  symbolic-propagator).
* **Reference-driven FlowType override** — small Ghidra core change
  to let an instruction's primary call/jump reference override the
  FlowType reported by `Instruction.getFlowType()`.  Would resolve
  #8 with much less code than crossbuild.  Trade-off: changes
  existing FlowType semantics across all processors.  Worth raising
  upstream rather than carrying a downstream fork.

## 9. Plugin-wide improvements (beyond IFC + ex9.it)

Work that's broader than IFC/ex9.it specifically but ships in the same
branch:

### 9.1 Chip memory map variants

`NDS32:LE:32:mt7663_bt` language variant adds a chip-specific pspec
(`nds32_mt7663_bt.pspec`) with `default_memory_blocks` for:

* `ILM_ROM` 0..0xdc000          (executable, uninitialized — loader fills)
* `ILM_RAM` 0xdc000..0x168000   (firmware-patch landing area, uninit)
* `DLM`     0x02000000..0x02040000  (SRAM data, uninit)
* `csr`     0..0x8000 in csreg space

Selected at import via `-processor "NDS32:LE:32:mt7663_bt"` (or the
GUI's language chooser).  Same canonical pattern Atmel uses for
chip variants (`atmega256.pspec`, `avr8xmega.pspec`).  Default
`NDS32:LE:32:default` variant is unchanged.

This is the pattern to follow for any future chip support.  Each
variant duplicates the symbol/csreg sections from the base pspec
since pspec doesn't have an `<include>` mechanism — accept the
duplication.

### 9.2 NDS32 vector table analyzer

`NDS32VectorTableAnalyzer` was hardcoded to address 0 and used a
too-strict 4-byte-entry pattern check.  Now:

* Configurable **Base address** option, default = lowest mapped
  initialized executable block.  Handles mt7663 (load 0), mt7921 BT
  (load 0x800000), and other non-zero bases.
* Configurable **Vector count** option, default 16, 0 = auto-detect
  by walking valid `j`/`jal` entries until the first mismatch.
* 4-byte entries accept first byte `0x48` (`j`) **or** `0x49`
  (`jal`); the remaining 24 bits of imm24 are unconstrained.  The
  earlier check required byte 1 == 0x00 which rejected vectors
  whose branch offset exceeds 0x10000 instructions (both mt7663
  vector 0 = `j 0x241d2` and mt7921 vector 0 = `j 0x82154e` fail
  the old check).

### 9.3 Data-init / CRT analyzer

`NDS32DataInitAnalyzer` (opt-in, `AnalyzerType.BYTE_ANALYZER`,
default-disabled).  Emulates the CRT sequence from the reset vector
with a fresh `PcodeEmulator` and commits memory writes to
currently-uninitialized blocks back to the program database.

Use cases:

* The ITB-load source for the firmware's `mtusr a0, itb` lives in
  SRAM that's populated by the ROM's `.data` init.  Without this
  analyzer, the firmware's ITB stays unresolvable.
* General: ROM-only binaries can't see their own `.data` values
  until init runs.  Emulating init exposes them statically.

Stop conditions (priority order):
1. PC reaches a user-configured stop address (`Init stop address`).
2. PC stays on the same instruction across one step (`j .` style
   spin loop).
3. No new write to any sink (uninitialized) block for N consecutive
   steps (default 50,000) — main loop reached.
4. Hard instruction cap (default 1,000,000).

Seeded registers (from the program's tracked context): `itb`,
`IFC_ON`, `gp`.

For the emulator to run the boot code, `NDS32PcodeUseropLibrary`
was extended with no-op stubs for the system pcodeops the existing
impl didn't cover: `isb`/`dsb`/`msync`/`isync`/`dpref`,
`cctl`/`setgie`/`setend`/`standby`, the `TLB_*` family,
`break`/`syscall`/`trap`, and `mfsr`/`mtsr` (returns synthetic 0).
All declared variadic so they match whatever shape sleigh emits.
These are pure model-state operations; no-op is correct for an
init trace.

mt7663 measurements:
* 117k step trace (stops on quiescent main loop, not the hard cap)
  applies 67,656 bytes to DLM + csr blocks.
* `0x02001fe8` (the firmware's ITB-source) ends up at `0x000dc000`,
  matching the hardware-runtime value.

### 9.4 BSE / BSP instruction semantics

Both Performance Extension V2 ops were previously `unimpl`.  Now
implemented in sleigh per AndeStar_ISA_UM025_V2.2 §9.4.1/§9.4.2 with
the three-way case analysis on D = M+N (normal/boundary/overflow)
and the underflow-recovery path that restores Rb[12:8] from
Rb[20:16] when Rb[30] was 1.  Decompiler now shows plain shift/mask
sequences rather than opaque pcodeops.

## What's next

In rough priority order:

1. **Auto-analysis performance on mt7663** — FIXED.  Total import +
   auto-analysis: 581s → 58s (90% reduction).  NDS32 Constant
   Reference Analyzer: 244s → 28.6s.  NDS32 ITB / EX9IT: 277s →
   2.1s.  NDS32 Misalignment Repair: 17.9s → 0.3s.  Changes:
   * `InjectEX9IT.lookupOrParse` made public + shared with
     `NDS32ITBAnalyzer.annotateEx9ItSites`, so the per-IT-entry
     prototype is parsed once (~256 unique entries) instead of once
     per ex9.it site (~17k).
   * `annotateEx9ItSites` skips `setComment` / `addMnemonicReference`
     round-trips when the existing comment/refs already match.
   * `markItbTableAsData` fast-paths when the IT region is already a
     `dword[count]` array of the right size.
   * `NDS32ITBAnalyzer.added` detects incremental invocations (set is
     non-empty + < half the loaded space + ITB already tracked) and
     restricts the ex9.it scan to `set`, skipping
     `discoverAllItbCandidates` / `applyGlobalItb` /
     `markItbTableAsData`.  `INSTRUCTION_ANALYZER` triggers many
     re-invocations during initial disassembly; this is the dominant
     win.
   * `NDS32Analyzer` skips the program-wide `setRegisterValue(gp)`
     call when every address already has the same gp default.
   * `NDS32Analyzer.markGpRelativeReferences` and
     `stripPush25PointerRefs` made incremental: when `set` is
     non-empty they iterate only that range.  This was the
     dominant remaining win — the `CODE_ANALYZER` subclass is
     also invoked many times during initial disassembly, and
     repeated full-program scans of post-passes were burning
     the constant-prop budget.
   * Removed per-instruction `.getMnemonicString().toLowerCase()`
     allocations in `markupDualInstruction` and other hot paths
     (NDS32 sleigh emits lowercase, so the call is redundant).
   * `markupDualInstruction` now reuses the cached `gp` field
     instead of `program.getRegister("gp")` per instruction.
   * `NDS32MisalignmentAnalyzer.computeUndecodedSet` made
     incremental — previously walked all 298k instructions +
     13k defined-data cells every invocation; now restricts
     the universe to `set` first and iterates only there.
     17.9s → 0.3s on mt7663.  (The analyzer reports zero
     repairs on the current test ROMs; the IFC/ITB fixes
     largely obsoleted its original speculative-disassembly
     fix-up role.  Kept as a cheap safety net.)
   Decompiler-switch analysis (~11s in plan) was not measured
   separately.

2. **GP-finding analyzer mis-fires on `push25`** — FIXED.  Root cause
   wasn't push25's stack store; it was the propagator's lastSet
   tracking.  `SymbolicPropogator.flowConstants` seeds every
   function's entry from `programContext` via `putValue(gp_varnode,
   constant_gp, false)`, which records the entry instruction (usually
   push25 on this firmware) as gp's lastSet location even though
   that instruction's pcode only reads gp.  pop25 has the same
   problem from a different angle: its `Lmwai(gp)` pcode literally
   writes gp via LOAD from a symbolic stack offset, and the
   propagator's stack tracking can return stale values stored at
   the same offset on unrelated paths, so `gp` ends up tracked as a
   small bogus integer (0x1, 0x14, 0x19, …).  Fix in
   `NDS32Analyzer.instructionConstantWritesGp(Instruction)`: accept
   the GP-discovery markup only when the candidate "lastSet"
   instruction's pcode contains a write to gp's varnode whose
   opcode is *not* LOAD — i.e. a real movi/sethi/ori/mtgp chain.
   Verified on mt7663: 5 bogus `_gp_N` symbols + 5 push25/pop25
   bookmarks before → 1 legitimate `_gp_1` + 1 bookmark after.

3. **MT76 connac patch loader** — FIXED (for the mt7615/mt7663 format).
   `Mt76ConnacPatchLoader` registers as a `SPECIALIZED_TARGET_LOADER`
   and recognizes the patch header (16-byte ASCII `build_date` +
   4-byte ASCII `platform` + version + checksum) — no magic number,
   so the sniff is on header-byte printability + the embedded
   newline.  On standalone import, the loader proposes
   `NDS32:LE:32:mt7663_bt` and lets the chip pspec create
   `ILM_ROM` / `ILM_RAM` / `DLM` / `csr` blocks, then strips the
   30-byte header and writes the payload into `ILM_RAM` at
   `0xdc000`.  "Add to Program" works too — when an existing
   block already covers the patch base address the loader writes
   into it (converting `ILM_RAM` from uninitialized to initialized
   + executable on the fly); otherwise it creates a new block.
   The plan originally hinted at "8-byte chunk descriptors near
   the file end"; that turns out to be wrong for the connac1
   format — the mt7615/mt7663 patch is a flat 30-byte header +
   payload.  The newer connac2/3 format (mt7921/mt7925/mt7990)
   does have section descriptors and is out of scope for this
   loader.

4. **`jral5 lp` / `jr5 lp` / `jral Rt, lp` flow correction** —
   FIXED.  `NDS32JralLpReturnAnalyzer` (new) re-labels these as
   `FlowOverride.RETURN` when the function never writes `lp`
   (push25/pop25 saves+restores count as a no-op).  Hardware
   reads `lp` before writing `lp = inst_next`, so when lp has
   its entry value control transfers to the caller.  Before this
   fix, these instructions were rendered as `COMPUTED_CALL` with
   fall-through into the next physical instruction, which is
   usually the start of an unrelated function — most visibly on
   small leaf functions like spider's 0x446
   (`copy_527e4_to_2099000_2514`) and 0x494
   (`copy_b0bc_to_2096800_540`) where the compiler emitted
   `jral5 lp` instead of the canonical `ret5 lp`.  Could
   alternatively be done via sleigh specialization on rb5=30
   (simpler, but context-free — would mis-handle the rare case
   where the function did write `lp` to a callback address
   before the `jral5 lp`).  Commit `8e373c03`.

5. **`applyCaptures` multi-range bug in
   `NDS32DataInitAnalyzer`** — FIXED.  After
   `mem.convertToInitialized` flipped a block from uninit to
   init, every subsequent capture in that block hit
   `block.isInitialized()` and was silently skipped — for blocks
   with multiple `memcpy` targets (e.g. spider's DLM has writes
   to 0x02090000-area and 0x02096800-area from different init
   routines) only the first range survived.  Track converted
   blocks by name so subsequent ranges keep applying.  On
   spider_n9: 32898 → 36490 captured bytes, and DLM at
   0x02096800 now matches its ROM source at 0xb0bc byte-for-byte
   (the function-pointer table referenced statically by the rest
   of the ROM).  Commit `8e373c03`.

6. **Shared IFC body forced into infinite loop in decompile** —
   FIXED.  When an IFC body lives inside the outer function's
   normal fall-through path, the multi-target ifret synth was
   forcibly branching to one of the recorded caller-next
   addresses regardless of whether the body was reached via
   `ifcall` or via fall-through.  Reaching the body via
   fall-through put `IFC_ON = 0`, but the synth ignored that
   and branched anyway — creating a cycle inside the body (e.g.
   spider's `FUN_ram_00005d30` looping through 0x5fc8-0x5fd0).
   Fix in `DecompileCallback.emitIfretMultiBranchback`: prefix
   the switch with `if (IFC_ON == 0) goto inst_next` so the
   fall-through path skips the dispatch and continues to the
   next instruction.  Commit `8e373c03`.

7. **MMIO mock + auto-poll-detect in
   `NDS32DataInitAnalyzer`** — FIXED.  The CRT trace used to
   stall whenever the boot code polled an MMIO register or
   indirected through a SRAM function-pointer table that no
   loader had populated (mt7925_bt's reset path; mt3616's GPT
   delay loop).  Two new options:
   * **MMIO mock overrides** (`ADDR=const:VAL` /
     `ADDR=count[:STEP]`) for chip-specific boot-mode reads,
     e.g. mt7925_bt needs `0x81030000=const:0x80000000` to land
     on the cold-boot fallthrough.
   * **Auto-detect MMIO polling**: an unmocked MMIO address
     read ≥100 times within 1000 consecutive emulator steps is
     promoted to a saturating counter (`+0x10000000` per read,
     capped at `0xFFFFFFFF`).  Catches both `bltz reg, exit`
     (works once high bit appears) and
     `cmp reg, threshold; b< loop` (works once value exceeds
     any reasonable threshold) without per-chip configuration.
   Implementation uses the `beforeLoad` PcodeEmulationCallbacks
   hook to write the synthesized value into the thread's state
   before each intercepted load.  Commit `7064acec`.

8. **MMIO-region volatile marker** — FIXED.
   `NDS32VolatileBlockAnalyzer` walks every block at startup and
   calls `setVolatile(true)` for those starting at
   `ram:0x80000000+`.  The decompiler stops constant-folding
   loads/stores in those blocks so MMIO writes survive const-prop.
   Sleigh/cspec has no range-based volatile mechanism (only
   per-symbol via `<default_symbols volatile="true">`), so this
   is the cleanest place to do it.  Commit `c79fb5ff`.

9. **MT3616 chip pspec** — FIXED.  `NDS32:LE:32:mt3616` variant
   with the memory map extracted from an existing AndeStar-language
   project (PS5 DualSense rom_joined.bin).  ILM_ROM/ILM_RAM,
   SYSRAM_N9/SYSRAM_M4, DLM_RAM, and all the MMIO peripheral
   windows.  Commit `ef6157eb`.

10. **Multi-target `in_ifc_lp` leak** (§1) — still cosmetic, still
    unfixed.  Either the per-site duplication approach or a
    decompiler-side elide-of-phi-only-register fix would close
    this plus §2.

11. **Stack-depth analysis at multi-target ifret** (§4) — VERIFIED
    NON-ISSUE.  Empirical check on both test ROMs shows the
    propagator already tracks SP correctly past ifret/tail-call;
    the D.1 `COMPUTED_JUMP` cross-references give it the edges it
    needs.  See §4 for the numbers.

12. **Ifcall-thunk-then-same-jal infinite-loop decompile** (§9) —
    FIXED in two stages.  `799e2f49` added a CBRANCH-guarded
    shared-body tail-call synth (no more infinite loop, but a
    2-iteration `while( true ) { ... break; }` shell remained).
    `448645df` added the inline-call optimization: for the common
    single-instruction-tail-call IFC body shape (the 16-bit-
    ifcall code-size thunking pattern), `NDS32IFCAnalyzer`
    records an `IfcInlineCall:<F>` map entry and
    `DecompileCallback` emits `CALL X; BRANCH inst_next;`
    directly at the ifcall site — semantic inlining of the
    body.  Decompile output now shows two clean `X(); ... X();`
    lines instead of the loop+break shell.

13. **mt7663 ifcall→data-block target** (§7) — RESOLVED in the
    meantime; active mt7663 projects all show 4/4 coverage on
    `GenericRomCheck`.  Only stale `mt7663_test` retains the
    gap.  No further work needed.

## Suggested next steps

In rough priority order; pick whichever matches your goal:

* **SymbolicPropogator stack tracking across inlined flow** -
  see `STACK_TRACKING_PLAN.md` (this directory).  Currently masked
  by `NDS32Analyzer.instructionConstantWritesGp`; the proper fix is
  upstream and benefits any plugin that inlines control flow through
  a synthetic boundary (NDS32 IFC today, Andes V5 tomorrow, plus
  potential improvements to general stack-load/store reference
  resolution).  Independent of any other item below.

* **Fix the leaked `in_ifc_lp` in multi-target ifret decompile
  output** (§1).  Two viable paths, both significant work:
  * Per-call-site body duplication in `DecompileCallback`: expand
    the IFC body's pcode inline into each ifcall's `getPcode`
    output + a direct `BRANCH` to that site's caller-next.  No
    shared switch, no `ifc_lp` read, the leak goes away
    structurally.  Trade-off: pcode-bloat, significant
    `DecompileCallback` rewrite, multi-flow visibility in the
    listing has to come from cross-references rather than the
    body extension.
  * Decompiler-side elide of a phi-only-via-CBRANCH register —
    the C++ side fix.  Cleaner but out of the Java/sleigh
    perimeter.  Worth raising upstream as a Ghidra feature
    request even if we don't fix it ourselves.

* **`mt7925_bt` chip pspec** mirroring what mt3616 and mt7663_bt
  have.  Without a sink block for the 0x900000+ RAM patch area
  (the 1260 `jal` targets discovered earlier), data-init coverage
  on that chip is capped at "MMIO writes only."  Same pattern as
  the mt3616 pspec — straightforward but tedious.

* **Sleigh specialization for `jral5 lp`** as an alternative to
  the analyzer (#4 above).  Decoder-level fix, simpler runtime
  story, but globally treats every `jral5 lp` as a return — would
  mis-handle the theoretical "lp loaded with a callback then
  jral5 lp" pattern (rare in compiled code).  Trade-off only
  worth it if we want to drop the analyzer; otherwise the
  analyzer's per-function correctness is preferable.

* **Decompiler crash on `JumpTable.writeOverride` for
  body-extension BRANCHIND** (§3) — file upstream as a Ghidra
  issue.  A minimal repro probably doesn't need IFC at all,
  just an override pointing at an address outside the function's
  primary body.

* **`ex9.it5` 5-bit-form regression coverage** (§8.10) — small
  test-coverage gap; only meaningful if a real firmware
  exercises this form (none observed so far).

### Known limitations (not on the work list)

* **Decompiler crashes on `JumpTable.writeOverride` for body-
  extension BRANCHIND** (§3) — Ghidra core bug.  Documented for
  future maintainers, but not tracked as a TODO: every workable
  IFC fix we tried that goes through `writeOverride` triggered it,
  and the upstream fix is somewhere in the C++ switch-recovery
  code.  Treat this as a hard constraint when designing future
  IFC variants — don't route through `writeOverride`.

* **Data-init trace observes spurious writes near SP=0.**  The
  emulator starts with SP=0; if any `jal` between the reset
  vector and the first explicit SP setup pushes registers, those
  writes land near address 0.  Doesn't affect the trace's main
  job (populating real SRAM/DLM from `.data` copies) and so
  isn't worth fixing for its own sake.  Only matters if the
  "writes to initialized blocks" diagnostic gets used as
  evidence of ROM-extent — which it isn't, given chip docs
  authoritatively specify the layout.

* **ex9.it5 5-bit form** has no regression test (§8.10).
  Functionally handled by the same sleigh constructors as the
  9-bit form; small coverage gap.

## Files

### IFC
* `data/languages/nds32.sinc` — ifcall/ifret/ifret16/ifcall9 +
  runtime-conditional jal et al. + `IFC_CHOOSER` register; also
  `bse`/`bsp` semantics (§9.4).
* `data/languages/nds32.pspec` — `IFC_ON = 0` tracked default.
* `data/languages/nds32.cspec` — `ifc_call` calling convention.
* `src/main/java/.../NDS32IFCAnalyzer.java` — body-extension walker,
  branchback maps, COMPUTED_JUMP refs, body annotations, convention
  seeding; ex9.it→jump/tail-call awareness via outgoing refs.
* `Ghidra/Features/Decompiler/.../DecompileCallback.java` — per-flow
  synth pcode for ifcall, ifret, tail-call, multi-target switch.
* `Ghidra/Framework/SoftwareModeling/.../FunctionManager.java` +
  `FunctionManagerDB.java` — `getFunctionsContaining(addr)` multi-
  owner API.
* `Ghidra/Framework/SoftwareModeling/.../Program.java` +
  `ProgramDB.java` + `AddressSetPropertyMapDB.java` —
  `getAddressSetPropertyMapNames()` support API.

### ex9.it
* `src/main/java/.../NDS32ITBAnalyzer.java` — mtusr-itb discovery,
  multi-ITB / firmware-override handling, manual-override option,
  IT-entry validation, 4-byte alignment check, `lwi.gp + addi`
  resolution.
* `src/main/java/.../InjectEX9IT.java` — per-(program, IT-entry-addr)
  prototype cache + `invalidateCache(program)` hook.
* `src/main/java/.../NDS32PcodeUseropLibraryFactory.java` — emulator
  userop library for `ex9` plus no-op stubs for system pcodeops so
  the data-init trace can run boot code.
* `ghidra_scripts/SelectNDS32Itb.java` — interactive ITB chooser
  (lists every discovered mtusr,itb writer + value, sets the
  override).

### Chip + data-init support (§9)
* `data/languages/nds32.ldefs` — adds `NDS32:LE:32:mt7663_bt`
  variant.
* `data/languages/nds32_mt7663_bt.pspec` — chip-specific memory map
  for the MT7663 BT core.
* `src/main/java/.../NDS32VectorTableAnalyzer.java` — base address +
  vector count options, jal/j vector acceptance.
* `src/main/java/.../NDS32DataInitAnalyzer.java` — CRT trace +
  apply-writes-to-uninitialized-blocks.

## Glossary

| Term | Meaning |
|------|---------|
| IFC body | The instructions reachable from an ifcall's target, treated as logically inlined into the caller. |
| Body extension | The `FunctionBodyExt:<entry>` AddressSetPropertyMap listing addresses that belong to the function's flow despite not being in its primary single-owner body. |
| Branch-back | The caller's instruction-after-ifcall, which an ifret in the IFC body branches to via `ifc_lp`. |
| Shared body | An IFC body called from 2+ ifcall sites with different branch-back targets — gives rise to multi-target ifret. |
| Tail-call | A `jal`/`jral` inside an IFC body that, in IFC mode, has `lp = ifc_lp`; the called function's natural `ret lp` returns directly to the original caller's branch-back. |
| Self-recursive IFC | The IFC body lives inside the calling function's own primary body (e.g. ROM's 0xc7e ifcalls 0xc82 which is inside 0xc7e). |
