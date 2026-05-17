# Engineering Plan: Intra-Function Parallel Decompilation

**Branch**: `feature/bounded-function-parallel-decompiler`
**Baseline**: commit `57061a37f0` (two-phase canApply infrastructure, OFF by default)
**Goal**: positive speedup on single-function decompilation via intra-function parallelism
**Constraints**:
- Semantic correctness verified by 668 datatests + custom integration tests
- SHA-identity vs serial is NOT required (relaxed per direction)
- No shortcuts, no #ifdef hacks, no half-finished components

---

## 0. Why this is hard

The Ghidra decompiler's hot path (`ActionPool::apply` rule dispatch) is **fine-grained**: each
`Rule::applyOp` is ~50-100 ns of work. Thread synchronization primitives (`std::mutex` ~20 ns,
`condition_variable` notify+wake ~10-50 µs) have overhead **comparable to or larger than** the work
parallelized. Naive parallelism on `applyOp` is consistently slower than serial.

The decompiler's IR (Funcdata) is also **not thread-safe by design**:
- `VarnodeBank`/`PcodeOpBank` use `std::set`/`std::list` with no synchronization
- `Varnode::descend` (list of consumers) is mutated by every `opSetInput`
- `Architecture` has lazy caches (`types`, `cpool`) accessed during decompile
- Many rules touch shared state implicitly (e.g., `deadRemovalAllowedSeen` mutates `HeritageInfo::deadremoved`)

Therefore positive intra-function speedup requires **systematic re-engineering**, not bolt-on parallelism.

The plan below covers three complementary tracks. They are **mutually reinforcing**, not alternatives — full
intra-function parallelism needs all three. Estimated total effort: **8-12 engineer-weeks** for an experienced
C++ developer who already knows the Ghidra codebase.

---

## Path 1 — Per-Rule TEST/APPLY Split

### Goal

Every `Rule` subclass exposes:
- `int4 canApply(const PcodeOp*, const Funcdata&) const` — **pure read**, returns 0/1
- `int4 doApply(PcodeOp*, Funcdata&)` — **mutation only**, called when `canApply` returned 1
- Existing `int4 applyOp(PcodeOp*, Funcdata&)` becomes `{ if (canApply(op,data)==0) return 0; return doApply(op,data); }`

This is the foundation for everything else: `canApply` is invoked massively in parallel; `doApply` runs
under whatever serialization scheme the dispatcher chooses (per-block sequential, fine-grained locks, etc.).

### Scope: 152 rules to audit (actual count via grep, updated 2026-05-17)

Source files containing `Rule` subclass `applyOp` implementations:

| File | Rule count |
|---|---:|
| `ruleaction.cc` | 134 |
| `subflow.cc` | 12 |
| `double.cc` | 4 |
| `constseq.cc` | 2 |
| **Total** | **152** |

Initial preliminary categorization (first-pass automated by `audit_rules.py`, see companion
`INTRA_FUNCTION_PARALLEL_RULE_AUDIT.md`):
- **A**: 85 rules — straightforward split (mutations only at the apply path)
- **B**: 42 rules — loop with multi-mutation (interleaved test+apply within the rule)
- **C**: 3 rules — known side effects in fail path
- **A_NOOP**: 22 rules — delegate to external helpers (e.g. `SplitVarnode::applyRuleIn`);
  require manual review since the regex audit can't see into the helpers

The first 10-15 hours of Path 1 work should be a **comprehensive manual audit pass**: open each
`applyOp`, walk into helpers, classify into A/B/C, list side effects. The automated first-pass above
is a starting point only — A_NOOP rules in particular need investigation.

### Rule classification

Each rule is sorted into one of three categories based on inspection of its `applyOp`:

**Category A — Pure-read fail path, single mutation point** (estimated ~55 rules)
- All early exits are pure reads on op/Varnode flags, opcode, input/output pointers
- Single block of mutations at the end (one or a few `opSet*` calls)
- `canApply` extracts the early-exit predicate; `doApply` contains the mutation block
- Example: `RuleCollapseConstants` (already split in `57061a37f0`)
- Effort per rule: **30 min audit + 15 min impl + 15 min test = ~1 hour**

**Category B — Pure-read fail path, interleaved mutations** (estimated ~20 rules)
- Rule loops over inputs/descendants; tests each; may mutate inside the loop
- `canApply` must determine whether ANY iteration would mutate
- `doApply` does the actual loop with mutations
- Example: `RulePropagateCopy` (already split in `57061a37f0`)
- Effort per rule: **45 min audit + 30 min impl + 30 min test = ~1.75 hours**

**Category C — Side effects in fail path** (estimated ~12 rules)
- "Failure" path also mutates state (set marker flag, register memo, bump counter)
- Side effects include: `opMarkNoCollapse`, `opMarkCpoolTransformed`, `deadRemovalAllowedSeen`, `setActiveHeritage`, internal cache updates
- Three resolution strategies per rule:
  1. **Move side effect to doApply** — if the side effect is only meaningful when the rule eventually applies (rare)
  2. **Eliminate via redesign** — if the side effect is a memo/cache that can be made thread-safe (e.g., atomic flag set)
  3. **Mark as no-canApply** — `canApply` returns -1 (unknown); rule always runs full `applyOp` in dispatcher's serial fallback
- Effort per rule: **1-3 hours each** depending on resolution

### Comprehensive rule list with categorization (preliminary, from profile + grep)

```
Category A — straightforward split (~55 rules):
  RuleEarlyRemoval ✓ done       RuleCollapseConstants ✓ done    RuleTermOrder
  RuleCondNegate                RuleEqual2Zero                  RuleEqual2Constant
  RuleAndMask                   RuleAndCommute                  RuleAndCompare
  RuleShiftCompare              RuleShiftAnd                    RuleShiftBitops
  RuleDoubleShift               RuleBooleanNegate               RuleSubvarCompzero
  RuleAddMultCollapse           RuleTrivialArith                RuleZextEliminate
  RuleIdentityEl                RuleDivOpt                      RuleDivTermAdd
  Rule2Comp2Mult                RuleSubright                    RuleExpandLoad
  RuleSplitCopy                 RuleSplitLoad                   RuleStringCopy
  RuleStringStore               RuleFloatSignCleanup            RuleSignMod
  RuleSignNearMult              RulePiecePathology              RulePiece2Sext
  RulePiece2Zext                RulePushPtr                     RuleStructOffset0
  RulePtrArith                  RulePtrSubCharConstant          RuleLeftRight
  RuleRightShiftAnd             RuleSignDiv2                    RuleSignShift
  RuleDumptyHump                ... (continue per ruleaction.cc enumeration)

Category B — interleaved mutation (~20 rules):
  RulePropagateCopy ✓ done      RuleCollectTerms                RuleAndDistribute
  RuleBitUndistribute           RuleAndOrLump                   RuleMultiCollapse
  RuleIndirectCollapse          RulePushMulti                   RuleConditionalMove
  RuleSwitchSingle              RuleConditionalExecution        RuleAddMultiCollapse
  RuleConditionalConstants      RuleSubfloatConvert             RuleSubvar*
  RuleBitfield*                 RuleSplit*                      RuleString*

Category C — side effects in fail path (~12 rules):
  RuleEarlyRemoval (deadRemovalAllowedSeen — minor; canApply conservatively skips this check)
  RuleCollapseConstants (opMarkNoCollapse in catch block — call it from doApply instead)
  RuleTransformCpool (opMarkCpoolTransformed at top — memo; move to doApply or make atomic)
  RuleIndirectCollapse (sets no_indirect_collapse flag — similar)
  RuleLoadVarnode (mutates load tracking state — needs deeper redesign)
  RuleStoreVarnode (similar)
  RuleHandleNewLoadCopies (heritage interaction — keep no-canApply)
  RulePtrCheck — sets vn->ptr_check flag in fail path — atomic flag set OK
  ... ~5 more
```

The first 5-10 hours of Path 1 work should be a **comprehensive audit pass**: open each `applyOp`,
classify into A/B/C, list side effects in a spreadsheet/markdown table. This grounds the rest of the work.

### Side-effect resolution strategies

For each category-C side effect, document the chosen strategy:

| Side effect | Frequency | Strategy |
|---|---|---|
| `opMarkNoCollapse` | RuleCollapseConstants catch | Move to doApply (only set after collapse attempt actually fails) |
| `opMarkCpoolTransformed` | RuleTransformCpool top | Convert to atomic CAS (set-once flag); canApply checks via atomic load |
| `deadRemovalAllowedSeen` | RuleEarlyRemoval | canApply omits the check (conservative); doApply does it |
| `setActiveHeritage` | Heritage code (not Rule) | N/A for Rule split |
| Per-rule memo flags | Various | Convert to atomic per-Varnode flag set |

### Atomic flag set pattern

`Varnode::flags` is `mutable uint4`. For thread-safe atomic flag set:

```cpp
class Varnode {
  mutable std::atomic<uint4> flags_atomic;  // replace `mutable uint4 flags`
public:
  bool isPtrCheck() const {
    return (flags_atomic.load(std::memory_order_acquire) & ptr_check) != 0;
  }
  void setPtrCheck() {
    flags_atomic.fetch_or(ptr_check, std::memory_order_acq_rel);
  }
};
```

Cost: ~5 ns per atomic op vs ~1 ns for plain read/write. Acceptable for rare operations.

Audit needed: every `flags |= ...` / `flags &= ...` on `Varnode`, `PcodeOp`, `AddrSpace`, `HeritageInfo`,
etc. **Estimated 50-100 sites** in core files. Convert all to atomic if used during parallel sections.

### Verification protocol per rule

For each split rule:
1. **Equivalence test**: run a test harness that calls `applyOp` vs `(canApply, doApply)` on a corpus of
   1000+ PcodeOps from real decompilations. Output must match.
2. **Datatest integration**: enable parallel mode with this rule's `has_canapply` flag and verify all
   668 datatests pass.
3. **Differential top30 SHA**: optional — confirm output is semantically identical even if textually
   differs (per relaxed constraint).

### Effort estimate Path 1 (revised for 152 rules)

| Activity | Time |
|---|---|
| Comprehensive manual audit (152 rules, walk into helpers) | 15 hours |
| Atomic flag conversion infrastructure | 8 hours |
| Per-rule split: 85 Category A × 1h | 85 hours |
| Per-rule split: 42 Category B × 1.75h | 73.5 hours |
| Per-rule split: 22 A_NOOP × 1.5h avg (after reclassification) | 33 hours |
| Per-rule split: 3 Category C × 2h | 6 hours |
| Per-rule equivalence test harness | 15 hours |
| Datatest integration sweep | 12 hours |
| Documentation per rule | 12 hours |
| **Total Path 1** | **~260 hours (~6.5 weeks at 40h/wk)** |

### Deliverables Path 1

- All 87 Rule subclasses with `canApply` and `doApply` methods
- `Rule::applyOp` becomes a non-virtual helper that delegates: `if (canApply==0) return 0; return doApply();`
- Atomic flag-set conversion for affected fields
- Per-rule equivalence test (in `unittests/`)
- Updated `ruleaction.hh` documentation explaining contract

---

## Path 2 — Block-DAG Static Partitioning

### Goal

ActionPool dispatch runs **multiple basic blocks in parallel** when they have disjoint mutation scopes
within a single pass. Larger parallelism units than per-op dispatch → amortizes thread overhead.

### Conflict model

Define **per-rule mutation scope** statically (annotated per rule, see Path 1):

```cpp
enum MutationScope {
  SCOPE_OP_ONLY         = 1,  // mutates op fields only (opcode, flags)
  SCOPE_OP_INPUTS_DEFS  = 2,  // mutates op + its input Varnodes' def-ops (descend list changes)
  SCOPE_OP_OUTPUT_USES  = 4,  // mutates op + its output's descendants (input slot rewires)
  SCOPE_BLOCK_LOCAL     = 8,  // mutates ops in same BasicBlock only (e.g., RuleMultiCse local)
  SCOPE_BLOCK_GLOBAL    = 16, // may mutate any op in function (e.g., heritage-aware rules) — serial only
};
```

Two block-batches B1, B2 can be processed in parallel if:
- For every rule R that may fire on B1: R's scope vs B2's ops produces no overlap
- And vice-versa

For most rules with `SCOPE_OP_ONLY` or `SCOPE_BLOCK_LOCAL` scope, two blocks are scope-disjoint UNLESS
they share Varnodes via cross-block def-use chains (MULTIEQUAL, INDIRECT).

### Static block-conflict graph

At function entry, build once per function (after heritage stabilizes):

```cpp
struct BlockConflict {
  BlockBasic *a, *b;
  uint4 scope_mask;  // which scope types cause conflict between a and b
};
vector<BlockConflict> conflictEdges;
```

Construction algorithm:
- For each Varnode V in function:
  - Let def_block = V->getDef()->getParent()
  - For each descendant op D of V: let use_block = D->getParent()
  - If def_block != use_block: add edge (def_block, use_block) with scope `SCOPE_OP_OUTPUT_USES`
- For each PcodeOp op with multi-input:
  - For each pair (input_i, input_j): if their def-blocks differ, add edge
- Complexity: O(N × avg_descend) ≈ O(N × 3) = O(N)

Memory: O(edges) where edges ~ # of cross-block data flow connections.

### Parallel scheduling per ActionPool::apply

Each pass:
1. Partition blocks into independent groups using conflict graph
   - Greedy coloring: assign each block a color such that no edge connects same-color blocks
   - All blocks of one color can run concurrently
2. For each color group: dispatch one task per block, parallel via thread pool
3. Each task runs serial ActionPool dispatch on its block's ops
4. Sync after each color (all tasks complete)
5. Repeat for next color
6. After all colors processed: pass done

Greedy coloring complexity: O(V + E). Typical color count: 3-5 for non-trivial functions.
Parallelism degree: ~|V|/colors. For 50-block function with 5 colors: ~10-way parallel.

### Cross-block side effects

Rules with `SCOPE_OP_OUTPUT_USES` actually touch ops outside their home block (the descendants).
Handling:

**Option 1**: Acquire per-Varnode lock before cross-block mutation.
- Each Varnode has a `std::mutex` (or `std::shared_mutex` for read-heavy)
- `opSetInput(op, V, slot)` acquires V's def-op's parent block lock + op's parent block lock
- Lock acquisition order: by block id (deadlock-free)
- Cost: ~20-50 ns per cross-block mutation

**Option 2**: Defer cross-block mutations to a post-color serial phase.
- During color processing, collect cross-block mutations into a list
- At color barrier, single thread applies all deferred mutations
- No locking needed during color processing

Option 2 is simpler but may serialize meaningful work. Option 1 is more flexible but needs careful
deadlock proof. **Recommendation: start with Option 2, switch to Option 1 if profiling shows the
deferred phase is the bottleneck.**

### Heritage integration

Heritage runs BEFORE ActionPool typically. After heritage, basic block graph is stable.
Rule cascades during ActionPool can change op structure but not basic block boundaries.

The conflict graph is rebuilt:
- After heritage (first time)
- After any Action that may add/remove ops at block boundaries (e.g., ActionBlockStructure)
- NOT after individual rule fires (most rules are intra-block)

Rebuild cost: O(N) per rebuild. Frequency: ~5-10 times per function.

### ActionPool changes

```cpp
int4 ActionPool::applyBlockParallel(Funcdata &data) {
  if (!data.blockConflictGraph().isReady()) data.blockConflictGraph().build();
  const auto &colors = data.blockConflictGraph().computeColoring();

  for (const auto &colorGroup : colors) {
    vector<future<int4>> futures;
    for (BlockBasic *bl : colorGroup) {
      futures.push_back(pool.submit([this, bl, &data]() {
        return this->processBlock(bl, data);
      }));
    }
    for (auto &f : futures) {
      int4 res = f.get();
      if (res < 0) return -1;  // breakpoint handling
    }
  }
  return 0;
}

int4 ActionPool::processBlock(BlockBasic *bl, Funcdata &data) {
  // Serial dispatch over ops in bl, using Path 1 canApply for fast filtering
  // and Path 3 locks for cross-block mutations.
  for (PcodeOp *op : bl->allOps()) {
    // ... existing per-op dispatch with canApply skip ...
  }
  return 0;
}
```

### Effort estimate Path 2

| Activity | Time |
|---|---|
| Rule scope annotation (depends on Path 1 audit) | 12 hours |
| Conflict graph construction + tests | 16 hours |
| Greedy coloring + parallel dispatch | 12 hours |
| Cross-block deferred-mutation handling | 16 hours |
| Heritage integration + graph rebuild triggers | 12 hours |
| Per-block test harness | 8 hours |
| Integration with Path 1 canApply | 8 hours |
| Datatest sweep + debugging | 24 hours |
| Performance tuning + profiling | 16 hours |
| Documentation | 8 hours |
| **Total Path 2** | **132 hours (~3.3 weeks)** |

### Deliverables Path 2

- `block_conflict.{hh,cc}` — conflict graph data structure + builder + coloring
- ActionPool's `applyBlockParallel` method (env or option gated)
- Per-rule `getMutationScope()` annotation
- Heritage hook for graph rebuild
- Cross-block deferred mutation queue
- Updated tests + benchmarks

---

## Path 3 — Fine-Grained Locking / STM for Parallel doApply

### Goal

When Path 2's block-level parallelism is insufficient (e.g., functions with one giant block, or
heavy cross-block sharing), allow concurrent `doApply` calls on different ops with safety via
fine-grained locks.

This is the most complex track. Three sub-approaches; recommendation is **Sub-path 3A**.

### Sub-path 3A — Per-Varnode RW locks + lock-free reads

**Architecture:**
- Each `Varnode` gets a `std::shared_mutex` (~80 bytes; ~800 KB for 10000 Varnodes)
- Each `PcodeOp` gets a `std::shared_mutex` (~80 bytes; ~400 KB for 5000 ops)
- `canApply` and other pure reads take **shared** locks on involved Varnodes/ops
- `doApply` mutations take **exclusive** locks on involved Varnodes/ops + Funcdata bank lock

**Lock acquisition contract per Funcdata operation:**

| Operation | Locks needed (exclusive) | Reason |
|---|---|---|
| `opSetOpcode(op, opc)` | op, op->getOut() (if any), each descendant of getOut() | output's def changes; descendants' input def-opcode changes |
| `opSetInput(op, V, slot)` | op, op->getIn(slot)->getDef() (old), V->getDef() (new) | op's slot, old-input def's descend list, new-input def's descend list |
| `opSetOutput(op, V)` | op, op->getOut() (old), V, V->getDef() (old) | op, old output, new output, new output's old def |
| `opSwapInput(op, i, j)` | op | no descendants affected |
| `opDestroy(op)` | op, op->getOut(), each descendant of out, each input's def | full chain |
| `newOp / newVarnode*` | Funcdata bank lock (single global) | bank is shared mutable |

**Deadlock avoidance**: sort lock targets by pointer value, acquire in ascending order. Use
`std::lock(...)` for atomic multi-lock acquisition where possible.

**Bank lock contention**: `newOp/newVarnode*` take a single global bank lock. Creates serialization
point for op creation. Mitigation: per-thread freelist of pre-allocated PcodeOp/Varnode objects
(refilled in batches under bank lock).

**Cost analysis**:
- Shared lock acquire: ~10-20 ns (`std::shared_mutex::lock_shared`)
- Exclusive lock acquire: ~30-50 ns
- Per typical `doApply`: 3-5 exclusive locks = 150-250 ns
- Per typical `canApply`: 2-3 shared locks = 40-60 ns

For 30M `applyOp` total:
- doApply lock overhead: 5% of total × 30M × 200 ns = 30 ms (assuming 5% fire rate)
- canApply lock overhead: 95% × 30M × 50 ns = 1.4 s (too much!)

**Refinement**: `canApply` skips locks entirely. It's pure read; concurrent reads of Varnode/op
fields are safe in C++ memory model **as long as** fields are not torn writes (use atomic flags
where needed per Path 1).

After this refinement, only `doApply` takes locks → 30 ms overhead. Acceptable.

### Sub-path 3B — Software Transactional Memory (STM)

Use GCC's libitm (`-fgnu-tm`) or hand-rolled STM.

```cpp
__transaction_atomic {
  doApply(op, data);
}
```

All reads/writes inside the transaction are logged. At commit, libitm checks for conflicts with
other transactions. On conflict, automatic rollback + retry.

**Pros**: simpler programming model, no manual lock management.

**Cons**:
- libitm overhead: 5-10× per transaction for typical workloads
- Decompiler is write-heavy → high conflict rate → many retries
- GCC libitm requires `-fgnu-tm` and all touched code compiled with transaction-safe attribute
- libitm is mature but not widely deployed; may have ABI issues

**Verdict**: NOT recommended for production. Prototype-only.

### Sub-path 3C — Hazard Pointers / Read-Copy-Update (RCU)

Used in Linux kernel for lock-free read-heavy data structures. Each writer copies the data structure,
modifies, atomically swaps in the pointer. Readers see consistent snapshots.

For decompiler: too complex for the deep IR mutation graph. Not pursued.

### Recommended: Sub-path 3A

Per-Varnode/op RW locks, with canApply reads lock-free (with atomic flags).

### Effort estimate Path 3

| Activity | Time |
|---|---|
| Atomic flag conversion (overlap with Path 1) | 8 hours |
| Per-Varnode/op shared_mutex addition | 16 hours |
| opSet*/opUnset* lock acquisition logic | 24 hours |
| Bank lock + per-thread freelist | 16 hours |
| Deadlock-free locking proof + tests | 16 hours |
| Race detector (TSan) integration + fuzz | 24 hours |
| Datatest sweep with parallel doApply | 32 hours |
| Performance tuning | 24 hours |
| Documentation | 8 hours |
| **Total Path 3** | **168 hours (~4.2 weeks)** |

### Deliverables Path 3

- `Varnode` and `PcodeOp` augmented with `std::shared_mutex`
- All `Funcdata::opSet*/opUnset*/opDestroy/newOp/newVarnode*` updated with lock acquisition
- Per-thread freelist for op/Varnode allocation
- TSan-validated lock-free correctness
- Performance benchmark showing parallel doApply scaling

---

## Integration plan

The three paths combine as follows:

```
ActionPool::apply(data) {
  if (parallel_enabled && data.opCount() >= minOps) {
    return applyBlockParallel(data);   // Path 2 entry point
  }
  return applySerial(data);  // existing v9 path
}

applyBlockParallel(data) {
  conflictGraph = data.getBlockConflictGraph();    // Path 2
  colors = conflictGraph.greedyColor();
  for (color in colors) {
    parallel_for (block in color) {                // Path 2 parallelism
      processBlockParallel(block, data);
    }
  }
}

processBlockParallel(block, data) {
  for (op in block.ops()) {
    for (rule in perop[op.code()]) {
      if (rule.canApply(op, data) == 0) continue;  // Path 1 filter, lock-free
      rule.doApply(op, data);                      // Path 3 locks taken inside
    }
  }
}
```

Each path is enabled independently via build flags / runtime options:
- `--enable-parallel-block` (Path 2)
- `--enable-parallel-canApply` (Path 1 — partial, current v10)
- `--enable-parallel-doApply` (Path 3)

Path 1 alone gives marginal speedup (~5%).
Path 1 + Path 2 with deferred cross-block mutations gives 1.5-2× speedup on multi-block functions.
Path 1 + Path 2 + Path 3 (full intra-function parallel) gives 2-4× on large functions.

---

## Testing & verification strategy

### Per-path unit tests

- **Path 1**: per-rule equivalence harness. For each rule, generate 100+ test ops and assert
  `applyOp(op, data)` outcome (before split) == `(canApply == 0) ? 0 : doApply(op, data)` (after split).
- **Path 2**: conflict graph correctness. Construct test functions with known cross-block dependencies;
  assert the graph contains expected edges and no false negatives.
- **Path 3**: TSan-validated lock acquisition. Build with `-fsanitize=thread`; run datatests; assert
  no data races.

### Integration tests

- **Datatests**: all 668 must pass with each path enabled (serial / Path1 / Path1+2 / Path1+2+3).
- **Top30 libc**: semantic equivalence. Compare decompiled output across parallel modes — variable
  naming may differ, but pcode structure must be identical (compare by parsing the C output to AST).
- **Cross-binary corpus**: extend to top100 functions across 10 different binaries (libc, libstdc++,
  Python interpreter, etc.) to surface edge cases.

### Race detection

Continuous run of decompile + TSan on every commit during Path 3 development. CI gates on no
TSan warnings.

### Performance regression suite

- Track per-function decompile time on a canonical benchmark suite
- Alert on regression > 5% in any function

---

## Effort summary & timeline

| Path | Engineer-weeks | Skill level required |
|---|---:|---|
| Path 1 (per-rule split + atomic flags, 152 rules) | 6.5 | Strong C++, Ghidra rule familiarity |
| Path 2 (block-DAG partitioning) | 3.3 | Strong C++, graph algorithms, Ghidra IR |
| Path 3 (fine-grained locking) | 4.2 | Strong C++ concurrency, lock-free, TSan |
| **Total sequential** | **~14 weeks** | |
| **Total with 2 engineers in parallel** | **~9 weeks** | Paths 1+2 can run mostly in parallel; Path 3 needs Path 1 outputs |

Realistic calendar with one mid-senior engineer full-time: **4-5 months end-to-end** including
testing, reviews, and unforeseen issues.

---

## Risk analysis

### High-risk items

1. **Path 1 Category C side effects** — some rules may have side effects that resist clean extraction.
   Mitigation: those rules stay as no-canApply (default -1); dispatcher falls back to serial for them.
   Impact: lower canApply coverage → less Path 2 parallelism for ops touching those rules.

2. **Path 2 conflict graph false negatives** — missing a conflict edge causes silent races.
   Mitigation: TSan validation + strict edge-coverage tests + conservative scope annotations
   (when in doubt, declare SCOPE_BLOCK_GLOBAL).

3. **Path 3 lock contention** — hot Varnodes (heritage MULTIEQUALs) may serialize many threads.
   Mitigation: profile lock contention; consider per-Varnode versioning (CAS) for high-contention cases.

4. **Bank lock as serialization point** — `newOp` / `newVarnode*` under one lock limits scaling.
   Mitigation: per-thread freelist refilled in batches; reduces bank lock acquisition by ~100×.

### Lower-risk items

5. Datatests may take longer to run (~3× with parallel + TSan). Mitigation: dedicated CI runner.

6. Memory overhead from per-object mutexes (~1.2 MB per function). Acceptable.

7. Some rules have deep recursion (RuleStructOffset0, RuleMultiCse) — may need stack-size tuning
   when running on worker threads.

---

## Open questions for engineering team

1. **Build system**: should parallel modes be compile-time `#ifdef` gated or runtime `option` gated?
   - Compile-time: cleaner code, two binaries to maintain
   - Runtime: single binary, dispatcher branching
   - Recommendation: runtime gate (matches Java `parallelDecompile` option already plumbed)

2. **Memory model**: do we require C++17 `std::shared_mutex` or C++20 `std::shared_timed_mutex`?
   Current codebase is C++11. Bump?
   - Recommendation: bump to C++17 (widely supported, cleaner shared_mutex semantics)

3. **Cross-platform**: do we need Windows MSVC support? Affects thread primitives selection.
   - Recommendation: stay POSIX-first; address Windows separately if needed

4. **Backward compat**: should the serial path stay available indefinitely?
   - Recommendation: yes — serial is the gold standard for SHA-equivalence requests

5. **Coverage threshold**: at what canApply coverage % do we declare Path 1 "done"?
   - Recommendation: 80% by call-count (covers the hot rules); the long tail can be incremental

---

## What's been done so far (commit `57061a37f0`)

- `parallel.{hh,cc}` thread pool foundation
- `Rule::canApply()` virtual + `has_canapply` opt-in flag
- 3 canApply implementations (RuleEarlyRemoval, RuleCollapseConstants, RulePropagateCopy)
- `ActionPool::applyParallel` two-phase dispatch
- env-gated (DECOMP_INTRA_WORKERS, DECOMP_INTRA_MINOPS)
- Pthread linkage in Makefile
- 668/668 datatests pass with parallel ON
- Currently 1-5% **slower** than serial due to overhead vs work imbalance

This represents ~1% of Path 1 (3/87 rules), 0% of Path 2, 0% of Path 3.

---

## Acceptance criteria for success

- **Correctness**: 668/668 datatests pass in all modes (serial, Path1, Path1+2, Path1+2+3)
- **Semantic equivalence**: top100 cross-binary corpus decompiles to AST-equivalent output
- **Performance**: ≥ 1.5× speedup on a benchmark of 5 single-large functions (printf_size,
  __wcsxfrm_l, getaddrinfo, __res_context_send, __strxfrm_l)
- **No regressions**: serial path remains within 2% of baseline
- **Memory**: total memory overhead < 5% on a 10000-function library decompile
- **TSan clean**: no data races detected in CI
- **Documentation**: design doc updated, per-rule audit table maintained, public API documented

---

*End of engineering plan.*
