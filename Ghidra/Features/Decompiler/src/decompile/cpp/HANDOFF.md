# Intra-function parallel decompiler — handoff

Branch: `feature/bounded-function-parallel-decompiler` on
`rdmitry/feature/bounded-function-parallel-decompiler`
(fork: https://github.com/rdmitry0911/ghidra.git).
Working tree: `/srv/project/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`.

## TL;DR after P4-fix-5/6 + P4-d4 + apples-to-apples bench

**Correctness:** Path 4 race fixed (P4-fix-5).  0/1680 SEGV under
massive-parallel stress, vs ~6% before.

**Performance vs stock upstream master (24 cores, libcrypto heavy corpus):**
The honest result, measured 18 May 2026 on 10.7.6.112 — see
`research/APPLES_BENCH_20260518.md` for full table:

```
  stock P=1    (master baseline)        7.93s   <- winner
  stock P=6                             7.93s   <- stock inter-fn pool saturates 24 cores

  ours P=1     (no intra-parallel)      8.48s   +6.9% slower than baseline
  ours P=6                              8.47s   +6.8%
  best ours intra-fn (P=3 W=8 path1)    9.11s  +14.9%
  ours P=6 W=4 path1+gcalls split       9.19s  +15.9%
```

**All our configurations lose to stock on this workload.**  The +7%
baseline serial overhead is the cost of the lock infrastructure
compiled in (Funcdata::poolMutex, Varnode::descendMutex, atomic
mod-counters) — uncontended, but adds up over millions of IR
mutations per function.

Inter-function parallelism (Ghidra's normal usage) already saturates
24 cores on this corpus.  Adding intra-function parallel on top
oversubscribes and costs more than it saves.

**Where our work still has value:**
  * Correctness fixes preserved across all configs
  * Lock infrastructure + parallel paths + guardCalls split are usable
    for call-heavy workloads (AGXG16X-style) where consultation
    profiling showed clear hot spots — we just don't have such a
    corpus locally to validate
  * HANDOFF.md, research/POINT4_FINDINGS.md, research/APPLES_BENCH point
    at the next concrete optimization targets

**To flip the result vs stock:**
  1. Compile-time drop locks when WORKERS<=1 at startup — templated
     Funcdata, no-op mutex policy.  Recovers the ~7% serial overhead.
  2. Workload-aware gating — engage intra-fn only when inter-fn pool
     is unsaturated AND function is large enough.
  3. Test on AGXG16X-class call-heavy workload where guardCalls is the
     measured 90% hot path.

See "Future-work ideas" at the end.

## What this branch is

Adds three optional intra-function parallel dispatch paths to
`ActionPool::apply` plus a runtime-tunable "never-fires" rule blocklist.
All paths default OFF; enable via env vars.

## Dispatch paths and env vars

```
DECOMP_INTRA_WORKERS=N         (>1 enables any parallel path; 0 = serial)
DECOMP_INTRA_MINOPS=K          (skip parallel for funcs with <K ops; default high)
DECOMP_INTRA_BLOCK_PARALLEL=1  (engage Path 3: color-aware canApply)
DECOMP_INTRA_TRUE_PARALLEL=1   (engage Path 4: parallel applyOp; needs BLOCK_PARALLEL)
DECOMP_INTRA_RULE_BLOCKLIST=a,b,c  (comma-separated rule names to disable)
DECOMP_INTRA_GRAPH_STATS=1     (dump block-conflict-graph stats)
DECOMP_INTRA_SCOPE_STATS=1     (per-mutation-scope test/fire counters)
DECOMP_INTRA_RULE_STATS=1      (per-rule test/fire counters at exit)
```

- **Path 1** (`WORKERS>1` alone): per-op stride canApply across N threads;
  serial phase 2 applyOp. Original prototype.
- **Path 3** (`+ BLOCK_PARALLEL=1`): partitions ops by block-conflict-graph
  color; phase 1 canApply parallel within color groups; serial phase 2.
- **Path 4** (`+ TRUE_PARALLEL=1`): phase 2a runs `scope_op_only` rules
  in parallel across color groups; phase 2b runs the rest serially.

`scope_op_only` is a per-Rule annotation
(`Rule::getMutationScope()` in `action.hh`, with values like
`scope_op_only`, `scope_block_local`, `scope_block_global`).

## Locking infrastructure for Path 4

See `parallel_safety.hh` for the full lock-hierarchy design doc.

- **L1 `Funcdata::poolMutex`** (`recursive_mutex`): every mutator that
  touches `vbank`/`obank` or any allocator. Acquired in `opSet*`,
  `opUnsetInput/Output`, `opDestroy*`, `opInsert*`, `newOp*`,
  `newVarnode*`, `newConstant`, `destroyVarnode*`.
- **L2 `Varnode::descendMutex`** (`mutex`, per-Varnode): guards
  `addDescend` / `eraseDescend` of the per-Varnode descend list.
- **L2u `Funcdata::unionMutex`** (`recursive_mutex`): guards `unionMap`
  (TypeUnion resolution cache).
- **L3 atomic mod-counters**: `globalModCount` / `irModCount` /
  `vnCreateCount` / `typeModCount` are `std::atomic<uint8>` with
  relaxed ordering.

## Real-world performance (libcrypto 14 heavy funcs, 5 runs avg s)

### Local 16-core fast-clock host

```
                       pre-fix-5/6  post-fix-5/6   Δ (perf regression
                       ~6% SEGV       0% SEGV       from rule demotion)
serial baseline           5.09         4.78          base
serial + bl               5.20         5.15
path1 W=4                 4.70 -7.7%   4.73 -1.0%   +6.7pp
path1 W=8                 4.50 -11.6%  4.75 -0.6%   +11.0pp
path3 W=4                 4.68 -8.1%   4.95 +3.6%   +11.7pp
path4 W=4                 4.13 -18.9%* 5.02 +5.0%   +23.9pp
path4 W=8                 4.22 -17.1%* 5.07 +6.1%   +23.2pp
                          * had ~6% SEGV
```

### Remote 10.7.6.112, 48-core slow-clock host (post-fix-5/6)

```
serial baseline           8.50          base
serial + bl               9.15          +7.7%
path1 W=4                 9.08          +6.8%
path1 W=8                 9.07          +6.7%
path3 W=4                 9.47          +11.4%
path3 W=8                 9.50          +11.8%
path4 W=4                 9.95          +17.1%
path4 W=8                10.04          +18.1%
```

### Stress (massive-parallel: 24 procs × 5 iters × 14 funcs = 1680 decompiles)

```
serial × 24:              wall = 57.2s          0/1680 SEGV
path4 W=4 × 24:           wall = 65.5s   +14%   0/1680 SEGV  <- stability!
```

Bench scripts: `bench_real.sh`, `bench_minops.sh`, `bench_stress.sh`,
`stress_parallel.sh` (in `/tmp/` on remote).  All scripts use
`SLEIGHHOME` env override.

### Recommended runtime configuration

- Production default: `WORKERS=0` (serial, safest AND fastest on
  every host tested post-fix-5/6).
- Bulk decompile across many functions: rely on Ghidra's existing
  inter-function parallelism (function-level worker pool); intra-function
  parallel paths currently add overhead without payback after the
  HumptyDumpty/DumptyHump demotion.
- Path 4 (TRUE_PARALLEL=1) is now correctness-clean on libcrypto but
  net-slower than serial on both tested hosts.  Worth keeping the
  infrastructure in tree as a base for the follow-up work below.

## Datatests baseline (664/668 expected — 4 stack-spill failures are pre-existing)

```
serial:                                 664/668
path1 W=4:                              664/668
path3 W=4 (+BLOCK_PARALLEL):            664/668
path4 W=4 (+TRUE_PARALLEL):             662/668
   ↑ Union #8, Union #10 — deterministic regressions due to
     non-deterministic union-field resolution order across workers.
     Not a SEGV; output is valid but picks a different field.
```

## Open items

### 1. Path 4 residual SEGV (~6% on libcrypto, 0% on datatests)

500/500 ASan stress on datatests is clean. Heavy libcrypto fat-funcs
stress: 47/50. Crash signature:

```
Varnode::isMark() at varnode.hh:268     ← null this
SubvariableFlow::setReplacement (subflow.cc:70)
SubvariableFlow::createLink (subflow.cc:1026)
SubvariableFlow::traceForward (subflow.cc:402)
RuleSubvarZext::applyOp (subflow.cc:1774)
ActionPool::processOp (action.cc:1083)  ← SERIAL dispatcher
ActionPool::apply (action.cc:1161)
```

Critical observation: crash is in the **serial** `processOp` loop
reached when `status == status_mid`, not in `applyBlockParallel` proper.
This means a previous parallel sweep returned −1 (action break or
checkActionBreak), left state inconsistent, then the next call fell to
serial dispatch which crashes on the corrupted state.

Three hypotheses (not yet validated):
- (a) phase 2a leaves an op with `output=null`; later serial dispatch
  iterates that op's input chain via `vn->descend` and finds it.
- (b) a `scope_op_only` rule transiently rewrites an input-chain
  another worker reads without holding `poolMutex`.
- (c) a workload-specific invariant in `SubvariableFlow` that
  pre-existed but is only exposed when phase 2a mutates IR before the
  serial cleanup.

Recommended next investigation:
1. Add a debug counter in `applyBlockParallel` for `breakReq` hits; run
   on libcrypto corpus to see if it ever fires (if not, hypothesis (a)
   needs different explanation).
2. Build ASan + TSan combined; rerun libcrypto stress. TSan should flag
   the unprotected read race if (b) is the cause.
3. Diff IR snapshots between serial-only and parallel-then-serial runs
   on a single libcrypto function (FUN_0037d150 is the heaviest, 19.6KB
   code, in `/tmp/bench_corpus/xml_heavy/0000_FUN_0037d150.xml`); the
   first divergence point identifies which rule misbehaves.

### 2. Union-field resolution non-determinism (Path 4 only)

Union #8, Union #10 (and intermittently Inlining #4) fail under
TRUE_PARALLEL because the first-writer-wins semantics of
`Funcdata::setUnionField` depends on worker scheduling order.

Mitigations to evaluate:
- Order-independent union scoring with a deterministic tiebreaker on
  edge identity.
- Gate phase 2a sequentially when union types are detected in the function.
- Stricter `scope_op_only` annotation that excludes rules calling
  `getTypeReadFacing`/`forceFacingType`/`inheritUnionField`.

### 3. Misannotated rules already downgraded in commit 73520f94ac

These previously caused UAF or null-deref under Path 4 and were moved
from `scope_op_only` to `scope_block_global`:
- `RuleEarlyRemoval` (called `data.opDestroy(op)` which delete's the
  output Varnode)
- `RuleTermOrder`, `RuleStoreVarnode`, `RuleSegment` (insert new op
  into block AND create Varnode at shared address)
- `Rule2Comp2Mult`, `RuleCondNegate`, `RuleTransformCpool` (insert new
  op into block)

The audit was driven by ASan; there may be more in `subflow.cc` rules
that I didn't sweep — worth a second pass if the residual 6% SEGV is
traced to one of them.

### 4. `opSetInput` atomic-pointer-swap fix (commit 73520f94ac)

Reorders `opUnsetInput → addDescend → setInput` to
`addDescend → setInput → eraseDescend(old)` so readers never see
`op->in[slot] == nullptr`. Descend-list invariants are briefly broken
during the window, but phase-2a rule reads tolerate that.
**A parallel fix for `opSetOutput` was attempted and reverted** because
it broke `vbank.setDef` invariants — the order there is load-bearing.

### 5. Disk / repo hygiene

- Working tree disk is at 100% (200MB free). The build/dist/*.zip was
  removed in commit 434b49fc3c to make room; rebuilding ghidra_opt
  needs ~10MB and is fine.
- Two untracked files in the repo root (above cpp/) that should NOT be
  committed: `OpenJDK25U-jdk_x64_linux_hotspot_25.0.2_10.tar.gz` (135MB
  user-downloaded JDK tarball) and `wget-log`. Leave them alone unless
  the user asks otherwise.
- An ASan-built `decomp_test_dbg` may be present (~63MB). Rebuild
  without ASan flags for normal use:
  ```
  rm -f test_dbg/*.o decomp_test_dbg
  make -j$(nproc) decomp_test_dbg
  ```

## Bench harness usage

All scripts assume cwd = `cpp/`.

```
# Stress / smoke (datatests, 20 iters × 3 runs, 12 modes, ~18 min)
./bench_stress.sh

# Real-corpus bench (8 modes, 3-5 runs)
./bench_real.sh /tmp/bench_corpus/xml_heavy 5

# MINOPS sweep (Path 1 and 3 across MINOPS thresholds)
./bench_minops.sh

# Generate a fresh corpus from a binary (requires headless analysis;
# ~5min for libcrypto)
HEADLESS=/srv/project/ghidra/build/ghidra_install/ghidra_12.2_DEV/support/analyzeHeadless
BENCH_XML_DIR=/tmp/bench_corpus/xml_heavy BENCH_MIN_BYTES=8000 BENCH_MAX_FUNCS=15 \
  "$HEADLESS" /tmp/bench_corpus/proj p -import /usr/lib/x86_64-linux-gnu/libcrypto.so.3 \
  -postScript /tmp/bench_corpus/scripts/DumpDecompXml.java \
  -scriptPath /tmp/bench_corpus/scripts -deleteProject
```

Corpora on disk:
- `/tmp/bench_corpus/xml`        — 50 libcrypto fat funcs (3.8-19.6KB)
- `/tmp/bench_corpus/xml_heavy`  — 14 libcrypto funcs (8-19.6KB)
- `/tmp/bench_corpus/xml_giant`  — 2 libcrypto giants (326KB each)

The dump script: `/tmp/bench_corpus/scripts/DumpDecompXml.java`.

## ASan repro for the residual SEGV

```
# Build ASan decomp_test_dbg
rm -f test_dbg/*.o decomp_test_dbg
make DBG_CXXFLAGS="-g -Wall -Wno-sign-compare -pthread -fsanitize=address -fno-omit-frame-pointer" \
     LNK="-lz -fsanitize=address" -j$(nproc) decomp_test_dbg

# datatests stress (currently 500/500 clean)
bash /tmp/asan_repro3.sh   # 100 iters; should pass

# Build ASan decomp_opt and stress libcrypto (currently ~6% SEGV)
rm -f com_opt/*.o decomp_opt
make OPT_CXXFLAGS="-O2 -Wall -Wno-sign-compare -pthread -fsanitize=address -fno-omit-frame-pointer -g" \
     LNK="-lz -fsanitize=address" -j$(nproc) decomp_opt
bash /tmp/asan_libc_repro.sh    # 30 iters until first crash; ASan stack
```

## Path 1/2/3 history (for context)

- **Path 1** (commits before 90fc891): plain canApply parallelism;
  per-op stride; serial phase 2.
- **Path 2**: annotated 136 active Rule subclasses with mutation_scope
  metadata (`scope_op_only`/`scope_block_local`/etc.) — drove every
  later decision.
- **Path 3**: color-aware canApply via `BlockConflictGraph`
  (`block_conflict.hh/cc`), greedy coloring; added the
  `DECOMP_INTRA_RULE_STATS` reporter and the 26-rule "never-fires"
  blocklist (which the libcrypto bench showed is workload-sensitive
  and should NOT be a default — see "Recommended runtime configuration"
  above).

## Files touched

- `parallel_safety.hh` — design doc + lock hierarchy.
- `parallel.cc/hh` — `ThreadPool` (single-instance, env-sized).
- `block_conflict.cc/hh` — DAG color partitioning.
- `action.cc/hh` — `applyParallel`, `applyBlockParallel`, env getters,
  stats reporters, scope filter.
- `funcdata.cc/hh` — `poolMutex`, `unionMutex`, atomic counters, lock
  wrappers in `unionMap` accessors.
- `funcdata_op.cc` — lock_guards in every mutator; atomic-swap
  `opSetInput`.
- `funcdata_varnode.cc` — lock_guards in `destroyVarnode*` and
  `newVarnode*`.
- `varnode.cc/hh` — `descendMutex`, lock_guards in `addDescend` /
  `eraseDescend`.
- `ruleaction.hh` — `getMutationScope` overrides on ~150 Rule
  subclasses; 7 downgraded in P4-fix.
- `Makefile` — added `parallel` and `block_conflict` to `DECCORE`
  (otherwise `ghidra_opt` doesn't link).
- `bench_*.sh` — bench harnesses.

## Key open task

The residual 6% SEGV was bisected (by external consultation) to
`RuleHumptyDumpty` + `RuleDumptyHump` and resolved by demoting both
from `scope_op_only` to `scope_block_global` in commit `5865290f9f`.
However, those were the highest-firing scope_op_only rules and
removing them killed Path 4's perf win.

## Future-work ideas to recover perf

The fundamental observation: `scope_op_only` was too coarse a
criterion — it asks "does the rule mutate only its own op?" but
should also ask "does it mutate atomically?".  Three concrete
directions for getting Path 4 back into a measurable speedup:

1. **Refactor HumptyDumpty/DumptyHump (and similar) to atomic
   rewrites.**  Add `Funcdata::opRewrite(op, new_opcode, new_inputs)`
   that performs all the swap operations under poolMutex without
   leaving the op in an intermediate state.  Then re-promote both
   rules back to scope_op_only.  Expected ~10pp recovery on phase 2a
   parallel work.

2. **Add per-PcodeOp shared_mutex for phase 2a.**  Each op gets a
   `shared_mutex`; phase 2a workers take a writer-exclusive lock
   on the op they're rewriting; any thread reading op->getIn() /
   op->getOut() takes a reader-shared lock.  Lots of new read sites
   to wrap.  Memory overhead ~40 bytes per op (significant for large
   functions).  Most thorough fix, biggest code churn.

3. **Sequentialize phase 2a per color group.**  Currently each color
   group runs on one worker thread.  If we can guarantee that no two
   workers ever touch the same shared Varnode (true under the
   color-graph partition), then multi-step rewrites within one color
   are still safe.  Requires proving the partition is strict.  Today
   the color partition is by BLOCK, but shared input Varnodes can
   cross color boundaries via descend lists — that's exactly the
   conflict the multi-step bug exposed.  Would require partitioning
   by Varnode reachability rather than block, or extending the
   conflict graph.

Direction 1 is the cheapest to try.  Direction 3 is the most
elegant if achievable — it would also fix the union-determinism
issue (open item 2).

## Other open items still relevant

- Union #8 / #10 determinism (open item 2 in original list): order-
  independent union scoring with a deterministic tiebreaker would fix it.
- Verify no other multi-step scope_op_only rules: I downgraded 7
  in `73520f94ac` plus the 2 above in `5865290f9f`; the consultation's
  bisect process (binary-search the denylist on libcrypto) should be
  re-run on a different non-libc binary to catch any remaining ones.

## Commit timeline (most recent first)

```
e05701822c P4-fix-6: drop cross-core counter writes from phase 2a hot loop
4c83aaa790 bench_real: SLEIGHHOME env-overridable (was hard-coded /srv path)
5865290f9f P4-fix-5: downgrade HumptyDumpty + DumptyHump (non-atomic rewrites)
ba9aa27986 Add HANDOFF.md for branch successor
1c08eb7300 parallel_safety: document final P4 status + runtime recommendations
10acac5a98 bench_real: add path4 W=4/W=8 modes; final P4 perf numbers
73520f94ac Path 4 fixes: ASan-validated race triage + atomic opSetInput
```
