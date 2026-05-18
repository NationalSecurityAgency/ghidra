# Intra-function parallel decompiler — handoff

Branch: `feature/bounded-function-parallel-decompiler` on
`rdmitry/feature/bounded-function-parallel-decompiler`
(fork: https://github.com/rdmitry0911/ghidra.git).
Working tree: `/srv/project/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp`.

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

```
serial baseline     5.09   base
serial + bl         5.20   +2.2%   ← blocklist HURTS on crypto (workload-specific)
path1 W=4           4.70   -7.7%
path1 W=4 + bl      4.77   -6.3%
path3 W=4           4.68   -8.1%
path3 W=4 + bl      5.03   -1.2%
path1 W=8           4.50  -11.6%   ← best stable, no crashes
path3 W=8           4.67   -8.3%
path4 W=4           4.13  -18.9%*  ← best (one segv in 5; ~-13% without)
path4 W=8           4.22  -17.1%*  ← (one segv in 5; ~-13.6% without)
```

The numbers vary across runs (noise band ~3-5%); the table reflects the
last-recorded benchmark from commit `10acac5a98`. Bench scripts:
`bench_real.sh`, `bench_minops.sh`, `bench_stress.sh`.

### Recommended runtime configuration

- Production default: `WORKERS=0` (serial, safest)
- Bulk decompile: `WORKERS=8` alone (path1, −11.6% on heavy, no crashes
  reproduced)
- Max throughput, opt-in: `WORKERS=4 BLOCK_PARALLEL=1 TRUE_PARALLEL=1`
  (path4, ~−13% mean, ~6% per-function SEGV rate on non-libc workloads)

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

The single most valuable next step is **finding and fixing the residual
6% SEGV on libcrypto** (open item 1 above). The fix is likely small (a
missing lock, a missing scope downgrade, or a phase 2b that needs to
always run). Once that's clean, Path 4 becomes shippable at −13% and
the whole branch is ready for upstream review.
