# Apples-to-apples: stock master vs ours on 24 cores (10.7.6.112)

Workload: libcrypto heavy 14 fat funcs (8-19 KB code each).
Each proc fully processes the 14-func corpus serially.
Pinned to CPUs 0-23.  3 runs/mode, avg seconds.

```
config                          wall    Δ vs stock P=1
---------------------------------------------------------
STOCK upstream master:
  stock P=1                     7.93s   baseline
  stock P=6                     7.93s   0%       ← scales linearly until ~6
  stock P=12                    9.49s   +19.7%
  stock P=24                   11.12s   +40.2%   ← oversubscription

OURS, no intra-fn parallel:
  ours P=1                      8.48s   +6.9%    ← our binary serial OVERHEAD
  ours P=6                      8.47s   +6.8%
  ours P=12                     9.78s   +23.3%
  ours P=24                    11.58s   +46.0%

OURS, intra-fn parallel modes at P=6 (24/4 inner):
  ours P=6 W=4 path1            9.10s   +14.8%
  ours P=6 W=4 path3            9.55s   +20.4%
  ours P=6 W=4 path4            9.98s   +25.9%
  ours P=6 W=4 gcalls           9.19s   +15.9%
  ours P=6 W=4 path3+gcalls     9.52s   +20.1%

OURS, P=3 W=8:
  ours P=3 W=8 path1            9.11s   +14.9%
  ours P=3 W=8 path3            9.43s   +18.9%
  ours P=3 W=8 path4           10.00s   +26.1%

OURS, P=12 W=2:
  ours P=12 W=2 path1          10.44s   +31.6%
  ours P=12 W=2 gcalls         10.54s   +32.9%
```

## Two-line summary

  * Best stock = 7.93s.  Best ours = 8.47s (+6.8%, no intra-parallel).
  * ALL our configurations lose to stock by 7-33%.

## Honest reading

1. **Our binary in pure-serial mode is ~7% slower than stock.**  This is
   the cost of the lock infrastructure compiled in:
   - Funcdata::poolMutex acquired on every IR mutation (~20 ns each ×
     millions of mutations per function)
   - Varnode::descendMutex on addDescend/eraseDescend (similar)
   - Atomic mod-counter fetch_add (4 of them, several per mutation)
   - Per-rule scope-stat env-checks (static-cached, but still load)
   The uncontended mutex fast path is ~10-20 ns each; with millions of
   mutation calls per function, this accumulates to ~500ms over 14 funcs.

2. **Inter-function parallelism (stock P=6) already saturates 24 cores
   on this corpus.**  P=6 == P=1 wall time, meaning the function pool
   amortizes startup cost without adding overhead.  Adding intra-fn
   parallel on top oversubscribes.

3. **Our intra-fn parallel paths (1/3/4) and the guardCalls split all
   regress on this workload** because:
   - libcrypto fat funcs aren't call-heavy enough (avg 17.6 calls per
     guardCalls invocation, max 228 in one func).  Threadpool dispatch
     overhead exceeds gain.
   - HumptyDumpty/DumptyHump demotion (P4-fix-5, required for
     correctness) removed the highest-firing scope_op_only rules from
     phase 2a, leaving little parallel work.

## Where our work still has value

- **Correctness fixes:** P4-fix-5 removed a 6% per-function SEGV race
  exposed under stress.  This is preserved across all our configs.
- **Infrastructure:** parallel.cc, block_conflict.cc, lock-hierarchy
  design, guardCalls split, scope stats, blocklist — all usable for
  future workloads (e.g., AGXG16X-style call-heavy) where they were
  measured to win.
- **Documentation:** HANDOFF.md + research/point4_profile/ point at the
  next high-value optimization (Heritage::guardCalls), with a proven
  hot-spot measurement and a concrete refactor direction.

## What it would take to flip the result

1. **Eliminate serial overhead** — compile-time flag to drop the locks
   when DECOMP_INTRA_WORKERS<=1 at startup.  Templated Funcdata with
   no-op mutex policy.  Recovers ~7%.

2. **Workload-aware engagement** — gate intra-fn parallel on numCalls
   ≥ 64 AND function body size ≥ some threshold AND not currently
   under inter-fn pool contention.  Recovers parallel cost on small
   workloads.

3. **Test on a call-heavy real workload** (AGXG16X or similar Apple
   kernel/driver, libstdc++/libc++ stress tests) where the consultation
   measured guardCalls dominating.  Expect our intra-fn paths to win
   there.
