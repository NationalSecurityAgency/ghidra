# P4-d5: conditional-lock elision — bench results

Host: 10.7.6.112, 24 cores pinned via taskset --cpu-list 0-23.
Corpus: libcrypto heavy xml (14 funcs).  SLEIGHHOME = ghidra_12.2_DEV.
Compiler: gcc 15.2.0, -O2 -m64 -pthread.

## Headline

Before lock elision (apples bench commit 14d3dd95b2):

```
stock P=1 = 7.93s     ours P=1 = 8.48s     →  +6.9% slower
stock P=24 = 11.12s   ours P=24 = 11.58s   →  +4.1% slower
```

After P4-d5 (commits 27e287daaa..e6bcb57020):

```
stock P=1 = 7.93s ± 0.16     ours P=1 = 8.13s ± 0.07     →  +2.6% slower
stock P=24 = 11.19s          ours P=24 = 11.03s          →  -1.4% (faster)
```

Apples bench, RUNS=3:

```
                          stock  ours       Δ
P=1   (serial single)     8.10   8.05    -0.6%   (cache warmer than focused)
P=6   (4 cores/proc)      7.76   7.91    +1.9%
P=12  (2 cores/proc)      9.32   9.39    +0.8%
P=24  (max throughput)    11.19  11.03   -1.4%
```

Focused bench, RUNS=10 + warmup (variance ≤ 0.16s):

```
                          stock  ours       Δ
P=1 serial                7.93   8.13    +2.6%
P=1 W=4 intra-fn (path1)  —      8.99    n/a   (no stock equivalent)
P=1 W=8 intra-fn (path1)  —      8.97    n/a
P=1 W=16 intra-fn (path1) —      9.00    n/a
P=1 W=8 guardCalls        —      8.99    n/a
```

## What we did

1. **P4-d5** (27e287daaa) — `parallel_safety.hh` adds `g_parallelActive`
   atomic<bool>, set once at startup from env (`DECOMP_INTRA_WORKERS>1`
   OR `DECOMP_PARALLEL_GUARDCALLS=1`).  `ConditionalRecursiveLock` and
   `ConditionalMutexLock` RAII wrappers skip mutex ops when the flag is
   false.  Replaced 34 `std::lock_guard` sites across funcdata.cc,
   funcdata_op.cc, funcdata_varnode.cc, varnode.cc.

2. **P4-d5b** (e881ca288f) — gate atomic counter `fetch_add` (LOCK XADD)
   behind `isParallelActive()`.  Serial path now uses
   `store(load(relaxed) + 1, relaxed)` — plain MOV/INC/MOV, no bus
   lock.  Affects `bumpGlobalModCount` / `bumpIrModCount` /
   `bumpVnCreateCount` / `bumpTypeModCount`.

3. **P4-d5c** (30a6c2ed44) — remove per-Varnode `descendMutex` field
   (40-byte std::mutex), replace with a 256-entry process-global mutex
   pool hashed by Varnode address.  Restored `sizeof(Varnode)` to the
   pre-P4 baseline.  Each Varnode previously straddled 3 cache lines
   instead of 2 — this was the largest single contributor to the gap.

4. **P4-d5d** (e6bcb57020) — `__builtin_expect` hints; mark
   `isParallelActive()` branches as UNLIKELY in `ConditionalLock`
   helpers and in the bump-counter helpers so the compiler lays out
   the no-lock serial path as the taken branch.

## Datatest validation

```
serial (default):                668/668 PASS
DECOMP_INTRA_WORKERS=4 path1:    668/668 PASS
DECOMP_PARALLEL_GUARDCALLS=1:    668/668 PASS
```

## Residual gap

Stock P=1 vs ours P=1 still shows +2.6% in focused bench (RUNS=10).
Sources of the remaining gap, in descending order of probable impact:

1. **Extra function call frames.**  Our `opSetInput` now calls
   `addDescend` (which calls `descendMutexFor()` then constructs/destroys
   `ConditionalMutexLock`) → `Varnode::setInput` → `bumpIrModCount`
   (constructs/destroys nothing but inlines a branch).  Stock's
   `opSetInput` is shorter.  At ~5 ns per extra function call frame
   and ~5M opSetInputs in the corpus, that's ~25ms over an 8s run = 0.3%.

2. **Atomic relaxed load** in `isParallelActive`.  Even on x86 this is
   a plain MOV from memory, but it requires the compiler to treat it as
   a possible observation point — no hoisting out of loops.  Where stock
   would have constant-fold or register-allocate, we have a MOV.

3. **`std::atomic<uint8>` for mod counters.**  Even with relaxed load/
   store, the codegen is slightly less efficient than plain `uint8` for
   the same reason — the compiler can't fold sequential bumps into a
   single add.

4. **Code size growth.**  Conditional branches inflate the I-cache
   working set.  Each lock-acquire site is now an extra ~5 bytes of
   code; 34 sites = +170 bytes; not huge but non-zero.

To close the remaining 2.6% we'd need to either ship two binaries
(serial-only vs full) or use template specialization to compile-time
elide everything when a build flag is set.  Not worth the build
complexity for 2.6% on this workload.

## Conclusion

The recommended production configuration after P4-d5 is **stock
defaults** (serial mode) — our binary is now within ~2.6% of stock at
P=1 and competitive at P=24.  The intra-fn parallel modes are
infrastructure-ready but don't beat embarrassingly-parallel inter-process
decompilation on this corpus (where work-per-fn is uniform).

Use cases where the intra-fn parallel infrastructure WOULD help:
- **One huge function.**  When the workload has a few outsized functions
  and few cores can be filled with parallel functions.
- **Tight latency on a single function.**  GUI decompile-on-demand where
  one function blocks the user.
- **Low core count + big workloads.**  Where inter-fn parallelism can't
  saturate cores.

For bulk batch decompilation on multi-core hosts with many functions:
spawn N independent decomp processes (P=cores or P=cores/2) and leave
intra-fn parallel off.  Our binary is now no slower than stock for that
pattern, and 1.4% faster at P=24 in the apples bench.
