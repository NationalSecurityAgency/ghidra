# Point 4: Heritage / ActionInferTypes profiling findings

Environment: stock Ghidra 12.0.4 native decompiler with profiling instrumentation, using the archived analyzed AGXG16X project and a quick libcrypto noanalysis smoke.

## Key AGXG16X top-heavy result

Top 10 largest functions completed in ~27.9s script time. Native substage totals:

- Heritage total: ~4.31s
  - Heritage::placeMultiequals: ~3.23s (~75% of Heritage)
  - Heritage::rename: ~0.76s (~18%)
  - per-space scan: ~0.29s (~7%)
- ActionInferTypes total: ~1.18s
  - propagateOneType loop: ~0.67s (~57% of ActionInferTypes)
  - buildLocaltypes: ~0.31s (~26%)
  - writeBack: ~0.19s (~16%)

Deeper placeMultiequals profile on top 5 functions:

- placeMultiequals total: ~2.78s
  - guard(): ~2.12s (~76%)
  - MULTIEQUAL creation: ~0.59s (~21%)
  - calcMultiequals/collect/refine are small
- guard() total: ~1.90s
  - guardCalls(): ~1.71s (~90% of guard)
  - guardStores(): ~0.16s (~8%)

The shape is therefore not "parallelize ActionInferTypes first". The first target is Heritage::guardCalls().

## Root cause of Heritage cost

For each disjoint memory range, Heritage::guard() calls guardCalls(), which scans every call-site in the function. In AGX top 5:

- guard ranges: 1448
- sum of call-site scans: 575,763
- hottest single ranges scan ~607 calls

This is an O(numHeritageRanges * numCalls) pattern. Heavy C++ driver functions with hundreds of calls make this dominate Heritage.

## Recommended targeted direction

Direction 4 should be split into:

1. First target: Heritage::guardCalls planning/apply split.
   - Keep ranges serial in placeMultiequals order.
   - For one range, evaluate call-sites in parallel into GuardCallPlan records.
   - Apply plans serially in call-index order to preserve deterministic trial registration and op insertion.
   - Threshold: only parallelize when fd->numCalls() >= 64 or >=128.
   - This attacks the measured 90% guard hot path without touching rename or SSA semantics.

2. Second target: Heritage MULTIEQUAL creation batching.
   - It is ~21% of placeMultiequals on AGX top 5.
   - Not as easy to parallelize because it mutates Funcdata/vbank/obank, but it can be optimized after guardCalls.

3. ActionInferTypes is secondary.
   - It is ~1.18s vs ~4.31s Heritage on AGX top 10.
   - The main type cost is propagateOneType; build/write are full Varnode scans but smaller.
   - Parallelizing roots naively is unsafe because setTempType()/mark traversal is a shared graph fixpoint.
   - Better first optimization: root filtering / priority order and converged-skip validation, not raw parallel DFS.

## Why not generic parallel runtime

Threadpool dispatch is not the bottleneck here. The measured hot path is a serial algorithmic cross-product in guardCalls(). A custom runtime would not remove O(ranges*calls); a planning/apply split would.
