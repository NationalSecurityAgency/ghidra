# SymbolicPropogator: stack tracking across inlined flow

**Status: RESOLVED.**  The "stack tracking lost across IFC bodies"
class of bugs turned out to be a one-line guard bug in
`VarnodeContext.putInitialValue` (commit `737a2a49`'s own addition),
not an architectural problem with how `SymbolicPropogator` walks
inlined flow.  Fixed in commit `8454ae48`.

The Approach C / D plans below are kept for historical reference -
they are not needed.

## What was actually wrong

`putInitialValue` was added to seed register entry-state values from
`programContext` without polluting `lastSet` with the function-entry
instruction (commit `737a2a49`).  Its guard read:

```java
if (out.isUnique() || !out.isAddress() || !isRegister(out)) {
    return;
}
```

`Varnode.isAddress()` returns true only for `TYPE_RAM` space.
Register varnodes live in `TYPE_REGISTER` and report
`isAddress() == false`.  The guard therefore short-circuited
**every** register seed - putInitialValue was a no-op for its only
intended caller (`SymbolicPropogator.flowConstants`'s
register-with-values loop).

Cascading effect on NDS32 push25 → IFC body → pop25:

1. `gp` entered the propagator with no tracked value (seed dropped).
2. `push25` ran `STORE sp-8 = getValue(gp)`; getValue returned gp's
   register varnode (no concrete value), so sp-8 held a
   self-reference rather than `0x202e000`.
3. The body ran and disturbed nothing semantically meaningful at
   sp-8 (the IFC body in `FUN_ram_000b8b4a` is just one `jal`).
4. `pop25` LOADed sp-8, got back the self-reference, and either
   resolved to null (no concrete value) or - via the 31-layer
   `memoryVals` walk - happened to find a stale small constant from
   some unrelated branch and propagated it as gp.
5. The analyzer then asked `getLastSetLocation(gp, 0x14)` and got
   pop25 back, creating a bogus `_gp_N @ 0x14`.

The 31-layer dump in the original observation was real but a red
herring - the layers were correct, the symbol just wasn't there to
find because step 1 silently failed.

## How it was found

Direct instrumentation in `VarnodeContext` (PUT/GET/PUSH/POP traces
gated by `-Dghidra.varnode.debug.spaces=sp,register`).  Captured a
trace of `FUN_ram_000b8b4a` and noticed `putInitialValue` was being
called for `gp` with `value=(const, 0x202e000, 4)`, but the
subsequent push25 STORE saw `(register, 0x74, 4)` (the register
itself) at sp-8 - meaning the seed had not landed.  Added one line
of trace inside `putInitialValue` to log the guard-check decision
and the early-return path fired immediately because `isAddress()`
was false for the register varnode.

## The fix

```diff
- if (out.isUnique() || !out.isAddress() || !isRegister(out)) {
+ if (out.isUnique() || !isRegister(out)) {
```

With the guard fixed:

* On `FUN_ram_000b8b4a`, push25 stores `(const, 0x202e000, 4)` at
  sp-8 and pop25 LOADs it back unchanged.  `getRegisterValue(gp)` at
  pop25 returns the correct seed value.
* Across mt7663 fresh import: 0 bogus low `_gp_N` symbols,
  `GenericRomCheck` 4/4.
* Across spider_n9: `RomRegressionSuite` 20/20, all other
  regressions unchanged.
* No perf regression - mt7663 first-import wall time 57s, same as
  before.

## What this means for Approaches A / B / C / D

* **Approach A (`getLastSetLocationFromConstant`)** is now belt-and-
  suspenders.  The underlying stack tracking is correct; A is still
  good defense-in-depth for processors that hit similar attribution
  problems through other code paths (MIPS gp recovery, future Andes
  V5).  Worth keeping as upstream API.
* **Approaches B, C, D** are not needed.  They were proposed under
  the assumption that the propagator's flow walk through IFC bodies
  is fundamentally wrong; it isn't.  The sleigh-level "ifcall as
  conditional jump" model already gives the propagator a transparent
  view of the body, and the symbolic stack namespace doesn't need
  per-flow sub-namespaces (Approach C) or boundary
  snapshot/invalidation (Approach D) for the cases we hit.

## Cross-references

* Commit `737a2a49`: introduced `putInitialValue` (with the guard
  bug).
* Commit `28ded630`: introduced `getLastSetLocationFromConstant` as
  downstream defense.
* Commit `8454ae48`: this fix.
