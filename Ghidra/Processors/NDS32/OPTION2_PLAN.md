# Option 2: per-ifcall body-pcode inlining at the DecompileCallback

**Goal:** Eliminate the `in_ifc_lp = 0xCALLER_NEXT; if (in_ifc_lp == ...)`
clutter that appears in decompile output for multi-caller IFC bodies.

**Scope after recategorization (spider_n9, ~mt7663 similar):**

| Spider count (multi-caller bodies)              | Notes                                                |
| ----------------------------------------------- | ---------------------------------------------------- |
| 151 total                                       | Bodies reached from >1 ifcall site in same caller    |
| 21 have nested ifcall* in body                  | **Not** a blocker - nested ifcall is `goto target`   |
| 31 have backward branches (loops)               | Tractable: remap branch targets to internal pcode    |
|                                                 | seq numbers within the inlined sequence              |
| 15 have mid-body BRANCHIND (`jr Rt` etc.)       | Tractable: copy JumpTable annotation per inline copy |
| 3 share body addrs with another function's body | Trivial: inlined copy is independent                 |

**No fundamental blockers**, just implementation work.

## Current decompile shape

For a body B that exits at ifret16 with N callers in caller F:
* At each ifcall site Ai in F, sleigh emits `ifc_lp = Ai.next; IFC_ON = 1; goto B`.
* At B's ifret16, DecompileCallback emits a multi-branchback synth that
  CBRANCHes ifc_lp against each Ai.next and branches accordingly.
* The decompiler renders the comparisons as visible C: `if (in_ifc_lp == 0x...)`.

## Target shape

At each ifcall site Ai in F, emit the entire body B's pcode INLINED with
terminals replaced by `BRANCH Ai.next`.  B's address is no longer in F's
extension, multi-branchback map drops these entries, dispatch synth at B
disappears, and decompiler renders B's effects inline at each ifcall site.

## Implementation pieces

1. **`NDS32IFCAnalyzer`** - publish a new property map `IfcInlineBody:<entry>`
   (StringPropertyMap, ifcall-addr -> body description) carrying enough
   info for DecompileCallback to walk the body without re-walking on
   every decompile.  Likely shape: ifcall-addr -> comma-separated list of
   body-instruction addresses in flow order, terminated with the exit
   address.

   Apply only to bodies where:
   - All terminals are ifret/ifret16 OR an unconditional tail-call.
   - Walker reaches every body instruction (no unresolved indirect jumps
     that escape the body).
   - Body size below a configurable threshold (start with 32 insns).

   Replace existing IfretMultiBranchback / IfretBranchback entries for
   these bodies.  Drop the body addresses from FunctionBodyExt.

2. **`DecompileCallback.emitFunctionPcodeOverride`** - handle the new map.
   On hitting an ifcall site with an IfcInlineBody entry:
   - Walk the listed body instructions in flow order.
   - For each body insn, get its prototype pcode (`Instruction.getPcode()`).
   - Re-address each PcodeOp to the ifcall site address.
   - Assign sequential seq numbers (continuing from where the synth left off).
   - Re-offset unique varnodes per-body-instruction so the body's intra-
     instruction uniques don't collide across instructions.  Use
     `unique_base += 0x100` per body insn.
   - For internal branches (target is another body instruction): rewrite
     target to `(ifcall_site_addr, target_seq)`.
   - For terminal ifret/ifret16: replace pcode with `IFC_ON = 0; BRANCH inst_next`.
   - For terminal tail-call `jal X`: emit `CALL X; BRANCH inst_next`.
   - For non-terminal BRANCHIND with a JumpTable override: emit the
     BRANCHIND and ensure the synth gets the same target set
     (need to look at `Instruction.getJumpTables()` and re-attach).
   - For non-terminal `j X` (unconditional jump to outside body):
     leave the BRANCH as-is.

3. **No emitMultiBranchback at body addresses** for ifcall sites covered
   by the new map.  The existing emitMultiBranchback path stays for bodies
   that don't qualify for inlining.

## Things to validate during implementation

* **Unique varnode collision** - if two body insns use the same unique
  number for different purposes, re-offsetting per-insn is critical.
  Verify via at least one body that uses uniques heavily.
* **Pcode SEQNUM space** - the ifcall site's emitted pcode array has a
  single ordering; every op's SequenceNumber must be unique.  Use
  monotonic seq numbers starting at 0.
* **JumpTable annotation propagation** - look at how
  `DecompileCallback.encodeInstruction` interacts with `JumpTable`
  metadata.  May need to call back into `JumpTable.encode()` for each
  synth BRANCHIND.
* **Decompiler reaction to "extra pcode at ifcall site"** - the pcode
  block at the ifcall site grows from ~3 ops to ~10-50 ops.  Should be
  fine but verify no slowdown / no truncation.

## Test plan

1. Existing regressions: BasicAsmRegression 17/17, RomRegressionSuite
   20/20, VerifyIFC 31/31, TestEmuIFC 29/29, GenericRomCheck 4/4,
   BodyCorrectnessCheck 0/0.
2. New: `tests/ifc/MeasureLeak.java` baseline:
   * Pre-change: 64 visible leaks / 691 ifcall-functions (spider).
   * Post-change goal: ~0 visible leaks (or close to it) for bodies that
     qualify; rest unaffected.
3. Verify FUN_ram_00000de6 (the example we walked through) renders
   without `in_ifc_lp` assignments or comparisons.
4. Emulator (TestEmuIFC) must still pass - decompile-side inlining is
   for the *decompiler*; the emulator path uses prototype pcode at the
   body's natural address, which we don't change.

## Out of scope for this work

* The `enableContiguousFunctionsOnly` / spurious-function-creation
  issue (`0x008090` example) - reverted; deferred.
* The 0x8000-as-function chicken-and-egg around incorrect symbolic
  propagation at `0x0035152` - separate issue, see
  `[[project_symprop_0035152]]` once that memory is written.
