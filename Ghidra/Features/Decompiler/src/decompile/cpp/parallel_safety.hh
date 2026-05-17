/* ###
 * Path 4: Funcdata thread-safety primitives for parallel applyOp.
 *
 * Background.
 * ===========
 * Path 1 (per-rule canApply) and Path 3 (block-DAG color partition) give us
 * the static metadata and partitioning needed to dispatch scope_op_only and
 * scope_block_local rules in parallel across non-conflicting blocks.  The
 * remaining obstacle is that Funcdata's mutation API is not thread-safe.
 * Path 4 adds the minimum locking machinery to make true parallel applyOp
 * sound on those rules, while leaving the IR-only / serial paths
 * unaffected.
 *
 * Mutation surface audited at Path 4 entry (top30 libc x86_64).
 * =============================================================
 * scope_op_only rules (66 rules / 80% of fires) call only these mutators:
 *
 *   Funcdata::opSetOpcode(op, opc)         -> obank.changeOpcode(op,...)
 *                                          -> globalModCount++
 *   Funcdata::opSetInput(op, vn, slot)     -> Funcdata::newConstant() iff vn is const
 *                                          -> Varnode::eraseDescend(old)
 *                                          -> Varnode::addDescend(new)
 *                                          -> PcodeOp::setInput
 *                                          -> globalModCount++
 *   Funcdata::opSetOutput(op, vn)          -> Funcdata::opUnsetOutput (if changing)
 *                                          -> VarnodeBank::setDef
 *                                          -> setVarnodeProperties
 *                                          -> PcodeOp::setOutput
 *                                          -> globalModCount++
 *   Funcdata::opUnsetInput(op, slot)       -> Varnode::eraseDescend
 *                                          -> PcodeOp::clearInput
 *   Funcdata::opUnsetOutput(op)            -> VarnodeBank::makeFree
 *                                          -> Varnode::clearCover
 *   Funcdata::opSwapInput(op, s1, s2)      -> PcodeOp::setInput x2 (no descend ops)
 *                                          -> globalModCount++
 *   Funcdata::opRemoveInput(op, slot)      -> opUnsetInput + PcodeOp::removeInput
 *   Funcdata::opInsertInput(op, vn, slot)  -> Varnode::addDescend + insertInput
 *   Funcdata::opDestroy(op)                -> opUnsetOutput + opUnsetInput x N
 *                                            + opUninsert (markDead + block->removeOp)
 *   Funcdata::newConstant(s, val)          -> VarnodeBank::create
 *                                          -> bumpVnCreateCount -> bumpIrModCount
 *   Funcdata::newUnique(s, ct)             -> VarnodeBank::createUnique
 *   Funcdata::newOp(inputs, addr)          -> PcodeOpBank::create
 *                                          -> bumpIrModCount
 *
 * Shared mutable state objects.
 * =============================
 *  S1.  Funcdata::obank   (PcodeOpBank)    — alive/dead lists, opcode->op idx, allocator
 *  S2.  Funcdata::vbank   (VarnodeBank)    — def map, location map, allocator
 *  S3.  Funcdata::globalModCount + irModCount + vnCreateCount + typeModCount (uint8)
 *  S4.  Varnode::descend  (std::list<PcodeOp*>)
 *  S5.  Varnode::flags  (uint4)  — coverdirty etc. set via setFlags from descend ops
 *  S6.  BlockBasic::op   (std::list<PcodeOp*>)  — touched by opInsert/opUninsert
 *  S7.  PcodeOp::inputs (vector), output (ptr), code (OpCode), parent (BlockBasic*)
 *
 * Per-thread, single-rule-on-one-op invariant.
 * ============================================
 * In the planned applyBlockParallel phase 2, each worker thread picks an op
 * from its color group's range and runs that op's full rule loop top-to-
 * bottom.  Two threads never operate on the same matched op.  This means
 * S7 (per-PcodeOp fields of the matched op) is owned by the rule's thread
 * for the duration of that op's dispatch — no PcodeOp-level lock needed
 * for the matched op.
 *
 * However, S7 of OTHER ops referenced by a rule (e.g. opSetInput's effect
 * on the input Varnode's other descendants, opSetOutput on a different
 * op, scope_op_output_uses' rewrites of descendant ops) IS shared.  Path 4
 * dispatch policy: only scope_op_only rules go on the parallel path —
 * those by construction touch only their matched op (modulo Varnode
 * descend lists and allocator).  scope_block_local and broader scopes
 * stay on the serial path until a later Path 5.
 *
 * Lock hierarchy (acquired top-to-bottom; never the reverse).
 * ===========================================================
 *   L1.  Funcdata::poolMutex     (recursive_mutex)
 *           — Guards S1 (obank), S2 (vbank), S3 (mod counters), S6 (block op list).
 *           — Recursive: newConstant calls bumpIrModCount which is already inside
 *             a locked region from opSetInput.
 *           — Acquired by every allocation (newConstant/newOp/newVarnode*),
 *             every block-list mutation (opInsert/opUninsert), and every
 *             bumpIrModCount.
 *
 *   L2.  Varnode::descendMutex   (mutex, per-Varnode)
 *           — Guards S4 (this Varnode's descend list) and S5 setFlags called
 *             by addDescend/eraseDescend.
 *           — Acquired only for addDescend / eraseDescend.  Never held across
 *             other Funcdata calls.
 *           — Order rule: a thread may hold poolMutex AND a single
 *             descendMutex simultaneously, but NEVER two descendMutexes.
 *             opSetInput releases the old Varnode's mutex before acquiring
 *             the new Varnode's mutex.
 *
 *   L2u. Funcdata::unionMutex     (recursive_mutex, per-Funcdata)
 *           — Guards the unionMap (TypeUnion field-resolution cache).
 *           — Acquired by getUnionField / getUnionResolution /
 *             getAddressBasedUnionField / setUnionField /
 *             setAddressBasedUnionField / updateUnionField /
 *             forceFacingType / inheritUnionField / inheritUnionFieldPtr.
 *           — Also acquired transitively by Datatype::findResolve when
 *             called via Varnode::getTypeReadFacing on union-typed varnodes
 *             (TypePointer::findResolve, TypeUnion::findResolve, etc.).
 *           — Sibling of poolMutex (L1); acquired alone, never nested
 *             under poolMutex.  Recursive so forceFacingType /
 *             inheritUnionField (which delegate to setUnionField) don't
 *             self-deadlock.
 *
 *   L3.  globalModCount + irModCount + vnCreateCount + typeModCount → std::atomic<uint8>
 *           — bumpIrModCount / bumpGlobalModCount / bumpVnCreateCount /
 *             bumpTypeModCount become relaxed atomic fetch_add.  This makes
 *             the counters free to update without the pool mutex.  It also
 *             means ActionPool::lastSeenModCount comparisons are read-correct
 *             even mid-mutation; the counters are monotonically non-decreasing.
 *
 * What we deliberately do NOT lock (yet).
 * =======================================
 *   - PcodeOp's per-op state (inputs/output/code/parent): single-owner per
 *     thread per dispatch invocation (see above).
 *   - HighVariable, Datatype, Symbol*: these are touched by Funcdata-level
 *     analyses that run serially before/after ActionPool; ActionPool itself
 *     (the parallel-mode target) does not mutate them on scope_op_only
 *     paths.
 *   - Backward iterator stability of Varnode::descend: only the owner of
 *     the descend list mutex may insert or erase; readers
 *     (beginDescend/endDescend during canApply phase) are reading a
 *     snapshot from phase 1, so they don't race with phase 2 writers
 *     because phase 2 is the only writer at any time.
 *
 * Performance expectations.
 * =========================
 * With W=4 and avg 4.1 colors/function, the theoretical scope_op_only
 * parallel ceiling is ~3× on the 80% of rule-fire work that is scope_op_only.
 * Lock contention on hot Varnodes (constants, spacebase) and on poolMutex
 * (allocator) is expected to cut this to 1.5-2.0× on real workloads.
 * The blocklist (Path 3) already strips 97% of cold-path canApply work, so
 * the parallel pass operates on a dense, already-filtered set of (op, rule)
 * pairs.
 *
 * Roll-out gate.
 * ==============
 * The locks are compiled in unconditionally (cost: one extra word per
 * Varnode for the mutex; one shared recursive_mutex on Funcdata).  Lock
 * acquisitions in the hot path (opSetInput) cost a few hundred cycles
 * each when uncontended.  The serial path (DECOMP_INTRA_WORKERS<=1)
 * pays this cost but it is dominated by the rest of applyOp work
 * (rule logic, type checks, etc.); measured overhead expected <2%.
 *
 * Build order across batches.
 * ===========================
 *   P4-1 (this header)        Audit & design.
 *   P4-2 add poolMutex         Funcdata::poolMutex; wrap allocators + mod counters.
 *   P4-3 add descendMutex      Per-Varnode mutex on addDescend/eraseDescend.
 *   P4-4 wrap PcodeOp helpers  opSetInput/Output/Opcode/Swap honor the locks.
 *   P4-5 wire parallel dispatch  applyBlockParallel phase 2 uses ThreadPool to
 *                              run scope_op_only rules across color groups.
 *                              Adds L2u unionMutex and L3 atomic mod-counters.
 *                              Gated by DECOMP_INTRA_TRUE_PARALLEL=1.
 *   P4-6 validate + bench      Datatests 664/668 across all modes; perf sweep.
 *
 * Known limitations of P4-5 (TRUE_PARALLEL=1).
 * ============================================
 *   - Non-deterministic union-field resolution order across workers can
 *     pick different valid fields for ambiguous union accesses, producing
 *     equivalent-but-different decompiler output.  Manifests on Union #8,
 *     Union #10 of the datatests suite (and intermittently Inlining #4).
 *     Mitigation paths considered for follow-up: (a) order-independent
 *     union scoring (deterministic tiebreaker on edge identity); (b) gate
 *     phase 2a per-color sequentially when union types are observed in
 *     the function; (c) restrict phase 2a to rules with provably no
 *     type-resolution side effects (stricter scope_op_only annotation).
 */
#ifndef __GHIDRA_PARALLEL_SAFETY_HH__
#define __GHIDRA_PARALLEL_SAFETY_HH__

#include <mutex>
#include <atomic>

namespace ghidra {

// Forward placeholders.  Real declarations land in P4-2/P4-3.
//   class PoolMutex;        // wrapper over std::recursive_mutex, owned by Funcdata
//   class DescendMutex;     // owned by each Varnode

} // namespace ghidra

#endif
