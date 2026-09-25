/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.plugin.core.analysis;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Publishes per-caller body extensions and branch-back maps so the
 * decompiler can render IFC as inlined flow.  Sleigh emits {@code ifcall}
 * as {@code goto T} and {@code ifret} as {@code goto [ifc_lp]}; the
 * pcode walker follows those, but the decompiler still treats T's
 * addresses as belonging to T (a separate function), not to its caller.
 * The maps below let {@link DecompileCallback} reclassify addresses
 * per-caller and emit per-flow synthetic pcode.
 * <ul>
 * <li>{@code FunctionBodyExt:&lt;entry&gt;} - addresses in T that are
 *     part of F's flow when decompiling F.
 * <li>{@code Branchback:&lt;entry&gt;} - ifret/tail-call address to
 *     caller-inst-next when only one caller-next is observed for that
 *     ifret.
 * <li>{@code MultiBranchback:&lt;entry&gt;} - comma-separated hex list
 *     of caller-inst-nexts when multiple callers share the ifret.
 * <li>{@code InlineCall:&lt;entry&gt;} - for ifcalls whose body is a
 *     single tail-call that lives in the caller's primary body; lets
 *     the decompiler render the IFC call inline at the ifcall site
 *     instead of via a 2-iteration loop through the shared body.
 * <li>{@code InlineBody:&lt;entry&gt;} - ifcall address to body-entry
 *     for fully-inlineable bodies; the decompiler emits the body's
 *     prototype pcode in place of the ifcall.
 * </ul>
 * Also seeds {@code IFC_ON = 1} at entries of functions whose visible
 * callers are all {@code ifcall*}, so standalone decompile of those
 * functions folds the runtime conditional in {@code ifret} pcode.
 */
public class NDS32IFCAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "NDS32 IFC Fixups";
	private static final String DESCRIPTION =
		"Publishes per-caller body extensions to recover multi-flow IFC semantics " +
			"at decompile time; seeds IFC_ON = 1 context where it matters.";
	private static final String PROCESSOR_NAME = "NDS32";

	private static final String EXT_MAP_PREFIX = "FunctionBodyExt:";
	private static final String IFRET_TARGET_MAP_PREFIX = "Branchback:";
	private static final String IFRET_MULTI_MAP_PREFIX = "MultiBranchback:";
	private static final String INLINE_CALL_MAP_PREFIX = "InlineCall:";
	private static final String INLINE_BODY_MAP_PREFIX = "InlineBody:";

	// Bodies with more than this many instructions stay as dispatch (the
	// inline pcode would balloon the synth and the dispatch shape is fine
	// for larger bodies anyway).  Bumped to 600 to cover the very large
	// multi-path bodies that appear in real firmware (some mt7663 bodies
	// are 400-500 insns).
	private static final int INLINE_BODY_MAX_INSNS = 600;

	public NDS32IFCAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setDefaultEnablement(true);
		setPriority(AnalysisPriority.LOW_PRIORITY);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor(PROCESSOR_NAME));
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// no options yet
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Register runIfcOn = program.getLanguage().getRegister("IFC_ON");
		if (runIfcOn == null) {
			return false;
		}
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		FunctionManager fm = program.getFunctionManager();
		ProgramContext pc = program.getProgramContext();
		RegisterValue runOne = new RegisterValue(runIfcOn, BigInteger.ONE);

		int totalFns = 0;
		int callersWithIfcall = 0;
		int extendedFunctions = 0;
		int seededContext = 0;
		int addedFallthroughs = 0;
		int ifretTargets = 0;
		// Body-entry -> set of caller function names, accumulated across
		// the per-function loop for the body-entry repeatable comment.
		Map<Address, LinkedHashSet<String>> ifcBodyCallers = new HashMap<>();

		// Safety net for projects whose ifcalls were disassembled before
		// the current sleigh started recording a natural fall-through.
		// applyTo() can invalidate the live iterator, so collect missing
		// targets first and disassemble after the loop.
		AddressSetView iterRange = (set != null && !set.isEmpty()) ? set : null;
		Iterable<Instruction> iter = iterRange != null
				? listing.getInstructions(iterRange, true)
				: listing.getInstructions(true);
		List<Address> needDisasm = null;
		for (Instruction insn : iter) {
			monitor.checkCancelled();
			String mn = insn.getMnemonicString();
			if (!mn.equals("ifcall") && !mn.equals("ifcall9")) continue;
			if (insn.getFallThrough() != null) continue;
			Address fall = insn.getMaxAddress().next();
			if (fall == null) continue;
			insn.setFallThrough(fall);
			addedFallthroughs++;
			if (listing.getInstructionAt(fall) == null) {
				if (needDisasm == null) needDisasm = new ArrayList<>();
				needDisasm.add(fall);
			}
		}
		if (needDisasm != null) {
			for (Address fall : needDisasm) {
				monitor.checkCancelled();
				if (listing.getInstructionAt(fall) == null) {
					new DisassembleCommand(fall, null, true).applyTo(program, monitor);
				}
			}
		}

		// Per-function loop.  For incremental re-analysis we restrict to
		// functions intersecting `set`; initial import passes the whole
		// program.
		Iterable<Function> fns;
		if (set != null && !set.isEmpty()) {
			fns = fm.getFunctions(set, true);
		}
		else {
			fns = fm.getFunctions(true);
		}
		for (Function f : fns) {
			monitor.checkCancelled();
			totalFns++;
			AddressSetView fbody = f.getBody();
			if (fbody == null || fbody.isEmpty()) continue;

			// Walk each ifcall in F: accumulate the reachable body into
			// `extension`, and record per-ifret(or tail-call) the set of
			// caller-inst-nexts.  Two ifcalls in F targeting the same body
			// will reach the same exit instruction with different caller-
			// nexts. split below into single vs multi-target maps.  An
			// ifcall whose body is a single unconditional CALL that also
			// lives in F's primary body is special-cased into the inline-
			// call map: the body is reachable both via the ifcall and via
			// natural fall-through, so rendering it as a shared synth at
			// the body's address would produce a 2-iteration loop.
			AddressSet extension = new AddressSet();
			Map<Address, LinkedHashSet<Address>> ifretTargetsMulti = new HashMap<>();
			Map<Address, Address> inlineCallMap = new HashMap<>();
			Map<Address, Address> inlineBodyMap = new HashMap<>();
			// Body addresses reached by an inlined ifcall, so we can apply
			// the ifret fall-through cleanup even when the body never goes
			// into F's extension.
			AddressSet inlineBodyAddrs = new AddressSet();
			boolean hasIfcalls = false;
			for (Instruction insn : listing.getInstructions(fbody, true)) {
				monitor.checkCancelled();
				String mn = insn.getMnemonicString();
				if (!mn.equals("ifcall") && !mn.equals("ifcall9")) continue;
				hasIfcalls = true;
				Address tgt = ifcTarget(insn);
				if (tgt == null) continue;
				// Some IFC targets aren't disassembled by the default
				// analysis (loader didn't pre-scan or the ifcall reference
				// type didn't trigger discovery).  Force disassembly so
				// the walker can reach the body.
				if (listing.getInstructionAt(tgt) == null) {
					new DisassembleCommand(tgt, null, true).applyTo(program, monitor);
				}
				Address callerNext = insn.getMaxAddress().next();
				Address inlineX = inlineTailCallTarget(listing, tgt);
				if (inlineX != null) {
					inlineCallMap.put(insn.getAddress(), inlineX);
					ifcBodyCallers.computeIfAbsent(tgt, k -> new LinkedHashSet<>())
							.add(f.getName());
					continue;
				}
				// Try the multi-instruction inline-body shape: linear body
				// ending in ifret/ifret16.  Each ifcall site gets its own
				// copy of the body's pcode, so multi-caller dispatch through
				// ifc_lp disappears from decompile output.
				if (qualifiesForInlineBody(listing, tgt, inlineBodyAddrs)) {
					inlineBodyMap.put(insn.getAddress(), tgt);
					ifcBodyCallers.computeIfAbsent(tgt, k -> new LinkedHashSet<>())
							.add(f.getName());
					continue;
				}
				accumulateReachableBody(listing, tgt, extension, ifretTargetsMulti,
					callerNext, fbody, monitor);
				ifcBodyCallers.computeIfAbsent(tgt, k -> new LinkedHashSet<>())
						.add(f.getName());
			}
			Map<Address, Address> ifretTargetMap = new HashMap<>();
			Map<Address, LinkedHashSet<Address>> ifretMultiMap = new HashMap<>();
			for (var e : ifretTargetsMulti.entrySet()) {
				LinkedHashSet<Address> targets = e.getValue();
				if (targets.size() == 1) {
					ifretTargetMap.put(e.getKey(), targets.iterator().next());
				}
				else {
					ifretMultiMap.put(e.getKey(), targets);
				}
			}
			if (hasIfcalls) callersWithIfcall++;

			String mapName = EXT_MAP_PREFIX +
				Long.toHexString(f.getEntryPoint().getOffset());
			AddressSetPropertyMap existing = program.getAddressSetPropertyMap(mapName);
			if (!extension.isEmpty()) {
				try {
					if (existing == null) {
						existing = program.createAddressSetPropertyMap(mapName);
					}
					existing.set(extension);
					extendedFunctions++;
				}
				catch (DuplicateNameException e) {
					Msg.warn(this, "couldn't create ext map " + mapName + ": " + e.getMessage());
				}
			}
			else if (existing != null) {
				existing.clear();
			}

			// For ifrets in isolated bodies (whose fall-through is
			// filler), clear the fall-through and apply a RETURN
			// override so the standalone decompile of the body
			// renders cleanly.  For ifrets in shared bodies (where
			// the fall-through is live code in some function) leave
			// the natural fall-through alone. otherwise we'd orphan
			// the post-ifret block in the outer caller's flow.
			// Apply across both the dispatch extension and the
			// inline-body footprint - the cleanup is per-instruction
			// regardless of which path renders the body.
			AddressSet ifretCleanup = new AddressSet();
			ifretCleanup.add(extension);
			ifretCleanup.add(inlineBodyAddrs);
			if (!ifretCleanup.isEmpty()) {
				for (Instruction in : listing.getInstructions(ifretCleanup, true)) {
					monitor.checkCancelled();
					String inMn = in.getMnemonicString();
					if (!inMn.equals("ifret") && !inMn.equals("ifret16")) {
						continue;
					}
					Address fall = in.getFallThrough();
					if (fall != null && !isLiveCodeInSomeFunction(listing, fm, fall)) {
						in.setFallThrough(null);
						if (in.getFlowOverride() != FlowOverride.RETURN) {
							in.setFlowOverride(FlowOverride.RETURN);
						}
					}
				}
			}

			// Persist the per-caller ifret-target map.  DecompileCallback
			// looks up each ifret instance address here and emits a
			// synthetic BRANCH to the recorded target in place of the
			// prototype's BRANCHIND-via-ifc_lp.
			String ifretMapName = IFRET_TARGET_MAP_PREFIX +
				Long.toHexString(f.getEntryPoint().getOffset());
			PropertyMapManager pmm = program.getUsrPropertyManager();
			LongPropertyMap targetMap = pmm.getLongPropertyMap(ifretMapName);
			if (!ifretTargetMap.isEmpty()) {
				if (targetMap == null) {
					try {
						targetMap = pmm.createLongPropertyMap(ifretMapName);
					}
					catch (DuplicateNameException e) {
						Msg.warn(this, "couldn't create ifret-target map " +
							ifretMapName + ": " + e.getMessage());
						targetMap = null;
					}
				}
				if (targetMap != null) {
					// Clear stale entries (entries no longer in computed map).
					Set<Address> wanted = ifretTargetMap.keySet();
					AddressIterator existingIt =
						targetMap.getPropertyIterator();
					List<Address> toRemove = new ArrayList<>();
					while (existingIt.hasNext()) {
						Address a = existingIt.next();
						if (!wanted.contains(a)) toRemove.add(a);
					}
					for (Address a : toRemove) targetMap.remove(a);
					// Write fresh entries.
					for (var e : ifretTargetMap.entrySet()) {
						targetMap.add(e.getKey(), e.getValue().getOffset());
						ifretTargets++;
					}
				}
			}
			else if (targetMap != null) {
				// No ifrets reachable now; clear any stale map.
				AddressIterator existingIt =
					targetMap.getPropertyIterator();
				List<Address> toRemove = new ArrayList<>();
				while (existingIt.hasNext()) toRemove.add(existingIt.next());
				for (Address a : toRemove) targetMap.remove(a);
			}

			// Persist the multi-target map as comma-separated hex offsets.
			// DecompileCallback synthesizes a linear-CBRANCH switch from
			// the list at each multi-target ifret address.
			String multiMapName = IFRET_MULTI_MAP_PREFIX +
				Long.toHexString(f.getEntryPoint().getOffset());
			StringPropertyMap multiMap =
				pmm.getStringPropertyMap(multiMapName);
			if (!ifretMultiMap.isEmpty()) {
				if (multiMap == null) {
					try {
						multiMap = pmm.createStringPropertyMap(multiMapName);
					}
					catch (DuplicateNameException e) {
						Msg.warn(this, "couldn't create multi-target map " +
							multiMapName + ": " + e.getMessage());
						multiMap = null;
					}
				}
				if (multiMap != null) {
					Set<Address> wanted = ifretMultiMap.keySet();
					AddressIterator existingIt =
						multiMap.getPropertyIterator();
					List<Address> toRemove = new ArrayList<>();
					while (existingIt.hasNext()) {
						Address a = existingIt.next();
						if (!wanted.contains(a)) toRemove.add(a);
					}
					for (Address a : toRemove) multiMap.remove(a);
					for (var e : ifretMultiMap.entrySet()) {
						StringBuilder sb = new StringBuilder();
						for (Address t : e.getValue()) {
							if (sb.length() > 0) sb.append(",");
							sb.append(Long.toHexString(t.getOffset()));
						}
						multiMap.add(e.getKey(), sb.toString());
					}
				}
			}
			else if (multiMap != null) {
				AddressIterator existingIt =
					multiMap.getPropertyIterator();
				List<Address> toRemove = new ArrayList<>();
				while (existingIt.hasNext()) toRemove.add(existingIt.next());
				for (Address a : toRemove) multiMap.remove(a);
			}

			// Persist the inline-call map (ifcall-addr -> tail-call target).
			String inlineMapName = INLINE_CALL_MAP_PREFIX +
				Long.toHexString(f.getEntryPoint().getOffset());
			LongPropertyMap inlineMap = pmm.getLongPropertyMap(inlineMapName);
			if (!inlineCallMap.isEmpty()) {
				if (inlineMap == null) {
					try {
						inlineMap = pmm.createLongPropertyMap(inlineMapName);
					}
					catch (DuplicateNameException e) {
						Msg.warn(this, "couldn't create inline-call map " +
							inlineMapName + ": " + e.getMessage());
						inlineMap = null;
					}
				}
				if (inlineMap != null) {
					Set<Address> wanted = inlineCallMap.keySet();
					AddressIterator existingIt =
						inlineMap.getPropertyIterator();
					List<Address> toRemove = new ArrayList<>();
					while (existingIt.hasNext()) {
						Address a = existingIt.next();
						if (!wanted.contains(a)) toRemove.add(a);
					}
					for (Address a : toRemove) inlineMap.remove(a);
					for (var e : inlineCallMap.entrySet()) {
						inlineMap.add(e.getKey(), e.getValue().getOffset());
					}
				}
			}
			else if (inlineMap != null) {
				AddressIterator existingIt =
					inlineMap.getPropertyIterator();
				List<Address> toRemove = new ArrayList<>();
				while (existingIt.hasNext()) toRemove.add(existingIt.next());
				for (Address a : toRemove) inlineMap.remove(a);
			}

			// Persist the inline-body map (ifcall-addr -> body entry).
			// DecompileCallback walks from the body entry at decompile time,
			// emitting the body's prototype pcode inline and replacing the
			// terminal ifret with a BRANCH to the ifcall's fall-through.
			String inlineBodyMapName = INLINE_BODY_MAP_PREFIX +
				Long.toHexString(f.getEntryPoint().getOffset());
			LongPropertyMap inlineBodyPm = pmm.getLongPropertyMap(inlineBodyMapName);
			if (!inlineBodyMap.isEmpty()) {
				if (inlineBodyPm == null) {
					try {
						inlineBodyPm = pmm.createLongPropertyMap(inlineBodyMapName);
					}
					catch (DuplicateNameException e) {
						Msg.warn(this, "couldn't create inline-body map " +
							inlineBodyMapName + ": " + e.getMessage());
						inlineBodyPm = null;
					}
				}
				if (inlineBodyPm != null) {
					Set<Address> wanted = inlineBodyMap.keySet();
					AddressIterator existingIt =
						inlineBodyPm.getPropertyIterator();
					List<Address> toRemove = new ArrayList<>();
					while (existingIt.hasNext()) {
						Address a = existingIt.next();
						if (!wanted.contains(a)) toRemove.add(a);
					}
					for (Address a : toRemove) inlineBodyPm.remove(a);
					for (var e : inlineBodyMap.entrySet()) {
						inlineBodyPm.add(e.getKey(), e.getValue().getOffset());
					}
				}
			}
			else if (inlineBodyPm != null) {
				AddressIterator existingIt =
					inlineBodyPm.getPropertyIterator();
				List<Address> toRemove = new ArrayList<>();
				while (existingIt.hasNext()) toRemove.add(existingIt.next());
				for (Address a : toRemove) inlineBodyPm.remove(a);
			}

			// Add explicit COMPUTED_JUMP cross-references at every
			// ifret/tail-call exit in F's body extension.  Without these
			// the listing shows only one outgoing edge (whichever caller-
			// next the const-prop happened to compute first); with them
			// the user sees every caller-next this exit may transfer to.
			for (var entry : ifretTargetMap.entrySet()) {
				Address exitAddr = entry.getKey();
				Address branchBack = entry.getValue();
				addMultiFlowReturnRef(refMgr, listing, exitAddr, branchBack);
			}
			for (var entry : ifretMultiMap.entrySet()) {
				Address exitAddr = entry.getKey();
				for (Address branchBack : entry.getValue()) {
					addMultiFlowReturnRef(refMgr, listing, exitAddr, branchBack);
				}
			}

			// Functions reached only via ifcall* get IFC_ON = 1 as entry
			// context plus the "ifc_call" calling convention, so their
			// standalone-decompile renders the ifret BRANCHIND-via-ifc_lp
			// as a function return rather than an indirect-call jumptable.
			if (hasOnlyIfcallEntry(refMgr, listing, f)) {
				Address entry = f.getEntryPoint();
				RegisterValue existingCtx = pc.getRegisterValue(runIfcOn, entry);
				if (existingCtx == null || !existingCtx.hasValue()
						|| !BigInteger.ONE.equals(existingCtx.getUnsignedValue())) {
					try {
						pc.setRegisterValue(entry, entry, runOne);
						seededContext++;
					}
					catch (ContextChangeException e) {
						Msg.warn(this, "couldn't seed IFC_ON @ " + entry + ": " +
							e.getMessage());
					}
				}
				if (!"ifc_call".equals(f.getCallingConventionName())) {
					try {
						f.setCallingConvention("ifc_call");
					}
					catch (InvalidInputException e) {
						Msg.warn(this, "couldn't set ifc_call convention on " + f.getName() +
							": " + e.getMessage());
					}
				}
			}
		}
		// Annotate each IFC body entry with a "ifcalled from: F, G, H"
		// repeatable comment.  Overwritten on each run so stale callers
		// from earlier states don't accumulate.
		int annotatedBodies = 0;
		for (var e : ifcBodyCallers.entrySet()) {
			Address bodyEntry = e.getKey();
			List<String> callers = new ArrayList<>(e.getValue());
			Collections.sort(callers);
			StringBuilder sb = new StringBuilder("IFC body. ifcalled from: ");
			int max = 8;
			for (int i = 0; i < Math.min(max, callers.size()); i++) {
				if (i > 0) sb.append(", ");
				sb.append(callers.get(i));
			}
			if (callers.size() > max) sb.append(", ... (").append(callers.size()).append(" total)");
			listing.setComment(bodyEntry,
				CodeUnit.REPEATABLE_COMMENT, sb.toString());
			annotatedBodies++;
		}

		Msg.info(this, String.format(
			"Added %d fallthroughs to ifcall*; iterated %d functions; %d have ifcalls; published extensions for %d; seeded %d; ifret targets %d; annotated %d IFC body entries",
			addedFallthroughs, totalFns, callersWithIfcall, extendedFunctions, seededContext,
			ifretTargets, annotatedBodies));
		return true;
	}

	/**
	 * Return the jump/call target of an {@code ifcall}/{@code ifcall9}
	 * instruction, or {@code null} if none is recorded.
	 */
	private static Address ifcTarget(Instruction insn) {
		for (Reference r : insn.getReferencesFrom()) {
			RefType rt = r.getReferenceType();
			if (rt.isJump() || rt.isCall()) {
				return r.getToAddress();
			}
		}
		return null;
	}

	/**
	 * Check whether the IFC body at {@code tgt} is shaped suitably for
	 * pcode-level inlining at each of its ifcall sites.  When this
	 * returns true the caller writes an {@link #INLINE_BODY_MAP_PREFIX}
	 * entry; the decompiler's {@code emitInlineBody} then emits the
	 * body's pcode inline at the ifcall site, replacing the multi-caller
	 * dispatch synth (which would otherwise surface as
	 * {@code in_ifc_lp == ...} clutter in decompile output).
	 *
	 * <p>The body qualifies if every reachable instruction is either a
	 * non-branching body insn, an intra-body branch (whose target is
	 * also reachable), or one of the supported terminator shapes:
	 * <ul>
	 * <li>{@code ifret}/{@code ifret16} - return to {@code ifc_lp}.</li>
	 * <li>Unconditional CALL ({@code jal X}, {@code jral5 Rt}, or
	 *     {@code ex9.it}-&gt;CALL): tail-call via set_link_gpr (callee
	 *     returns to outer caller_next).</li>
	 * <li>Nested {@code ifcall*}: in IFC mode this is a plain jump,
	 *     and the nested body's own terminator returns to outer
	 *     caller_next via the unchanged ifc_lp - effectively a
	 *     tail-call from the outer body's view.</li>
	 * <li>{@code ex9.it}-&gt;JUMP X: branch clears ifc_on, transferring
	 *     control to X in non-IFC mode.</li>
	 * <li>Bare TERMINAL-not-call ({@code pop25}/{@code ret}/{@code jr}):
	 *     exits F via the stack-restored lp.</li>
	 * </ul>
	 *
	 * <p>Body addresses are appended to {@code inlineBodyAddrs} when
	 * the check succeeds so the per-function ifret cleanup pass can
	 * find them even though they never enter F's extension map.
	 *
	 * <p>Rejects bodies that exceed {@link #INLINE_BODY_MAX_INSNS}
	 * reachable insns, have unresolved indirect jumps, or contain
	 * conditional CALL instructions (we'd need to model both the call
	 * and the fall-through path, which we don't).
	 */
	private static boolean qualifiesForInlineBody(Listing listing, Address tgt,
			AddressSet inlineBodyAddrs) {
		if (tgt == null) return false;
		LinkedHashSet<Address> reachable = new LinkedHashSet<>();
		ArrayDeque<Address> work = new ArrayDeque<>();
		work.add(tgt);
		boolean anyTerminator = false;
		while (!work.isEmpty()) {
			if (reachable.size() >= INLINE_BODY_MAX_INSNS) return false;
			Address cur = work.poll();
			if (!reachable.add(cur)) continue;
			Instruction in = listing.getInstructionAt(cur);
			if (in == null) return false;
			Outcome o = classifyForInline(in);
			if (o == Outcome.REJECT) return false;
			if (o == Outcome.TERMINATOR) {
				anyTerminator = true;
				continue;
			}
			// SUCCESSORS: add the instruction's successors and walk on.
			FlowType ft = in.getFlowType();
			if (ft != null && ft.isJump()) {
				for (Reference r : in.getReferencesFrom()) {
					if (r.getReferenceType().isJump()) work.add(r.getToAddress());
				}
				if (ft.isConditional()) {
					Address fall = in.getFallThrough();
					if (fall != null) work.add(fall);
				}
				continue;
			}
			Address fall = in.getFallThrough();
			if (fall == null) return false;
			work.add(fall);
		}
		if (!anyTerminator) return false;
		for (Address a : reachable) {
			Instruction bi = listing.getInstructionAt(a);
			if (bi != null) inlineBodyAddrs.addRange(bi.getMinAddress(), bi.getMaxAddress());
		}
		return true;
	}

	/** Per-instruction outcome for {@link #qualifiesForInlineBody}. */
	private enum Outcome { TERMINATOR, SUCCESSORS, REJECT }

	/**
	 * Classify a body instruction.  Mirrors the kind detection in
	 * {@code DecompileCallback.emitInlineBody}; both must agree on
	 * which shapes are inlineable.  Returns {@code REJECT} for shapes
	 * the emitter can't model (missing call ref on a tail-call,
	 * conditional CALL).
	 */
	private static Outcome classifyForInline(Instruction in) {
		String mn = in.getMnemonicString();
		if (mn.equals("ifret") || mn.equals("ifret16")) return Outcome.TERMINATOR;
		if (mn.equals("ifcall") || mn.equals("ifcall9")) {
			return hasJumpOrCallRef(in) ? Outcome.TERMINATOR : Outcome.REJECT;
		}
		if (mn.equals("ex9.it") || mn.equals("ex9.it5")) {
			for (Reference r : in.getReferencesFrom()) {
				RefType rt = r.getReferenceType();
				if (rt.isCall() || rt.isJump()) return Outcome.TERMINATOR;
			}
			// No call/jump ref: ex9.it is a pure side-effect insn.
		}
		FlowType ft = in.getFlowType();
		if (ft != null && ft.isCall() && !ft.isConditional()) {
			if (ft.isComputed()) return Outcome.TERMINATOR; // jral5, CALLIND
			return hasCallRef(in) ? Outcome.TERMINATOR : Outcome.REJECT;
		}
		// Conditional CALL (jralnez etc.) is treated as a normal
		// fall-through here.  Its taken-path tail-call semantic isn't
		// modeled, but the dispatch synth at the body's other
		// terminators still handles the body's overall continuation.
		if (ft != null && ft.isTerminal()) return Outcome.TERMINATOR;
		return Outcome.SUCCESSORS;
	}

	private static boolean hasJumpOrCallRef(Instruction in) {
		for (Reference r : in.getReferencesFrom()) {
			RefType rt = r.getReferenceType();
			if (rt.isJump() || rt.isCall()) return true;
		}
		return false;
	}

	private static boolean hasCallRef(Instruction in) {
		for (Reference r : in.getReferencesFrom()) {
			if (r.getReferenceType().isCall()) return true;
		}
		return false;
	}

	private static Address inlineTailCallTarget(Listing listing, Address tgt) {
		Instruction tgtInsn = listing.getInstructionAt(tgt);
		if (tgtInsn == null) {
			return null;
		}
		FlowType ft = tgtInsn.getFlowType();
		if (ft == null || !ft.isCall() || ft.isConditional()) {
			return null;
		}
		for (Reference r : tgtInsn.getReferencesFrom()) {
			if (r.getReferenceType().isCall()) {
				return r.getToAddress();
			}
		}
		return null;
	}

	private void accumulateReachableBody(Listing listing, Address start, AddressSet into,
			Map<Address, LinkedHashSet<Address>> ifretTargetsMulti,
			Address instructionAfterIfcall,
			AddressSetView exclude, TaskMonitor monitor) throws CancelledException {
		Deque<Address> work = new ArrayDeque<>();
		Set<Address> seen = new HashSet<>();
		work.add(start);
		while (!work.isEmpty()) {
			Address cur = work.poll();
			if (!seen.add(cur)) continue;
			// `exclude` (caller F's primary body) is no longer checked.
			// When the initial disassembly followed the ifcall's BRANCH
			// edge into the IFC body, those bytes ended up in F's
			// primary body. but they're still legitimately ifcalled
			// code that we need to walk (to record ifret targets).
			Instruction insn = listing.getInstructionAt(cur);
			if (insn == null) continue;
			Address insnEnd = insn.getMaxAddress();
			into.addRange(cur, insnEnd);
			String mn = insn.getMnemonicString();
			// Record control-flow-back-to-caller points: instructions
			// that, when reached in IFC mode, transfer control to the
			// caller's instruction-after-ifcall.  Only two shapes do
			// this reliably:
			//   - ifret/ifret16: explicit `goto [ifc_lp]`.
			//   - Unconditional calls (jal/jral/etc.): in IFC mode the
			//     analyzer's set_link_gpr stores lp = ifc_lp, so the
			//     tail-callee returns to ifc_lp = caller-inst-next.
			// Bare terminators (pop25/ret/jr) do NOT necessarily go to
			// ifc_lp: pop25 reloads lp from the stack (always F's caller's
			// return), and bare `ret lp` returns wherever lp was last
			// stored (typically F's original lp unless a jal/jral in the
			// same body explicitly set lp = ifc_lp).  Treating them as
			// branch-backs creates a spurious dispatch synth that doesn't
			// match runtime behavior; leave them to the natural pcode +
			// TERMINATOR flow which renders cleanly as F-exit.
			FlowType ftHere = insn.getFlowType();
			boolean isIfret = mn.equals("ifret") || mn.equals("ifret16");
			// ex9.it (and ex9.it5) substitute an instruction from the
			// IT-table at runtime, but its FlowType remains FALL_THROUGH
			// because sleigh sees only the {@code ex9(imm)} CALLOTHER.
			// NDS32ITBAnalyzer attaches proper outgoing call/jump refs to
			// the ex9.it site instead.  We pick those up here to recover
			// the effective flow shape.
			boolean ex9SiteIsCall = false;
			boolean ex9SiteIsJump = false;
			if (mn.equals("ex9.it")) {
				for (Reference r : insn.getReferencesFrom()) {
					RefType rt = r.getReferenceType();
					if (rt.isCall()) ex9SiteIsCall = true;
					if (rt.isJump()) ex9SiteIsJump = true;
				}
			}
			boolean isTailCall = (ftHere != null && ftHere.isCall()
					&& !ftHere.isConditional())
					|| ex9SiteIsCall;
			if ((isIfret || isTailCall)
					&& instructionAfterIfcall != null) {
				// Record all distinct branch-back targets observed for
				// this ifret/tail-call instance across the per-ifcall
				// walks in the caller function.  Stored in
				// insertion-order so the resulting switch pcode is
				// deterministic.
				ifretTargetsMulti.computeIfAbsent(cur, k -> new LinkedHashSet<>())
					.add(instructionAfterIfcall);
			}
			FlowType ft = insn.getFlowType();
			if (ft == null) continue;
			// Follow fall-through. but NOT for instructions whose
			// fallthrough doesn't represent continuation within the IFC
			// body:
			//   - unconditional calls (jal, jral, etc.) in IFC mode are
			//     tail-calls (lp = ifc_lp); the callee returns to ifc_lp
			//     in the outer caller, NOT to inst_next of the call.
			//     Following fallthrough would walk past the body into
			//     unrelated code (often the next function or filler).
			//   - ifret/ifret16: returns to ifc_lp.  inst_next isn't in
			//     the body either.
			//   - jr/ret: out-of-IFC branches.
			// Conditional calls (bgezal, bltzal) keep fall-through (the
			// not-taken path continues in the IFC body).
			boolean suppressFallthrough =
				(ft.isCall() && !ft.isConditional())
				|| isIfret
				|| ex9SiteIsCall;
			Address fall = insn.getFallThrough();
			if (fall != null && !suppressFallthrough) work.add(fall);
			// Follow JUMP targets but NOT call targets: a CALL inside
			// an IFC body (e.g. a `jal far` inside a thunk, or a normal
			// `jal` inside a longer IFC body) leaves the body and
			// transfers to an external function.  At runtime the
			// callee returns via lp (which is ifc_lp in IFC mode), so
			// the *effect* in the caller's view is a tail-call that
			// continues at the caller's instruction-after-ifcall.  The
			// CALL target itself is NOT inlined.
			//
			// For ifcall instructions specifically, we want to follow
			// them because their pcode is `goto T` (a JUMP), so they
			// fall under `ft.isJump()` and are handled by the loop
			// below.
			//
			// For ifret/ifret16: don't follow outgoing jump references
			// either.  ifret's computed-jump target (CONDITIONAL_COMPUTED_JUMP
			// to ifc_lp) IS the branch-back exit out of the IFC body -
			// the caller's instruction-after-ifcall. which we don't want
			// to inline into the IFC body's extension.
			if ((ft.isJump() || ex9SiteIsJump) && !isIfret) {
				for (Reference r : insn.getReferencesFrom()) {
					if (r.getReferenceType().isJump()) {
						work.add(r.getToAddress());
					}
				}
			}
			monitor.checkCancelled();
		}
	}

	/**
	 * Return true if {@code addr} is currently a disassembled
	 * instruction that belongs to some function's primary body.  Used
	 * by the ifret fallthrough-clearing heuristic to distinguish
	 * shared-body ifrets (whose fallthrough is real code in the
	 * containing function) from isolated-IFC-body ifrets (whose
	 * fallthrough is filler/data).
	 */
	private static boolean isLiveCodeInSomeFunction(Listing listing,
			FunctionManager fm, Address addr) {
		if (addr == null) return false;
		if (listing.getInstructionAt(addr) == null) return false;
		return fm.getFunctionContaining(addr) != null;
	}

	/**
	 * Add a {@link RefType#COMPUTED_JUMP}
	 * reference from {@code exitAddr} to {@code branchBack}, used by
	 * the IFC analyzer to make the listing visualize multi-flow at
	 * ifret/tail-call exits.  Idempotent: if an identical reference
	 * already exists at this address, no-op.
	 *
	 * <p>For tail-call (unconditional CALL) instances, the call's
	 * native CALL reference is kept; the added COMPUTED_JUMP overlays
	 * the post-return continuation.
	 */
	private static void addMultiFlowReturnRef(ReferenceManager refMgr,
			Listing listing, Address exitAddr, Address branchBack) {
		Instruction in = listing.getInstructionAt(exitAddr);
		if (in == null) return;
		String mn = in.getMnemonicString();
		boolean isIfret = mn.equals("ifret") || mn.equals("ifret16");
		// For ifret/ifret16: add COMPUTED_JUMP refs to caller-nexts.
		// For tail-call (jal/jral/etc.) or ex9.it-dispatched-ret: DO NOT
		// add COMPUTED_JUMP refs.  Those refs confuse Ghidra's stack-depth
		// analyzer: the jal's natural flow is CALL (post-call depth is
		// computed via stack-purge), but a COMPUTED_JUMP edge bypasses
		// that and propagates an inconsistent depth to the caller's
		// post-ifcall code.  Visualization of the tail-call's branch-back
		// is still available via the repeatable comment at the IFC body
		// entry (D.4) and via the synth pcode at decompile time.
		if (!isIfret) {
			return;
		}
		// Skip if an equivalent ref is already present (idempotent).
		for (Reference r : in.getReferencesFrom()) {
			if (r.getToAddress().equals(branchBack)
				&& r.getReferenceType().equals(RefType.COMPUTED_JUMP)) {
				return;
			}
		}
		refMgr.addMemoryReference(exitAddr, branchBack, RefType.COMPUTED_JUMP,
			SourceType.ANALYSIS, -1);
	}

	/**
	 * Heuristic for "function likely called only via ifcall". every
	 * external instruction-reference to the entry comes from an
	 * {@code ifcall}/{@code ifcall9}.
	 */
	private static boolean hasOnlyIfcallEntry(ReferenceManager refMgr, Listing listing,
			Function f) {
		Address entry = f.getEntryPoint();
		boolean sawExternalIfcall = false;
		for (Reference r : refMgr.getReferencesTo(entry)) {
			if (f.getBody().contains(r.getFromAddress())) continue;
			Instruction src = listing.getInstructionAt(r.getFromAddress());
			if (src == null) return false;
			String mn = src.getMnemonicString();
			if (mn.equals("ifcall") || mn.equals("ifcall9")) {
				sawExternalIfcall = true;
				continue;
			}
			return false;
		}
		return sawExternalIfcall;
	}
}
