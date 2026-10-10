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
package ghidra.app.decompiler.inline;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompileCallback;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PatchEncoder;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

/**
 * Generates synthetic pcode for the five IFC-style shapes the decompiler
 * needs at ifcall and ifret instances.  Architecture-specific names
 * (mnemonics, registers) come from the {@link IfcDialect}; the pcode
 * shapes are identical across all conformant ISAs.
 *
 * <p>Each public {@code emit*} method writes a complete instruction to
 * the encoder; the caller doesn't need to add anything else for that
 * address.  Methods return false only when the input is malformed
 * (missing call/jump reference, body that fails the inline checks);
 * the caller then falls back to the prototype pcode.
 *
 * <p>This class is stateless beyond its constructor arguments and
 * safe to construct once and reuse across decompile calls on the same
 * program.
 */
public final class IfcPcodeEmitter {

	private final Program program;
	private final Listing listing;
	private final IfcDialect dialect;
	private final Register ifcOnRegister;
	private final Register ifcLpRegister;

	public IfcPcodeEmitter(Program program, IfcDialect dialect) {
		this.program = program;
		this.listing = program.getListing();
		this.dialect = dialect;
		this.ifcOnRegister = program.getLanguage().getRegister(dialect.getIfcOnRegisterName());
		this.ifcLpRegister = program.getLanguage().getRegister(dialect.getIfcLpRegisterName());
	}

	public IfcDialect getDialect() {
		return dialect;
	}

	/**
	 * Emit {@code CALL xTarget; BRANCH inst_next}.  Lets the decompile
	 * render a call inline at this site rather than via the physical
	 * instruction at the actual reference target, which is useful when
	 * that target's instruction is shared with the caller's natural
	 * fall-through path.
	 */
	public void emitInlineCall(PatchEncoder out, Address addr, Instruction instr,
			Address xTarget) throws IOException {
		Address instNext = instr.getMaxAddress().next();
		PcodeOp call = new PcodeOp(addr, 0, PcodeOp.CALL,
			new Varnode[] { new Varnode(xTarget, xTarget.getPointerSize()) });
		PcodeOp br = new PcodeOp(addr, 1, PcodeOp.BRANCH,
			new Varnode[] { new Varnode(instNext, instNext.getPointerSize()) });
		DecompileCallback.encodeInstruction(out, addr, new PcodeOp[] { call, br },
			instr.getLength(), 0, program.getAddressFactory());
	}

	/**
	 * Standard ifcall synth: {@code ifc_lp = inst_next; IFC_ON = 1;
	 * BRANCH target}.  Replaces the sleigh {@code IFC_CHOOSER} pattern
	 * so the chooser doesn't leak into decompile output as a live var.
	 * Returns false if the instruction has no jump/call reference (the
	 * caller should leave the prototype pcode in place).
	 */
	public boolean emitIfcallSynth(PatchEncoder out, Address addr, Instruction instr)
			throws IOException {
		Address ifcTarget = findCallOrJumpTarget(instr);
		if (ifcTarget == null) {
			return false;
		}
		List<PcodeOp> ops = new ArrayList<>();
		int seq = 0;
		if (ifcLpRegister != null && ifcOnRegister != null) {
			Address instNext = instr.getMaxAddress().next();
			Varnode lpDst = regVarnode(ifcLpRegister);
			Varnode lpVal = constVarnode(instNext.getOffset(), ifcLpRegister.getMinimumByteSize());
			ops.add(new PcodeOp(addr, seq++, PcodeOp.COPY, new Varnode[] { lpVal }, lpDst));
			Varnode onDst = regVarnode(ifcOnRegister);
			Varnode onVal = constVarnode(1, ifcOnRegister.getMinimumByteSize());
			ops.add(new PcodeOp(addr, seq++, PcodeOp.COPY, new Varnode[] { onVal }, onDst));
		}
		Varnode tgtVn = new Varnode(ifcTarget, ifcTarget.getPointerSize());
		ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH, new Varnode[] { tgtVn }));
		DecompileCallback.encodeInstruction(out, addr, ops.toArray(new PcodeOp[0]),
			instr.getLength(), 0, program.getAddressFactory());
		return true;
	}

	/**
	 * Emit a BRANCH (or CALL + BRANCH for the unconditional-call tail-
	 * call shape) to {@code target}.  When the dialect declares an
	 * IFC_ON register and the source instruction also lives in
	 * {@code caller}'s primary body (the shared-body case used by IFC),
	 * the branch back is gated on a captured pre-clear IFC_ON value so
	 * the synthetic branch only fires on the IFC path.  Otherwise the
	 * branch is unconditional.
	 */
	public void emitSingleBranchback(PatchEncoder out, Function caller, Address addr,
			Instruction instr, Address target) throws IOException {
		Varnode targetVn = new Varnode(target, target.getPointerSize());
		FlowType ft = instr.getFlowType();
		boolean isUncondCall = ft != null && ft.isCall() && !ft.isConditional();

		List<PcodeOp> ops = new ArrayList<>();
		int seq = 0;
		boolean inPrimaryBody = caller != null && caller.getBody() != null
				&& caller.getBody().contains(addr);

		// Capture pre-clear IFC_ON for the shared-body tail-call case so the
		// BRANCH back to caller_next only fires when we entered via ifcall.
		Varnode preIfcVn = null;
		if (isUncondCall && inPrimaryBody && ifcOnRegister != null) {
			preIfcVn = uniqueVarnode(0x10001000L, ifcOnRegister.getMinimumByteSize());
			ops.add(new PcodeOp(addr, seq++, PcodeOp.COPY,
				new Varnode[] { regVarnode(ifcOnRegister) }, preIfcVn));
		}
		// Clear IFC_ON so downstream pcode doesn't see a stale 1 leaked from
		// the preceding ifcall's synth.  Otherwise const-prop carries IFC_ON
		// past the synth and any unmarked ifret falls through its BRANCHIND.
		appendIfcOnClear(ops, addr, seq);
		seq = ops.size();

		Address callTarget = isUncondCall ? findCallOrJumpTarget(instr) : null;
		if (callTarget != null) {
			Varnode callVn = new Varnode(callTarget, callTarget.getPointerSize());
			ops.add(new PcodeOp(addr, seq++, PcodeOp.CALL, new Varnode[] { callVn }));
			if (preIfcVn != null) {
				ops.add(new PcodeOp(addr, seq++, PcodeOp.CBRANCH,
					new Varnode[] { targetVn, preIfcVn }));
			}
			else {
				ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH, new Varnode[] { targetVn }));
			}
		}
		else {
			ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH, new Varnode[] { targetVn }));
		}
		DecompileCallback.encodeInstruction(out, addr, ops.toArray(new PcodeOp[0]),
			instr.getLength(), 0, program.getAddressFactory());
	}

	/**
	 * Linear-CBRANCH switch dispatching to one of {@code targets} based
	 * on the ifc_lp register's value.  Emits N-1 CBRANCHes plus an
	 * unconditional BRANCH to the last target; by exhaustion the
	 * unconditional BRANCH is the correct fall-through when none of the
	 * CBRANCHes fire.  When the dialect also declares an IFC_ON
	 * register, the dispatch is prefixed with an
	 * {@code IFC_ON == 0 -> goto inst_next} guard so a shared body
	 * reached via natural fall-through doesn't dispatch.
	 */
	public void emitMultiBranchback(PatchEncoder out, Address addr, Instruction instr,
			List<Address> targets) throws IOException {
		if (ifcLpRegister == null) {
			// Dispatch register isn't defined; emit a single BRANCH to
			// the first recorded target as best-effort fallback.
			Varnode tv = new Varnode(targets.get(0), targets.get(0).getPointerSize());
			PcodeOp br = new PcodeOp(addr, 0, PcodeOp.BRANCH, new Varnode[] { tv });
			DecompileCallback.encodeInstruction(out, addr, new PcodeOp[] { br },
				instr.getLength(), 0, program.getAddressFactory());
			return;
		}

		long uniqOff = 0x10000000L;
		Varnode ifcLpVn = regVarnode(ifcLpRegister);
		List<PcodeOp> ops = new ArrayList<>();
		int seq = 0;

		// "if (IFC_ON == 0) goto inst_next" preserves the nop case for
		// shared bodies reached via the function's natural flow.
		if (ifcOnRegister != null) {
			Varnode ifcOnVn = regVarnode(ifcOnRegister);
			Varnode zeroVn = constVarnode(0, ifcOnRegister.getMinimumByteSize());
			Varnode notIfcVn = uniqueVarnode(uniqOff, 1);
			uniqOff += 0x100;
			ops.add(new PcodeOp(addr, seq++, PcodeOp.INT_EQUAL,
				new Varnode[] { ifcOnVn, zeroVn }, notIfcVn));
			Address instNext = instr.getMaxAddress().next();
			Varnode instNextVn = new Varnode(instNext, instNext.getPointerSize());
			ops.add(new PcodeOp(addr, seq++, PcodeOp.CBRANCH,
				new Varnode[] { instNextVn, notIfcVn }));
		}
		appendIfcOnClear(ops, addr, seq);
		seq = ops.size();

		int last = targets.size() - 1;
		for (int i = 0; i < last; i++) {
			Address t = targets.get(i);
			Varnode constVn = constVarnode(t.getOffset(), ifcLpRegister.getMinimumByteSize());
			Varnode condVn = uniqueVarnode(uniqOff, 1);
			uniqOff += 0x100;
			ops.add(new PcodeOp(addr, seq++, PcodeOp.INT_EQUAL,
				new Varnode[] { ifcLpVn, constVn }, condVn));
			Varnode tVn = new Varnode(t, t.getPointerSize());
			ops.add(new PcodeOp(addr, seq++, PcodeOp.CBRANCH, new Varnode[] { tVn, condVn }));
		}
		Address lastT = targets.get(last);
		Varnode lastTVn = new Varnode(lastT, lastT.getPointerSize());
		ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH, new Varnode[] { lastTVn }));
		DecompileCallback.encodeInstruction(out, addr, ops.toArray(new PcodeOp[0]),
			instr.getLength(), 0, program.getAddressFactory());
	}

	/**
	 * Per-instruction classification used by {@link #emitInlineBody}.
	 * Each terminator has a specific replacement pcode shape; see
	 * {@link #emitTerminator} for what each emits.  Non-terminator
	 * insns and ifcalls (which we walk past into their inner body)
	 * have no entry in the {@code terminalKind} map.
	 */
	private enum Term {
		/** ifret/ifret16: returns to the scope's caller_next via ifc_lp. */
		IFRET,
		/** Unconditional CALL X (jal, ex9-call, or jal-thunk for a fresh
		 *  ifcall): in IFC mode set_link_gpr stores lp=ifc_lp, so the
		 *  callee returns to the scope's caller_next. */
		TAILCALL,
		/** Computed CALL (jral5 Rt): same as TAILCALL but indirect. */
		COMPCALL,
		/** ex9-dispatch JUMP X: the underlying j clears ifc_on and
		 *  transfers control to X (typically lands back in F's primary
		 *  body). */
		EX9JUMP,
		/** Bare TERMINAL-not-call (pop25/ret/jr): exits the enclosing
		 *  function via the stack-restored or unchanged lp.  Emit the
		 *  prototype pcode as-is so the RETURN op surfaces. */
		PASSIVE
	}

	/**
	 * Emit an IFC body's prototype pcode inline at the ifcall site.
	 * Three passes: CFG-walk and classify each address; linearize and
	 * compute per-address pcode-op seq starts; emit pcode with intra-
	 * body branch targets rewritten to const-space relative-seq
	 * offsets.  See {@link Term} for the replacement shapes used at
	 * each terminator.
	 *
	 * <p>Returns false (so the caller falls back to {@link #emitIfcallSynth})
	 * if the body has drifted since analysis time or is shaped in a
	 * way this walker can't model: missing call refs, unresolved
	 * indirect branches, conditional CALLs, or body larger than the
	 * dialect's {@link IfcDialect#getMaxBodyInsns() max body limit}.
	 */
	public boolean emitInlineBody(PatchEncoder out, Address addr, Instruction ifcallInstr,
			Address bodyStart) throws IOException {
		Address callerNext = ifcallInstr.getMaxAddress().next();
		AddressSpace defSpace = program.getAddressFactory().getDefaultAddressSpace();
		AddressSpace constSpace = program.getAddressFactory().getConstantSpace();

		// Pass 1 state.
		LinkedHashSet<Address> reachable = new LinkedHashSet<>();
		Map<Address, Term> terminalKind = new HashMap<>();
		Map<Address, Address> termTarget = new HashMap<>();
		Map<Address, Address> termContinuation = new HashMap<>();
		// ifc_on at the START of each visited instruction (1 = in IFC
		// mode, 0 = cleared by a prior taken branch within this walk).
		Map<Address, Integer> ifcOnAt = new HashMap<>();
		// caller_next a terminator at this address should branch back
		// to.  Successors inherit; an ifcall overrides for its inner
		// body (nested ifcall keeps the outer scope, fresh ifcall
		// starts a new scope at its own caller_next).
		Map<Address, Address> scopeAt = new HashMap<>();
		// ifcalls that we walk past into their inner body rather than
		// treat as a terminator; Pass 3 emits a single BRANCH op per
		// entry, transferring control to the inner body's first
		// emitted pcode op.
		Map<Address, Address> ifcallTransition = new HashMap<>();
		ifcOnAt.put(bodyStart, 1);
		scopeAt.put(bodyStart, callerNext);
		Deque<Address> work = new ArrayDeque<>();
		work.add(bodyStart);
		int maxBody = dialect.getMaxBodyInsns();
		while (!work.isEmpty()) {
			if (reachable.size() >= maxBody) return false;
			Address cur = work.poll();
			if (!reachable.add(cur)) continue;
			Instruction in = listing.getInstructionAt(cur);
			if (in == null) return false;
			int ifcOn = ifcOnAt.getOrDefault(cur, 1);
			Address scope = scopeAt.getOrDefault(cur, callerNext);
			String mn = in.getMnemonicString().toLowerCase();

			// ifret: terminator that branches to current ifc_lp, which
			// the walker tracks as `scope`.  ifret with ifc_on=0 is
			// technically a nop, but modeling it the same way is fine
			// here: in isolated bodies the natural fall-through is
			// filler, and the observable behavior from the outer
			// ifcall's caller is identical either way.
			if (dialect.getIfretMnemonics().contains(mn)) {
				terminalKind.put(cur, Term.IFRET);
				termContinuation.put(cur, scope);
				continue;
			}

			// ifcall in a body: walk into the inner body rather than
			// emit a terminator.  An ifcall only writes ifc_lp on first
			// entry to IFC mode (ifc_on=0), so a nested ifcall keeps
			// the outer scope while a fresh ifcall starts a new scope
			// at its own caller_next.  After the ifcall, ifc_on=1.
			if (dialect.getIfcallMnemonics().contains(mn)) {
				Address ct = findCallOrJumpTarget(in);
				if (ct == null) return false;
				Address innerScope = ifcOn == 1 ? scope : in.getMaxAddress().next();
				ifcOnAt.putIfAbsent(ct, 1);
				scopeAt.putIfAbsent(ct, innerScope);
				ifcallTransition.put(cur, ct);
				work.add(ct);
				continue;
			}

			// ex9-dispatch resolves to a CALL or JUMP at runtime; the
			// analyzer attaches a call or jump ref reflecting that
			// instruction's effective flow.
			FlowType ft = in.getFlowType();
			if (dialect.getEx9DispatchMnemonics().contains(mn)) {
				for (Reference r : in.getReferencesFrom()) {
					RefType rt = r.getReferenceType();
					if (rt.isCall()) {
						terminalKind.put(cur, Term.TAILCALL);
						termTarget.put(cur, r.getToAddress());
						termContinuation.put(cur, scope);
						break;
					}
					if (rt.isJump()) {
						terminalKind.put(cur, Term.EX9JUMP);
						termTarget.put(cur, r.getToAddress());
						break;
					}
				}
				if (terminalKind.containsKey(cur)) continue;
				// No call/jump ref - the IT-table entry was a pure data
				// op (no flow effect).  Fall through.
			}

			// Unconditional CALL (jal, jral, jral5): tail-call under
			// set_link_gpr, callee returns to scope's caller_next.
			// Conditional CALLs aren't handled - we'd need to model
			// both the call and the not-taken fall-through path.
			if (ft != null && ft.isCall() && !ft.isConditional()) {
				if (ft.isComputed()) {
					terminalKind.put(cur, Term.COMPCALL);
					termContinuation.put(cur, scope);
				}
				else {
					Address t = findCallOrJumpTarget(in);
					if (t == null) return false;
					terminalKind.put(cur, Term.TAILCALL);
					termTarget.put(cur, t);
					termContinuation.put(cur, scope);
				}
				continue;
			}

			// Bare-terminal (pop25/ret/jr): exits the enclosing function.
			if (ft != null && ft.isTerminal()) {
				terminalKind.put(cur, Term.PASSIVE);
				continue;
			}

			// Non-terminator: enqueue successors.  Any taken branch
			// clears ifc_on at the target.  Scope is set by enclosing
			// ifcalls and flows through unchanged across branches.
			if (ft != null && ft.isJump()) {
				for (Reference r : in.getReferencesFrom()) {
					if (r.getReferenceType().isJump()) {
						Address jt = r.getToAddress();
						ifcOnAt.putIfAbsent(jt, 0);
						scopeAt.putIfAbsent(jt, scope);
						work.add(jt);
					}
				}
				if (ft.isConditional()) {
					Address fall = in.getFallThrough();
					if (fall != null) {
						ifcOnAt.putIfAbsent(fall, ifcOn);
						scopeAt.putIfAbsent(fall, scope);
						work.add(fall);
					}
				}
				continue;
			}
			Address fall = in.getFallThrough();
			if (fall == null) return false;
			ifcOnAt.putIfAbsent(fall, ifcOn);
			scopeAt.putIfAbsent(fall, scope);
			work.add(fall);
		}
		if (terminalKind.isEmpty()) return false;

		// Pass 2: physical-address linearization + per-instruction
		// seq-start map.
		TreeSet<Address> ordered = new TreeSet<>(reachable);
		boolean prependBranch = !ordered.first().equals(bodyStart);
		Map<Address, Integer> seqStart = new HashMap<>();
		int totalSeq = prependBranch ? 1 : 0;
		for (Address a : ordered) {
			seqStart.put(a, totalSeq);
			totalSeq += opCountFor(a, terminalKind, ifcallTransition);
		}

		// Pass 3: emit pcode.
		List<PcodeOp> ops = new ArrayList<>();
		int seq = 0;
		if (prependBranch) {
			long rel = ((long) seqStart.get(bodyStart)) & 0xFFFFFFFFL;
			ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH,
					new Varnode[] { new Varnode(constSpace.getAddress(rel), 4) }));
		}
		for (Address a : ordered) {
			Address ifcallTarget = ifcallTransition.get(a);
			if (ifcallTarget != null) {
				// ifcall transition: discard the prototype's ifc_lp/
				// ifc_on plumbing; we model entry into the inner body
				// by branching directly to the inner body's first
				// emitted pcode op.
				Integer innerSeq = seqStart.get(ifcallTarget);
				if (innerSeq == null) return false;
				long rel = ((long) innerSeq - seq) & 0xFFFFFFFFL;
				ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH,
						new Varnode[] { new Varnode(constSpace.getAddress(rel), 4) }));
				continue;
			}
			Term kind = terminalKind.get(a);
			if (kind != null) {
				seq = emitTerminator(ops, addr, seq, a, kind,
						termTarget.get(a), termContinuation.get(a));
				if (seq < 0) return false;
				continue;
			}
			seq = emitBodyInstruction(ops, addr, seq, a, defSpace, constSpace, seqStart);
		}
		DecompileCallback.encodeInstruction(out, addr, ops.toArray(new PcodeOp[0]),
			ifcallInstr.getLength(), 0, program.getAddressFactory());
		return true;
	}

	/** Op count contributed by an instruction at {@code a} in the
	 *  emitted output - mirrors what {@link #emitTerminator} and
	 *  {@link #emitBodyInstruction} actually emit. */
	private int opCountFor(Address a, Map<Address, Term> terminalKind,
			Map<Address, Address> ifcallTransition) {
		Term kind = terminalKind.get(a);
		if (kind != null) {
			switch (kind) {
				case IFRET:
				case EX9JUMP:
					return 2; // IFC_ON=0; BRANCH target
				case TAILCALL:
				case COMPCALL:
					return 3; // IFC_ON=0; CALL/CALLIND; BRANCH cont
				case PASSIVE:
					PcodeOp[] proto = listing.getInstructionAt(a).getPcode();
					return proto == null ? 0 : proto.length;
			}
		}
		if (ifcallTransition.containsKey(a)) {
			return 1; // single BRANCH op to inner body
		}
		Instruction in = listing.getInstructionAt(a);
		PcodeOp[] proto = in.getPcode();
		int n = proto == null ? 0 : proto.length;
		FlowType ft = in.getFlowType();
		if (ft != null && ft.isJump() && !ft.isConditional()) {
			n -= 1; // drop final BRANCH for intra-body uncond jumps
		}
		return n;
	}

	/** Emit the replacement pcode for a terminator at {@code a}.
	 *  Returns the new seq, or -1 on failure (missing CALLIND register). */
	private int emitTerminator(List<PcodeOp> ops, Address addr, int seq, Address a, Term kind,
			Address target, Address cont) {
		Instruction in = listing.getInstructionAt(a);
		if (kind == Term.PASSIVE) {
			// pop25/ret/jr: emit prototype pcode as-is.  These insns
			// only have LOAD/COPY/RETURN ops, so no branch-target
			// rewriting is required.
			PcodeOp[] proto = in.getPcode();
			if (proto != null) {
				for (PcodeOp p : proto) {
					ops.add(new PcodeOp(addr, seq++, p.getOpcode(),
							p.getInputs(), p.getOutput()));
				}
			}
			return seq;
		}
		// All other terminators clear IFC_ON and end in a BRANCH.
		if (ifcOnRegister != null) {
			ops.add(new PcodeOp(addr, seq++, PcodeOp.COPY,
				new Varnode[] { constVarnode(0, ifcOnRegister.getMinimumByteSize()) },
				regVarnode(ifcOnRegister)));
		}
		switch (kind) {
			case IFRET:
				ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH,
						new Varnode[] { new Varnode(cont, cont.getPointerSize()) }));
				return seq;
			case EX9JUMP:
				ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH,
						new Varnode[] { new Varnode(target, target.getPointerSize()) }));
				return seq;
			case TAILCALL:
				ops.add(new PcodeOp(addr, seq++, PcodeOp.CALL,
						new Varnode[] { new Varnode(target, target.getPointerSize()) }));
				ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH,
						new Varnode[] { new Varnode(cont, cont.getPointerSize()) }));
				return seq;
			case COMPCALL:
				Varnode reg = findCallIndRegister(in);
				if (reg == null) return -1;
				ops.add(new PcodeOp(addr, seq++, PcodeOp.CALLIND, new Varnode[] { reg }));
				ops.add(new PcodeOp(addr, seq++, PcodeOp.BRANCH,
						new Varnode[] { new Varnode(cont, cont.getPointerSize()) }));
				return seq;
			default:
				return -1; // unreachable
		}
	}

	/** Emit prototype pcode for a non-terminator body instruction at
	 *  {@code a}, with RAM-targeted BRANCH/CBRANCH rewritten to const-
	 *  space relative-seq offsets when the target is itself in the
	 *  linearized body. */
	private int emitBodyInstruction(List<PcodeOp> ops, Address addr, int seq, Address a,
			AddressSpace defSpace, AddressSpace constSpace,
			Map<Address, Integer> seqStart) {
		Instruction in = listing.getInstructionAt(a);
		PcodeOp[] proto = in.getPcode();
		if (proto == null) return seq;
		Address skipBranchTo = unconditionalIntraBodyJumpTarget(in);
		for (PcodeOp p : proto) {
			int op = p.getOpcode();
			// Drop the final BRANCH op of an unconditional intra-body
			// jump - its target's pcode follows immediately in the
			// linearization, so the natural fall-through is correct.
			if (skipBranchTo != null && op == PcodeOp.BRANCH
					&& p.getNumInputs() >= 1
					&& p.getInput(0).getAddress().equals(skipBranchTo)) {
				continue;
			}
			// Rewrite RAM-targeted BRANCH/CBRANCH whose target is also
			// in the linearized body into a const-space relative-seq
			// offset (sleigh's resolveRelatives convention, offset
			// masked to the varnode size).
			if ((op == PcodeOp.BRANCH || op == PcodeOp.CBRANCH)
					&& p.getNumInputs() >= 1) {
				Varnode tv = p.getInput(0);
				if (tv != null && tv.getAddress().getAddressSpace().equals(defSpace)) {
					Integer tgtSeq = seqStart.get(tv.getAddress());
					if (tgtSeq != null) {
						Varnode[] inputs = p.getInputs().clone();
						long rel = ((long) tgtSeq - seq) & 0xFFFFFFFFL;
						inputs[0] = new Varnode(constSpace.getAddress(rel), tv.getSize());
						ops.add(new PcodeOp(addr, seq++, op, inputs, p.getOutput()));
						continue;
					}
				}
			}
			ops.add(new PcodeOp(addr, seq++, op, p.getInputs(), p.getOutput()));
		}
		return seq;
	}

	private void appendIfcOnClear(List<PcodeOp> ops, Address addr, int seq) {
		if (ifcOnRegister == null) return;
		ops.add(new PcodeOp(addr, seq, PcodeOp.COPY,
			new Varnode[] { constVarnode(0, ifcOnRegister.getMinimumByteSize()) },
			regVarnode(ifcOnRegister)));
	}

	private Varnode regVarnode(Register r) {
		return new Varnode(r.getAddress(), r.getMinimumByteSize());
	}

	private Varnode constVarnode(long value, int size) {
		return new Varnode(program.getAddressFactory().getConstantAddress(value), size);
	}

	private Varnode uniqueVarnode(long offset, int size) {
		return new Varnode(program.getAddressFactory().getUniqueSpace().getAddress(offset), size);
	}

	private static Address findCallOrJumpTarget(Instruction instr) {
		for (Reference r : instr.getReferencesFrom()) {
			RefType rt = r.getReferenceType();
			if (rt.isCall() || rt.isJump()) {
				return r.getToAddress();
			}
		}
		return null;
	}

	private static Varnode findCallIndRegister(Instruction in) {
		PcodeOp[] proto = in.getPcode();
		if (proto == null) return null;
		for (PcodeOp p : proto) {
			if (p.getOpcode() == PcodeOp.CALLIND && p.getNumInputs() >= 1) {
				return p.getInput(0);
			}
		}
		return null;
	}

	private static Address unconditionalIntraBodyJumpTarget(Instruction in) {
		FlowType ft = in.getFlowType();
		if (ft == null || !ft.isJump() || ft.isConditional()) return null;
		for (Reference r : in.getReferencesFrom()) {
			if (r.getReferenceType().isJump()) return r.getToAddress();
		}
		return null;
	}

}
