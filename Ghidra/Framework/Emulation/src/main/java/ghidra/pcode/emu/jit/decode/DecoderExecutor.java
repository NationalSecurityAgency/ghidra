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
package ghidra.pcode.emu.jit.decode;

import java.math.BigInteger;
import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighParserContext;
import ghidra.app.util.PseudoInstruction;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.*;
import ghidra.pcode.emu.jit.analysis.JitDataFlowState;
import ghidra.pcode.emu.jit.op.JitNopOp;
import ghidra.pcode.exec.*;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.Msg;

/**
 * The p-code interpreter used during passage decode
 * 
 * <p>
 * Aside from branches, this interpreter simply logs each op, so that they get collected into the
 * greater stride and passage. It does "rewrite" the ops, so that we can easily recover the input
 * context, especially when the op is emitted from a user inject. For branches, this interpreter
 * creates the appropriate {@link Branch} records and notifies the passage decoder of new seeds.
 * 
 * <p>
 * This executor also implements the {@link DisassemblerContext} to track context changes, namely
 * uses of {@code globalset}. This is kept in {@link #futCtx}. <b>TODO</b>: Should {@link #futCtx}
 * be moved into the passage decoder to ensure it persists for more than a single instruction? I'm
 * not sure whether or not that is already taken care of by the {@link Disassembler}.
 * 
 * @implNote I had considered using a {@link JitDataFlowState} here, but that's Not a Good Idea,
 *           because a stride is not generally a <em>basic block</em>. A "stride" is just a
 *           contiguous run of instructions with fall-through. If there is a jump into the middle of
 *           it, any value analysis (e.g., constant folding) would be meaningless. Were we to put
 *           this in there, the temptation may be to have userop libraries attempt constant
 *           resolution, esp., for syscall numbers. While that may work, if only because syscall
 *           numbers are conventionally set in the same basic block as the invocation, there's no
 *           guarantee that's the case. And there may be other use cases where this is totally
 *           wrong. Instead, we should use as barren an executor here as possible. We do incorporate
 *           injects here, because they may affect control flow, which the decoder must consider.
 * 
 * @implNote <b>WARNING</b>: This executor has no {@link PcodeExecutorState state} object. Care must
 *           be taken to ensure we override any method that assumes we have one, and that we don't
 *           invoke any method from the superclass that assumes we have one.
 * 
 */
class DecoderExecutor extends PcodeExecutor<Object>
		implements DisassemblerContextAdapter {
	private final DecoderForOneStride stride;
	final AddrCtx at;

	private PseudoInstruction instruction;
	private NopPcodeOp termNop;

	private RegisterValue flow;
	private final Map<Address, RegisterValue> futCtx = new HashMap<>();

	final List<PcodeOp> opsForThisStep = new ArrayList<>();
	private final List<Branch> branchesForThisStep = new ArrayList<>();

	private final Map<PcodeOp, DecodedPcodeOp> rewrites = new HashMap<>();

	/**
	 * Construct the interpreter
	 * 
	 * @param stride the stride being decoded
	 * @param at the address and contextreg value of the instruction
	 * @param instruction the instruction, or {@code null}
	 */
	DecoderExecutor(DecoderForOneStride stride, AddrCtx at, PseudoInstruction instruction) {
		super(stride.decoder.thread.getLanguage(), null, null, null);
		this.stride = stride;
		this.at = at;
		setInstruction(instruction);
	}

	/**
	 * Construct the interpreter without an instruction
	 * 
	 * <p>
	 * This initializes the interpreter without an instruction. The decoder must set the instruction
	 * via {@link #setInstruction(PseudoInstruction)} as soon as it becomes available, either 1)
	 * because the step resulted in a simple instruction, or 2) because a user inject caused the
	 * instruction to be decoded.
	 * 
	 * @param stride the stride being decoded
	 * @param at the address and contextreg value of the instruction
	 */
	DecoderExecutor(DecoderForOneStride stride, AddrCtx at) {
		this(stride, at, null);
	}

	/**
	 * Re-write the given op as a {@link DecodedPcodeOp} with the given address/contextreg value
	 * 
	 * <p>
	 * If the given op is already a {@link DecodedPcodeOp}, i.e., a {@link DecodeErrorPcodeOp} or
	 * {@link NopPcodeOp}, just return the same op without re-writing.
	 * 
	 * @param at the address and decode context
	 * @param op the original p-code op
	 * @return the equivalent op, re-written
	 */
	static DecodedPcodeOp rewriteOp(AddrCtx at, PcodeOp op) {
		if (op instanceof DecodedPcodeOp dec) {
			assert dec.getAt().equals(at);
			return dec;
		}
		return new DecodedPcodeOp(at, op);
	}

	/**
	 * Re-write the given op
	 * 
	 * <p>
	 * Because we create an interpreter for each instruction step, we already know the target
	 * address and decode context. We re-write the op to capture that target. If we've already
	 * re-written the op, return the existing one to ensure we retain identity in the re-written
	 * realm.
	 * 
	 * @param op the op to re-write
	 * @return the equivalent op, re-written
	 */
	DecodedPcodeOp rewrite(PcodeOp op) {
		return rewrites.computeIfAbsent(op, o -> rewriteOp(at, o));
	}

	/**
	 * Set the current instruction.
	 * 
	 * <p>
	 * This also pre-computes the resulting "flow" context from the given instruction. That is, the
	 * input context for the next decode instruction, not accounting for {@code globalset}. It is
	 * computed by taking the given instruction's input context and resetting non-flowing bits to
	 * the language's defaults. When a branch is encountered or fall through is considered, we
	 * account for {@code globalset} and derive the target context for the target address.
	 * 
	 * @param instruction the instruction
	 */
	void setInstruction(PseudoInstruction instruction) {
		this.instruction = instruction;
		if (at.rvCtx == null || instruction == null ||
			instruction instanceof DecodeErrorInstruction) {
			this.flow = at.rvCtx;
		}
		else {
			Register contextreg = stride.decoder.contextreg;
			ProgramContext defaultContext = stride.decoder.defaultContext;
			this.flow = new RegisterValue(contextreg, BigInteger.ZERO)
					.combineValues(defaultContext.getDefaultValue(contextreg, at.address))
					.combineValues(defaultContext.getFlowValue(at.rvCtx));
			processContextChanges();
		}
	}

	/**
	 * Decode the instruction this executor is meant to interpret
	 * 
	 * <p>
	 * This can be delayed if there is a user inject at the target address. In that case, this may
	 * be invoked by {@link DecoderUseropLibrary#emu_exec_decoded(PcodeExecutor)} or
	 * {@link DecoderUseropLibrary#emu_skip_decoded(PcodeExecutor)}.
	 * 
	 * @return the decoded instruction, which may be a {@link DecodeErrorInstruction}
	 */
	PseudoInstruction decodeInstruction() {
		PseudoInstruction instruction = stride.decoder.decodeInstruction(at.address, at.rvCtx);
		setInstruction(instruction);
		return instruction;
	}

	private void processContextChanges() {
		try {
			SleighParserContext parserCtx =
				(SleighParserContext) instruction.getParserContext();
			parserCtx.applyCommits(this);
		}
		catch (MemoryAccessException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Interpret the given program with the passage decoder's userop library
	 * 
	 * @param program the p-code to interpret
	 */
	public void execute(PcodeProgram program) {
		execute(program, stride.passage.library());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * @implNote We check here if a "terminal nop" was necessary. Any jump to (should never be past)
	 *           the end of the program will require one. Instead of trying to figure out what the
	 *           op following this instruction is, so the jumps can target it, we add a special nop,
	 *           and the jump is made to target it. Once we reach the end of the p-code program
	 *           proper, we have to add that nop.
	 */
	@Override
	public void finish(PcodeFrame frame, PcodeUseropLibrary<Object> library) {
		super.finish(frame, library);
		if (termNop != null) {
			opsForThisStep.add(termNop);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We only really need to interpret branching ops here. We also interpret
	 * {@link PcodeOp#CALLOTHER callother}, in case wer're able to inline a p-code userop. Note that
	 * if we inline the userop, we still retain the {@code callother} op, because internal jumps may
	 * target it. It is easier to leave it in the books and {@link JitNopOp nop} it out later than
	 * to try to substitute the first inlined op. Worse, if the inlined userop emits no p-code,
	 * substitution would get especially difficult.
	 * 
	 * <p>
	 * We also interpret {@link PcodeOp#UNIMPLEMENTED unimplemented}, because that will require us
	 * to create an {@link ErrBranch} record. All other ops must still be added to the decoded
	 * passage, but not (yet) interpreted.
	 */
	@Override
	public void stepOp(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<Object> library) {
		/**
		 * NOTE: Must log every op, including inlined CALLOTHER's, because an internal jump may
		 * refer to that CALLOTHER. It's easier, I think, to snuff the op later than it is to try to
		 * substitute the refs.
		 */
		op = rewrite(op);
		switch (op.getOpcode()) {
			case PcodeOp.BRANCH, //
					PcodeOp.CBRANCH, //
					PcodeOp.CALL, //
					PcodeOp.BRANCHIND, //
					PcodeOp.CALLIND, //
					PcodeOp.RETURN, //
					PcodeOp.CALLOTHER, //
					PcodeOp.UNIMPLEMENTED -> {
				opsForThisStep.add(op);
				super.stepOp(op, frame, library);
			}
			default -> {
				opsForThisStep.add(op);
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We interpret this the same as an unconditional branch, because at this point, we need only
	 * collect branch targets to seed additional strides.
	 */
	@Override
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		doExecuteBranch(op, frame);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We override this to prevent an attempt to write PC to the {@link #getState() state}, which is
	 * {@code null}.
	 */
	@Override
	protected void branchToOffset(PcodeOp op, long offset, PcodeFrame frame) {
	}

	@Override
	protected void branchToOffset(PcodeOp op, Object offset, PcodeFrame frame) {
		throw new AssertionError();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This creates an {@link ExtBranch} record and collects it for this instruction step. The
	 * record will first be used to check for fall through. Then, the passage decoder is notified,
	 * which either adds it to the seed queue or converts it to an {@link IntBranch} record.
	 * 
	 * @see #checkFallthroughAndAccumulate(PcodeProgram)
	 */
	@Override
	protected void branchToAddress(PcodeOp op, Address target) {
		branchesForThisStep.add(new ExtBranch(op, takeTargetContext(target)));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This create an {@link IntBranch} record and collects it for this instruction step. The record
	 * will first be used to check for fall through. Then, the passage decoder is notified, which
	 * collects the records to later passage-wide control flow analysis.
	 * 
	 * @see #checkFallthroughAndAccumulate(PcodeProgram)
	 */
	@Override
	protected void branchInternal(PcodeOp op, PcodeFrame frame, int relative) {
		int tgtSeq = op.getSeqnum().getTime() + relative;
		if (tgtSeq == frame.getCode().size()) {
			if (termNop == null) {
				termNop = new NopPcodeOp(at, tgtSeq);
			}
			branchesForThisStep.add(new IntBranch(op, termNop, false));
		}
		else {
			PcodeOp to = frame.getCode().get(op.getSeqnum().getTime() + relative);
			branchesForThisStep.add(new IntBranch(op, rewrite(to), false));
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This create an {@link IndBranch} record and collects it for this instruction step. The record
	 * will first be used to check for fall through. Then, the passage decoder is notified, which
	 * collects the records to later passage-wide control flow analysis.
	 * 
	 * @see #checkFallthroughAndAccumulate(PcodeProgram)
	 */
	@Override
	protected void doExecuteIndirectBranch(PcodeOp op, PcodeFrame frame) {
		branchesForThisStep.add(new IndBranch(op, flow));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This create an {@link ErrBranch} record and collects it for this instruction step. The record
	 * will first be used to check for fall through. Then, the passage decoder is notified, which
	 * collects the records to later passage-wide control flow analysis. In most (all?) cases, this
	 * is the only op emitted by the instruction (decode error, unimplemented instruction), and so
	 * there is certainly no fall through.
	 * 
	 * @see #checkFallthroughAndAccumulate(PcodeProgram)
	 */
	@Override
	protected void badOp(PcodeOp op) {
		String message;
		if (instruction instanceof DecodeErrorInstruction err) {
			message = err.getMessage();
		}
		else {
			message =
				"Encountered an unimplemented instruction at " + at + " (" + instruction + ")";
		}
		branchesForThisStep.add(new ErrBranch(op, message));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * This create an {@link ErrBranch} record and collects it for this instruction step. The record
	 * will first be used to check for fall through. Then, the passage decoder is notified, which
	 * collects the records to later passage-wide control flow analysis. In contrast to
	 * {@link #badOp(PcodeOp)}, an instruction that calls a missing userop may still have fall
	 * through.
	 */
	@Override
	protected void onMissingUseropDef(PcodeOp op, PcodeFrame frame, String opName,
			PcodeUseropLibrary<Object> library) {
		branchesForThisStep.add(
			new ErrBranch(op, "Sleigh userop '%s' is not in the library".formatted(opName)));
	}

	@Override
	public void setFutureRegisterValue(Address address, RegisterValue value) {
		if (!value.getRegister().isProcessorContext()) {
			return;
		}
		futCtx.compute(address, (a, v) -> v == null ? value : v.combineValues(value));
	}

	/**
	 * Derive the contextreg value at the given target address (branch or fall through).
	 * 
	 * <p>
	 * An instruction's constructors may use {@code globalset} to place context changes at specific
	 * addresses. Those changes are collected by
	 * {@link #setFutureRegisterValue(Address, RegisterValue)} through some chain of method
	 * invocations started by {@link #setInstruction(PseudoInstruction)}. When the interpreter
	 * encounters a branch op, that op will specify the target address. We must also derive the
	 * context for that branch. This is the pre-computed "flow" context, but now accounting for
	 * {@code globalset} at the target address.
	 * 
	 * @param target the target address
	 * @return the target address and contextreg value
	 */
	public AddrCtx takeTargetContext(Address target) {
		if (!futCtx.containsKey(target)) {
			return new AddrCtx(flow, target);
		}
		/** Do not remove, in case there are multiple branches to the same target address */
		return new AddrCtx(flow.combineValues(futCtx.get(target)), target);
	}

	/**
	 * After p-code interpretation, check if the instruction has fall through, notify the stride
	 * decoder of the instruction's ops, and notify the passage of the instruction's branches.
	 * 
	 * <p>
	 * To determine whether there's fall through, this performs a miniature control flow analysis on
	 * just this step's p-code ops. This is required because a user inject can be very complex, and
	 * need not obey all of the usual control flow checks imposed by the Sleigh semantic compiler.
	 * In particular {@link Instruction#hasFallthrough()} is not sufficient, for at least two
	 * reasons: 1) The aforementioned user inject possibilities, 2) We do not consider a
	 * {@link PcodeOp#CALL call} or {@link PcodeOp#CALLIND callind} as having fall through.
	 * 
	 * <p>
	 * To use control flow analysis as a means of checking for fall through, we append a special
	 * "probe" {@link ExitPcodeOp} along with an {@link ExtBranch} record to {@link AddrCtx#NOWHERE
	 * nowhere}. The probe thus serves the secondary purpose of preventing any complaints from the
	 * analyzer about unterminated control flow. We then perform the analysis, borrowing
	 * {@link BlockSplitter} from {@link JitControlFlowModel}. In practice, this seems fast enough.
	 * Because the splitter keeps the blocks in the original order, the first op will certainly be
	 * in the first block, and the probe op will certainly be in the last block. We perform a simple
	 * reachability test between the two. The step has fall through if and only if a path is found.
	 * 
	 * @param from the instruction's or inject's p-code
	 * @return true if the step falls through.
	 */
	public boolean checkFallthroughAndAccumulate(PcodeProgram from) {
		if (instruction instanceof DecodeErrorInstruction) {
			stride.opsForStride.addAll(opsForThisStep);
			for (Branch branch : branchesForThisStep) {
				switch (branch) {
					case ErrBranch eb -> stride.passage.otherBranches.put(eb.from(), eb);
					default -> throw new AssertionError();
				}
			}
			return false;
		}
		if (opsForThisStep.isEmpty()) {
			return true;
		}

		ExitPcodeOp probeOp = new ExitPcodeOp(AddrCtx.NOWHERE);
		opsForThisStep.add(probeOp);
		ExtBranch probeBranch = new ExtBranch(probeOp, AddrCtx.NOWHERE);
		branchesForThisStep.add(probeBranch);

		PcodeProgram program = new PcodeProgram(from, opsForThisStep);
		BlockSplitter splitter = new BlockSplitter(program);
		splitter.addBranches(branchesForThisStep);
		SequencedMap<PcodeOp, JitBlock> blocks = splitter.splitBlocks();
		JitBlock entry = blocks.firstEntry().getValue();
		JitBlock exit = blocks.lastEntry().getValue();

		Set<JitBlock> reachable = new HashSet<>();
		collectReachable(reachable, entry);

		for (JitBlock block : blocks.values()) {
			for (PcodeOp op : block.getCode()) {
				if (op != probeOp) {
					stride.opsForStride.add(op);
				}
			}
			for (IntBranch branch : block.branchesFrom()) {
				if (!branch.isFall()) {
					stride.passage.internalBranches.put(branch.from(), branch);
				}
			}
			for (Branch branch : block.branchesOut()) {
				if (branch != probeBranch) {
					switch (branch) {
						case ExtBranch eb -> stride.passage.flowTo(eb);
						default -> stride.passage.otherBranches.put(branch.from(), branch);
					}
				}
			}
		}

		return reachable.contains(exit);
	}

	/**
	 * The reachability test mentioned in {@link #checkFallthroughAndAccumulate(PcodeProgram)}
	 * 
	 * <p>
	 * Collects the set of blocks reachable from {@code cur} into the given mutable set.
	 * 
	 * @param into a mutable set for collecting reachable blocks
	 * @param cur the source block, or an intermediate during recursion
	 */
	private void collectReachable(Set<JitBlock> into, JitBlock cur) {
		if (!into.add(cur)) {
			return;
		}
		for (BlockFlow flow : cur.flowsFrom().values()) {
			collectReachable(into, flow.to());
		}
	}

	/**
	 * Compute the fall-through address
	 * 
	 * <p>
	 * This computes the "next" address whether or not the instruction actually has fall through.
	 * The caller should check for fall through first.
	 * 
	 * @return the next address
	 * @implNote If no instruction was actually decoded during this step, and the decoder is asking
	 *           about fall through, then the user very likely made an error in specifying an
	 *           inject's control flow, in which case the counter will not advance. To get this same
	 *           effect, we just return the current address. The decoder and/or translator ought to
	 *           recognize this and ensure the resulting infinite loop can be interrupted.
	 * @see PcodeMachine#inject(Address, String)
	 */
	Address getAdvancedAddress() {
		if (instruction != null) {
			return instruction.getMaxAddress().next();
		}
		Msg.warn(this, "An inject may have forgotten control flow.");
		return at.address;
	}

	/**
	 * Notify the stride of an instruction
	 * 
	 * <p>
	 * For addresses without injects, every decoded instruction ought to be included in the stride.
	 * For an address with an inject, a decoded instruction should only be included if it is
	 * actually interpreted, i.e., its ops are included.
	 * 
	 * @param instruction the decoded instruction
	 */
	void addInstruction(PseudoInstruction instruction) {
		stride.instructions.add(instruction);
	}
}
