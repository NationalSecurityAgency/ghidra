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
package ghidra.pcode.exec;

import java.util.List;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.pcode.opbehavior.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An executor of p-code programs
 * 
 * <p>
 * This is the kernel of Sleigh expression evaluation and p-code emulation. For a complete example
 * of a p-code emulator, see {@link PcodeEmulator}.
 *
 * @param <T> the type of values processed by the executor
 */
public class PcodeExecutor<T> {
	protected final SleighLanguage language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final PcodeExecutorState<T> state;
	protected final Reason reason;
	protected final Register pc;
	protected final int pcSize;

	/**
	 * Construct an executor with the given bindings
	 * 
	 * @param language the processor language
	 * @param arithmetic an implementation of arithmetic p-code ops
	 * @param state an implementation of load/store p-code ops
	 * @param reason a reason for reading the state with this executor
	 */
	public PcodeExecutor(SleighLanguage language, PcodeArithmetic<T> arithmetic,
			PcodeExecutorState<T> state, Reason reason) {
		this.language = language;
		this.arithmetic = arithmetic;
		this.state = state;
		this.reason = reason;

		this.pc = language.getProgramCounter();
		this.pcSize = pc != null ? pc.getNumBytes() : language.getDefaultSpace().getPointerSize();
	}

	/**
	 * Get the executor's Sleigh language (processor model)
	 * 
	 * @return the language
	 */
	public SleighLanguage getLanguage() {
		return language;
	}

	/**
	 * Get the arithmetic applied by the executor
	 * 
	 * @return the arithmetic
	 */
	public PcodeArithmetic<T> getArithmetic() {
		return arithmetic;
	}

	/**
	 * Get the state bound to this executor
	 * 
	 * @return the state
	 */
	public PcodeExecutorState<T> getState() {
		return state;
	}

	/**
	 * Get the reason for reading state with this executor
	 * 
	 * @return the reason
	 */
	public Reason getReason() {
		return reason;
	}

	/**
	 * Compile and execute a block of Sleigh
	 * 
	 * @param source the Sleigh source
	 */
	public void executeSleigh(String source) {
		PcodeProgram program =
			SleighProgramCompiler.compileProgram(language, "exec", source, PcodeUseropLibrary.NIL);
		execute(program, PcodeUseropLibrary.nil());
	}

	/**
	 * Begin execution of the given program
	 * 
	 * @param program the program, e.g., from an injection, or a decoded instruction
	 * @return the frame
	 */
	public PcodeFrame begin(PcodeProgram program) {
		return begin(program.code, program.useropNames);
	}

	/**
	 * Execute a program using the given library
	 * 
	 * @param program the program, e.g., from an injection, or a decoded instruction
	 * @param library the library
	 * @return the frame
	 */
	public PcodeFrame execute(PcodeProgram program, PcodeUseropLibrary<T> library) {
		return execute(program.code, program.useropNames, library);
	}

	/**
	 * Begin execution of a list of p-code ops
	 * 
	 * @param code the ops
	 * @param useropNames the map of userop numbers to names
	 * @return the frame
	 */
	public PcodeFrame begin(List<PcodeOp> code, Map<Integer, String> useropNames) {
		return new PcodeFrame(language, code, useropNames);
	}

	/**
	 * Execute a list of p-code ops
	 * 
	 * @param code the ops
	 * @param useropNames the map of userop numbers to names
	 * @param library the library of userops
	 * @return the frame
	 */
	public PcodeFrame execute(List<PcodeOp> code, Map<Integer, String> useropNames,
			PcodeUseropLibrary<T> library) {
		PcodeFrame frame = begin(code, useropNames);
		finish(frame, library);
		return frame;
	}

	/**
	 * Finish execution of a frame
	 * 
	 * <p>
	 * TODO: This is not really sufficient for continuation after a break, esp. if that break occurs
	 * within a nested call back into the executor. This would likely become common when using pCode
	 * injection.
	 * 
	 * @param frame the incomplete frame
	 * @param library the library of userops to use
	 */
	public void finish(PcodeFrame frame, PcodeUseropLibrary<T> library) {
		try {
			while (!frame.isFinished()) {
				step(frame, library);
			}
		}
		catch (PcodeExecutionException e) {
			if (e.frame == null) {
				e.frame = frame;
			}
			throw e;
		}
	}

	/**
	 * Handle an unrecognized or unimplemented p-code op
	 * 
	 * @param op the op
	 */
	protected void badOp(PcodeOp op) {
		switch (op.getOpcode()) {
			case PcodeOp.UNIMPLEMENTED:
				throw new LowlevelError(
					"Encountered an unimplemented instruction at " + op.getSeqnum().getTarget());
			default:
				throw new LowlevelError(
					"Unsupported p-code op at " + op.getSeqnum().getTarget() + ": " + op);
		}
	}

	/**
	 * Step one p-code op
	 * 
	 * @param op the op
	 * @param frame the current frame
	 * @param library the library, invoked in case of {@link PcodeOp#CALLOTHER}
	 */
	public void stepOp(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<T> library) {
		OpBehavior b = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		switch (b) {
			case null -> badOp(op);
			case UnaryOpBehavior unOp -> executeUnaryOp(op, unOp);
			case BinaryOpBehavior binOp -> executeBinaryOp(op, binOp);
			default -> {
				switch (op.getOpcode()) {
					case PcodeOp.LOAD -> executeLoad(op);
					case PcodeOp.STORE -> executeStore(op);
					case PcodeOp.BRANCH -> executeBranch(op, frame);
					case PcodeOp.CBRANCH -> executeConditionalBranch(op, frame);
					case PcodeOp.BRANCHIND -> executeIndirectBranch(op, frame);
					case PcodeOp.CALL -> executeCall(op, frame, library);
					case PcodeOp.CALLIND -> executeIndirectCall(op, frame);
					case PcodeOp.CALLOTHER -> executeCallother(op, frame, library);
					case PcodeOp.RETURN -> executeReturn(op, frame);
					default -> badOp(op);
				}
			}
		}
	}

	/**
	 * Step a single p-code op
	 * 
	 * @param frame the frame whose next op to execute
	 * @param library the userop library
	 */
	public void step(PcodeFrame frame, PcodeUseropLibrary<T> library) {
		try {
			stepOp(frame.nextOp(), frame, library);
		}
		catch (PcodeExecutionException e) {
			e.frame = frame;
			throw e;
		}
		catch (Exception e) {
			throw new PcodeExecutionException(e.getMessage(), frame, e);
		}
	}

	/**
	 * Skip a single p-code op
	 * 
	 * @param frame the frame whose next op to skip
	 */
	public void skip(PcodeFrame frame) {
		frame.nextOp();
	}

	/**
	 * Assert that a varnode is constant and get its value as an integer.
	 * 
	 * <p>
	 * Here "constant" means a literal or immediate value. It does not read from the state.
	 * 
	 * @param vn the varnode
	 * @return the value
	 */
	protected int getIntConst(Varnode vn) {
		assert vn.getAddress().getAddressSpace().isConstantSpace();
		return (int) vn.getAddress().getOffset();
	}

	/**
	 * Execute the given unary op
	 * 
	 * @param op the op
	 * @param b the op behavior
	 */
	public void executeUnaryOp(PcodeOp op, UnaryOpBehavior b) {
		Varnode in1Var = op.getInput(0);
		Varnode outVar = op.getOutput();
		T in1 = state.getVar(in1Var, reason);
		T out = arithmetic.unaryOp(op, in1);
		state.setVar(outVar, out);
	}

	/**
	 * Execute the given binary op
	 * 
	 * @param op the op
	 * @param b the op behavior
	 */
	public void executeBinaryOp(PcodeOp op, BinaryOpBehavior b) {
		Varnode in1Var = op.getInput(0);
		Varnode in2Var = op.getInput(1);
		Varnode outVar = op.getOutput();
		T in1 = state.getVar(in1Var, reason);
		T in2 = state.getVar(in2Var, reason);
		T out = arithmetic.binaryOp(op, in1, in2);
		state.setVar(outVar, out);
	}

	/**
	 * Extension point: logic preceding a load
	 * 
	 * @param space the address space to be loaded from
	 * @param offset the offset about to be loaded from
	 * @param size the size in bytes to be loaded
	 */
	protected void checkLoad(AddressSpace space, T offset, int size) {
	}

	/**
	 * Get the address space for a {@link PcodeOp#LOAD load} or {@link PcodeOp#STORE store} op
	 * 
	 * @param op the op
	 * @return the address space (derived from const input 0)
	 */
	protected AddressSpace getLoadStoreSpace(PcodeOp op) {
		int spaceID = getIntConst(op.getInput(0));
		return language.getAddressFactory().getAddressSpace(spaceID);
	}

	/**
	 * Get the offset varnode for a {@link PcodeOp#LOAD load} or {@link PcodeOp#STORE store} op
	 * 
	 * @param op the op
	 * @return the offset varnode (input 1)
	 */
	protected Varnode getLoadStoreOffset(PcodeOp op) {
		return op.getInput(1);
	}

	/**
	 * Execute a load
	 * 
	 * @param op the op
	 */
	public void executeLoad(PcodeOp op) {
		AddressSpace space = getLoadStoreSpace(op);
		Varnode inOffset = getLoadStoreOffset(op);
		T offset = state.getVar(inOffset, reason);
		Varnode outVar = op.getOutput();
		checkLoad(space, offset, outVar.getSize());

		T out = state.getVar(space, offset, outVar.getSize(), true, reason);
		T mod = arithmetic.modAfterLoad(op, space, offset, out);
		state.setVar(outVar, mod);
	}

	/**
	 * Extension point: logic preceding a store
	 * 
	 * @param space the address space to be stored to
	 * @param offset the offset about to be stored to
	 * @param size the size in bytes to be stored
	 */
	protected void checkStore(AddressSpace space, T offset, int size) {
	}

	/**
	 * Get the value varnode for a {@link PcodeOp#STORE store} op
	 * 
	 * @param op the op
	 * @return the value varnode (input 2)
	 */
	protected Varnode getStoreValue(PcodeOp op) {
		return op.getInput(2);
	}

	/**
	 * Execute a store
	 * 
	 * @param op the op
	 */
	public void executeStore(PcodeOp op) {
		AddressSpace space = getLoadStoreSpace(op);
		Varnode inOffset = getLoadStoreOffset(op);
		T offset = state.getVar(inOffset, reason);
		Varnode valVar = getStoreValue(op);
		checkStore(space, offset, valVar.getSize());

		T val = state.getVar(valVar, reason);
		T mod = arithmetic.modBeforeStore(op, space, offset, val);
		state.setVar(space, offset, valVar.getSize(), true, mod);
	}

	/**
	 * Extension point: Called when execution branches to a target address
	 * 
	 * <p>
	 * NOTE: This is <em>not</em> called for the fall-through case
	 * 
	 * @param target the target address
	 */
	protected void branchToAddress(PcodeOp op, Address target) {
	}

	/**
	 * Convert the given offset to the machine's type and delegate to
	 * {@link #branchToOffset(PcodeOp, Object, PcodeFrame)}.
	 * 
	 * <p>
	 * Overriding this allows extension to avert attempted uses of the arithmetic, when it may not
	 * be applicable.
	 * 
	 * @param op the op
	 * @param offset the offset (the new value of the program counter)
	 * @param frame the frame to finish
	 */
	protected void branchToOffset(PcodeOp op, long offset, PcodeFrame frame) {
		branchToOffset(op, arithmetic.fromConst(offset, pcSize), frame);
	}

	/**
	 * Set the state's pc to the given offset and finish the frame
	 * 
	 * <p>
	 * This implements only part of the p-code control flow semantics. An emulator must also
	 * override {@link #branchToAddress(PcodeOp, Address)}, so that it can update its internal
	 * program counter. The emulator could just read the program counter from the state after
	 * <em>every</em> completed frame, but receiving it "out of band" is faster.
	 * 
	 * @param op the op
	 * @param offset the offset (the new value of the program counter)
	 * @param frame the frame to finish
	 */
	protected void branchToOffset(PcodeOp op, T offset, PcodeFrame frame) {
		T truncOff = arithmetic.unaryOp(PcodeOp.COPY, pc.getMinimumByteSize(),
			(int) arithmetic.sizeOf(offset), offset);
		state.setVar(pc, truncOff);
		frame.finishAsBranch();
	}

	/**
	 * Branch internally
	 * 
	 * @param frame the frame
	 * @param relative the relative offset to branch
	 */
	protected void branchInternal(PcodeOp op, PcodeFrame frame, int relative) {
		frame.branch(relative);
	}

	/**
	 * Get the target address of a {@link PcodeOp#BRANCH branch}, {@link PcodeOp#CBRANCH conditional
	 * branch}, or {@link PcodeOp#CALL call} op
	 * 
	 * @param op the op
	 * @return the target address (input 0's address)
	 */
	protected Address getBranchTarget(PcodeOp op) {
		return op.getInput(0).getAddress();
	}

	/**
	 * Perform the actual logic of a branch p-code op
	 * 
	 * <p>
	 * This is a separate method, so that overriding {@link #executeBranch(PcodeOp, PcodeFrame)}
	 * does not implicitly modify {@link #executeConditionalBranch(PcodeOp, PcodeFrame)}.
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	protected void doExecuteBranch(PcodeOp op, PcodeFrame frame) {
		Address target = getBranchTarget(op);
		if (target.isConstantAddress()) {
			branchInternal(op, frame, (int) target.getOffset());
		}
		else {
			branchToOffset(op, target.getOffset(), frame);
			branchToAddress(op, target);
		}
	}

	/**
	 * Execute a branch
	 * 
	 * <p>
	 * This merely defers to {@link #doExecuteBranch(PcodeOp, PcodeFrame)}. To instrument the
	 * operation, override this. To modify or instrument branching in general, override
	 * {@link #doExecuteBranch(PcodeOp, PcodeFrame)},
	 * {@link #branchToOffset(PcodeOp, Object, PcodeFrame)}, and/or
	 * {@link #branchToAddress(PcodeOp, Address)}.
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	public void executeBranch(PcodeOp op, PcodeFrame frame) {
		doExecuteBranch(op, frame);
	}

	/**
	 * Get the predicate varnode of a {@link PcodeOp#CBRANCH conditional branch} op
	 * 
	 * @param op the op
	 * @return the predicate varnode (input 1)
	 */
	protected Varnode getConditionalBranchPredicate(PcodeOp op) {
		return op.getInput(1);
	}

	/**
	 * Execute a conditional branch
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		Varnode condVar = getConditionalBranchPredicate(op);
		T cond = state.getVar(condVar, reason);
		if (arithmetic.isTrue(cond, Purpose.CONDITION)) {
			doExecuteBranch(op, frame);
		}
	}

	/**
	 * Get the target of an {@link PcodeOp#BRANCHIND indirect branch}, {@link PcodeOp#CALLIND
	 * indirect call}, or {@link PcodeOp#RETURN return} op.
	 * 
	 * @param op the op
	 * @return the target varnode (input 0)
	 */
	protected Varnode getIndirectBranchTarget(PcodeOp op) {
		return op.getInput(0);
	}

	/**
	 * Perform the actual logic of an indirect branch p-code op
	 * 
	 * <p>
	 * This is a separate method, so that overriding
	 * {@link #executeIndirectBranch(PcodeOp, PcodeFrame)} does not implicitly modify
	 * {@link #executeIndirectCall(PcodeOp, PcodeFrame)} and
	 * {@link #executeReturn(PcodeOp, PcodeFrame)}.
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	protected void doExecuteIndirectBranch(PcodeOp op, PcodeFrame frame) {
		T offset = state.getVar(getIndirectBranchTarget(op), reason);
		branchToOffset(op, offset, frame);

		long concrete = arithmetic.toLong(offset, Purpose.BRANCH);
		Address target = op.getSeqnum().getTarget().getNewAddress(concrete, true);
		branchToAddress(op, target);
	}

	/**
	 * Execute an indirect branch
	 * 
	 * <p>
	 * This merely defers to {@link #doExecuteIndirectBranch(PcodeOp, PcodeFrame)}. To instrument
	 * the operation, override this. To modify or instrument indirect branching in general, override
	 * {@link #doExecuteIndirectBranch(PcodeOp, PcodeFrame)}.
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	public void executeIndirectBranch(PcodeOp op, PcodeFrame frame) {
		doExecuteIndirectBranch(op, frame);
	}

	/**
	 * Execute a call
	 * 
	 * @param op the op
	 * @param frame the frame
	 * @param library the userop library
	 */
	public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<T> library) {
		Address target = getBranchTarget(op);
		branchToOffset(op, target.getOffset(), frame);
		branchToAddress(op, target);
	}

	/**
	 * Execute an indirect call
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	public void executeIndirectCall(PcodeOp op, PcodeFrame frame) {
		doExecuteIndirectBranch(op, frame);
	}

	/**
	 * Get the name of a userop
	 * 
	 * @param opNo the userop number
	 * @param frame the frame
	 * @return the name, or null if it is not defined
	 */
	public String getUseropName(int opNo, PcodeFrame frame) {
		if (opNo < language.getNumberOfUserDefinedOpNames()) {
			return language.getUserDefinedOpName(opNo);
		}
		return frame.getUseropName(opNo);
	}

	/**
	 * Get the userop number of a {@link PcodeOp#CALLOTHER callother} op
	 * 
	 * @param op the op
	 * @return the userop number (const input 0)
	 */
	protected int getCallotherOpNumber(PcodeOp op) {
		return getIntConst(op.getInput(0));
	}

	/**
	 * Execute a userop call
	 * 
	 * @param op the op
	 * @param frame the frame
	 * @param library the library of userops
	 */
	public void executeCallother(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<T> library) {
		int opNo = getCallotherOpNumber(op);
		String opName = getUseropName(opNo, frame);
		if (opName == null) {
			throw new AssertionError("Pcode userop " + opNo + " is not defined");
		}
		PcodeUseropDefinition<T> opDef = library.getUserops().get(opName);
		if (opDef != null) {
			opDef.execute(this, library, op);
			return;
		}
		onMissingUseropDef(op, frame, opName, library);
	}

	/**
	 * Extension point: Behavior when a userop definition was not found in the library
	 * 
	 * <p>
	 * The default behavior is to throw a {@link SleighLinkException}.
	 * 
	 * @param op the op
	 * @param frame the frame
	 * @param opName the name of the p-code userop
	 * @param library the library
	 */
	protected void onMissingUseropDef(PcodeOp op, PcodeFrame frame, String opName,
			PcodeUseropLibrary<T> library) {
		throw new SleighLinkException(
			"Sleigh userop '" + opName + "' is not in the library " + library);
	}

	/**
	 * Execute a return
	 * 
	 * @param op the op
	 * @param frame the frame
	 */
	public void executeReturn(PcodeOp op, PcodeFrame frame) {
		doExecuteIndirectBranch(op, frame);
	}
}
