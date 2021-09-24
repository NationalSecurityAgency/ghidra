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
import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.SleighUseropLibrary.SleighUseropDefinition;
import ghidra.pcode.opbehavior.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeExecutor<T> {
	protected final SleighLanguage language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final PcodeExecutorStatePiece<T, T> state;
	protected final Register pc;
	protected final int pointerSize;

	public PcodeExecutor(SleighLanguage language, PcodeArithmetic<T> arithmetic,
			PcodeExecutorStatePiece<T, T> state) {
		this.language = language;
		this.arithmetic = arithmetic;
		this.state = state;

		this.pc = language.getProgramCounter();
		this.pointerSize = language.getDefaultSpace().getPointerSize();
	}

	/**
	 * Get the executor's SLEIGH language (processor model)
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
	public PcodeExecutorStatePiece<T, T> getState() {
		return state;
	}

	public void executeLine(String line) {
		PcodeProgram program = SleighProgramCompiler.compileProgram(language,
			"line", List.of(line + ";"), SleighUseropLibrary.NIL);
		execute(program, SleighUseropLibrary.nil());
	}

	public PcodeFrame begin(PcodeProgram program) {
		return begin(program.code, program.useropNames);
	}

	public PcodeFrame execute(PcodeProgram program, SleighUseropLibrary<T> library) {
		return execute(program.code, program.useropNames, library);
	}

	public PcodeFrame begin(List<PcodeOp> code, Map<Integer, String> useropNames) {
		return new PcodeFrame(language, code, useropNames);
	}

	public PcodeFrame execute(List<PcodeOp> code, Map<Integer, String> useropNames,
			SleighUseropLibrary<T> library) {
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
	public void finish(PcodeFrame frame, SleighUseropLibrary<T> library) {
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

	public void stepOp(PcodeOp op, PcodeFrame frame, SleighUseropLibrary<T> library) {
		OpBehavior b = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		if (b == null) {
			throw new LowlevelError("Unsupported pcode op" + op);
		}
		if (b instanceof UnaryOpBehavior) {
			executeUnaryOp(op, (UnaryOpBehavior) b);
			return;
		}
		if (b instanceof BinaryOpBehavior) {
			executeBinaryOp(op, (BinaryOpBehavior) b);
			return;
		}
		switch (op.getOpcode()) {
			case PcodeOp.LOAD:
				executeLoad(op);
				return;
			case PcodeOp.STORE:
				executeStore(op);
				return;
			case PcodeOp.BRANCH:
				executeBranch(op, frame);
				return;
			case PcodeOp.CBRANCH:
				executeConditionalBranch(op, frame);
				return;
			case PcodeOp.BRANCHIND:
				executeIndirectBranch(op, frame);
				return;
			case PcodeOp.CALL:
				executeCall(op, frame);
				return;
			case PcodeOp.CALLIND:
				executeIndirectCall(op, frame);
				return;
			case PcodeOp.CALLOTHER:
				executeCallother(op, frame, library);
				return;
			case PcodeOp.RETURN:
				executeReturn(op, frame);
				return;
			default:
				throw new LowlevelError("Unsupported op " + op);
		}
	}

	public void step(PcodeFrame frame, SleighUseropLibrary<T> library) {
		try {
			stepOp(frame.nextOp(), frame, library);
		}
		catch (PcodeExecutionException e) {
			e.frame = frame;
			throw e;
		}
		catch (Exception e) {
			throw new PcodeExecutionException("Exception during pcode execution", frame, e);
		}
	}

	protected int getIntConst(Varnode vn) {
		assert vn.getAddress().getAddressSpace().isConstantSpace();
		return (int) vn.getAddress().getOffset();
	}

	public void executeUnaryOp(PcodeOp op, UnaryOpBehavior b) {
		Varnode in1Var = op.getInput(0);
		Varnode outVar = op.getOutput();
		T in1 = state.getVar(in1Var);
		T out = arithmetic.unaryOp(b, outVar.getSize(),
			in1Var.getSize(), in1);
		state.setVar(outVar, out);
	}

	public void executeBinaryOp(PcodeOp op, BinaryOpBehavior b) {
		Varnode in1Var = op.getInput(0);
		Varnode in2Var = op.getInput(1);
		Varnode outVar = op.getOutput();
		T in1 = state.getVar(in1Var);
		T in2 = state.getVar(in2Var);
		T out = arithmetic.binaryOp(b, outVar.getSize(),
			in1Var.getSize(), in1, in2Var.getSize(), in2);
		state.setVar(outVar, out);
	}

	public void executeLoad(PcodeOp op) {
		int spaceID = getIntConst(op.getInput(0));
		AddressSpace space = language.getAddressFactory().getAddressSpace(spaceID);
		T offset = state.getVar(op.getInput(1));
		Varnode outvar = op.getOutput();
		T out = state.getVar(space, offset, outvar.getSize(), true);
		state.setVar(outvar, out);
	}

	public void executeStore(PcodeOp op) {
		int spaceID = getIntConst(op.getInput(0));
		AddressSpace space = language.getAddressFactory().getAddressSpace(spaceID);
		T offset = state.getVar(op.getInput(1));
		Varnode valVar = op.getInput(2);
		T val = state.getVar(valVar);
		state.setVar(space, offset, valVar.getSize(), true, val);
	}

	/**
	 * Called when execution branches to a target address
	 * 
	 * <p>
	 * NOTE: This is <em>not</em> called for the fall-through case
	 * 
	 * @param target the target address
	 */
	protected void branchToAddress(Address target) {
		// Extension point
	}

	protected void branchToOffset(T offset, PcodeFrame frame) {
		state.setVar(pc.getAddressSpace(), pc.getOffset(), (pc.getBitLength() + 7) / 8, false,
			offset);
		frame.finishAsBranch();
	}

	public void executeBranch(PcodeOp op, PcodeFrame frame) {
		Address target = op.getInput(0).getAddress();
		if (target.isConstantAddress()) {
			frame.branch((int) target.getOffset());
		}
		else {
			branchToOffset(arithmetic.fromConst(target.getOffset(), pointerSize), frame);
			branchToAddress(target);
		}
	}

	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		Varnode condVar = op.getInput(1);
		T cond = state.getVar(condVar);
		if (arithmetic.isTrue(cond)) {
			executeBranch(op, frame);
		}
	}

	public void executeIndirectBranch(PcodeOp op, PcodeFrame frame) {
		T offset = state.getVar(op.getInput(0));
		branchToOffset(offset, frame);

		long concrete = arithmetic.toConcrete(offset).longValue();
		Address target = op.getSeqnum().getTarget().getNewAddress(concrete);
		branchToAddress(target);
	}

	public void executeCall(PcodeOp op, PcodeFrame frame) {
		Address target = op.getInput(0).getAddress();
		branchToOffset(arithmetic.fromConst(target.getOffset(), pointerSize), frame);
		branchToAddress(target);
	}

	public void executeIndirectCall(PcodeOp op, PcodeFrame frame) {
		executeIndirectBranch(op, frame);
	}

	public String getUseropName(int opNo, PcodeFrame frame) {
		if (opNo < language.getNumberOfUserDefinedOpNames()) {
			return language.getUserDefinedOpName(opNo);
		}
		return frame.getUseropName(opNo);
	}

	public void executeCallother(PcodeOp op, PcodeFrame frame, SleighUseropLibrary<T> library) {
		int opNo = getIntConst(op.getInput(0));
		String opName = getUseropName(opNo, frame);
		if (opName == null) {
			throw new AssertionError(
				"Pcode userop " + opNo + " is not defined");
		}
		SleighUseropDefinition<T> opDef = library.getUserops().get(opName);
		if (opDef == null) {
			throw new SleighLinkException(
				"Sleigh userop '" + opName + "' is not in the library " + library);
		}
		opDef.execute(state, op.getOutput(), List.of(op.getInputs()).subList(1, op.getNumInputs()));
	}

	public void executeReturn(PcodeOp op, PcodeFrame frame) {
		executeIndirectBranch(op, frame);
	}
}
