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

import ghidra.pcode.error.LowlevelError;
import ghidra.pcode.exec.SleighUseropLibrary.SleighUseropDefinition;
import ghidra.pcode.opbehavior.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PcodeExecutor<T> {
	protected final Language language;
	protected final PcodeArithmetic<T> arithmetic;
	protected final PcodeExecutorStatePiece<T, T> state;
	protected final Register pc;
	protected final int pointerSize;

	public PcodeExecutor(Language language, PcodeArithmetic<T> arithmetic,
			PcodeExecutorStatePiece<T, T> state) {
		this.language = language;
		this.arithmetic = arithmetic;
		this.state = state;

		this.pc = language.getProgramCounter();
		this.pointerSize = language.getDefaultSpace().getPointerSize();
	}

	public void execute(SleighProgram program, SleighUseropLibrary<T> library) {
		execute(program.code, program.useropNames, library);
	}

	public void execute(List<PcodeOp> code, Map<Integer, String> useropNames,
			SleighUseropLibrary<T> library) {
		PcodeFrame frame = new PcodeFrame(code);
		while (!frame.isFinished()) {
			step(frame, useropNames, library);
		}
	}

	public void stepOp(PcodeOp op, PcodeFrame frame, Map<Integer, String> useropNames,
			SleighUseropLibrary<T> library) {
		OpBehavior b = OpBehaviorFactory.getOpBehavior(op.getOpcode());
		if (b == null) {
			throw new LowlevelError("Unsupported pcode op" + op);
		}
		if (b instanceof UnaryOpBehavior) {
			Varnode in1Var = op.getInput(0);
			Varnode outVar = op.getOutput();
			T in1 = state.getVar(in1Var);
			T out =
				arithmetic.unaryOp((UnaryOpBehavior) b, outVar.getSize(), in1Var.getSize(), in1);
			state.setVar(outVar, out);
			return;
		}
		if (b instanceof BinaryOpBehavior) {
			Varnode in1Var = op.getInput(0);
			Varnode in2Var = op.getInput(1);
			Varnode outVar = op.getOutput();
			T in1 = state.getVar(in1Var);
			T in2 = state.getVar(in2Var);
			T out = arithmetic.binaryOp((BinaryOpBehavior) b, outVar.getSize(), in1Var.getSize(),
				in1, in2);
			state.setVar(outVar, out);
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
				executeCallother(op, useropNames, library);
				return;
			case PcodeOp.RETURN:
				executeReturn(op, frame);
				return;
			default:
				throw new LowlevelError("Unsupported op " + op);
		}
	}

	public void step(PcodeFrame frame, Map<Integer, String> useropNames,
			SleighUseropLibrary<T> library) {
		stepOp(frame.nextOp(), frame, useropNames, library);
	}

	protected int getIntConst(Varnode vn) {
		assert vn.getAddress().getAddressSpace().isConstantSpace();
		return (int) vn.getAddress().getOffset();
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

	protected void branchTo(T offset, PcodeFrame frame) {
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
			branchTo(arithmetic.fromConst(target.getOffset(), pointerSize), frame);
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
		branchTo(offset, frame);
	}

	public void executeCall(PcodeOp op, PcodeFrame frame) {
		Address target = op.getInput(0).getAddress();
		branchTo(arithmetic.fromConst(target.getOffset(), pointerSize), frame);
	}

	public void executeIndirectCall(PcodeOp op, PcodeFrame frame) {
		executeIndirectBranch(op, frame);
	}

	public void executeCallother(PcodeOp op, Map<Integer, String> useropNames,
			SleighUseropLibrary<T> library) {
		int opNo = getIntConst(op.getInput(0));
		String opName = useropNames.get(opNo);
		if (opName == null) {
			throw new AssertionError(
				"Pcode userop " + opNo + " is not defined");
		}
		SleighUseropDefinition<T> opDef = library.getUserops().get(opName);
		if (opDef == null) {
			throw new SleighLinkException(
				"Sleigh userop " + opName + " is not in the library " + library);
		}
		opDef.execute(state, op.getOutput(), List.of(op.getInputs()).subList(1, op.getNumInputs()));
	}

	public void executeReturn(PcodeOp op, PcodeFrame frame) {
		executeIndirectBranch(op, frame);
	}
}
