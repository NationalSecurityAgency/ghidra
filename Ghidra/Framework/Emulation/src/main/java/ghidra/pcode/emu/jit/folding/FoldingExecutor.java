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
package ghidra.pcode.emu.jit.folding;

import ghidra.lifecycle.Internal;
import ghidra.pcode.emu.jit.JitPassage.ExitPcodeOp;
import ghidra.pcode.emu.jit.JitPassage.Operand;
import ghidra.pcode.emu.jit.decode.DecoderForOnePassage;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeUseropLibrary.PcodeUseropDefinition;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An executor that records and/or removes folded constants into a passage decoder.
 */
@Internal
public class FoldingExecutor extends PcodeExecutor<MaskedBytes> {
	final DecoderForOnePassage passage;
	protected final FoldedState state; // My own copy of more specific type

	public FoldingExecutor(DecoderForOnePassage passage, FoldedState state) {
		this.passage = passage;
		this.state = state;
		super(passage.decoder.thread.getLanguage(), state == null ? null : state.getArithmetic(),
			state, Reason.EXECUTE_READ);
	}

	@Override
	public FoldedState getState() {
		return state;
	}

	/**
	 * Interpret the given program with the passage decoder's userop library
	 * 
	 * @param program the p-code to interpret
	 */
	public void execute(PcodeProgram program) {
		execute(program, passage.library());
	}

	/**
	 * Record (or remove) a folded constant from the passage
	 * <p>
	 * If the value is not <em>completely</em> known, we do not record it. We may invalidate it,
	 * actually. (It remains in the state, but we don't record this specific operand instance as
	 * foldable.)
	 * 
	 * @param op the op whose operand is being considered
	 * @param index the position of the operand, -1 for output, otherwise the input operand index
	 * @param value the value observed
	 * @return
	 */
	MaskedBytes recordFolded(PcodeOp op, int index, MaskedBytes value) {
		// No sense in recording the degenerate case
		Varnode operand = index == -1 ? op.getOutput() : op.getInput(index);
		if (operand.isConstant()) {
			return value;
		}

		byte[] c = FoldedArithmetic.concreteOrNull(value);
		Operand key = new Operand(op, index);
		if (c != null) {
			passage.folded.put(key, c);
		}
		else {
			passage.folded.remove(key);
		}
		return value;
	}

	@Override
	public void executeUnaryOp(PcodeOp op, UnaryOpBehavior b) {
		if (state == null) {
			return;
		}
		Varnode in1Var = op.getInput(0);
		Varnode outVar = op.getOutput();
		MaskedBytes in1 = recordFolded(op, 0, state.getVar(in1Var, reason));
		MaskedBytes out = recordFolded(op, -1, arithmetic.unaryOp(op, in1));
		state.setVar(outVar, out);
	}

	@Override
	public void executeBinaryOp(PcodeOp op, BinaryOpBehavior b) {
		if (state == null) {
			return;
		}
		Varnode in1Var = op.getInput(0);
		Varnode in2Var = op.getInput(1);
		Varnode outVar = op.getOutput();
		MaskedBytes in1 = recordFolded(op, 0, state.getVar(in1Var, reason));
		MaskedBytes in2 = recordFolded(op, 1, state.getVar(in2Var, reason));
		MaskedBytes out = recordFolded(op, -1, arithmetic.binaryOp(op, in1, in2));
		state.setVar(outVar, out);
	}

	@Override
	public void executeLoad(PcodeOp op) {
		if (state == null) {
			return;
		}
		super.executeLoad(op);
	}

	@Override
	protected void afterLoad(PcodeOp op, AddressSpace space, MaskedBytes offset, int size,
			MaskedBytes value) {
		recordFolded(op, 1, offset);
		// LATER: Treat near loads as constant?
		// LATER: If so, would need to add to ranges causing translation cache invalidation
	}

	@Override
	public void executeStore(PcodeOp op) {
		if (state == null) {
			return;
		}
		super.executeStore(op);
	}

	@Override
	protected void afterStore(PcodeOp op, AddressSpace space, MaskedBytes offset, int size,
			MaskedBytes value) {
		recordFolded(op, 1, offset);
	}

	@Override
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		if (state == null) {
			return;
		}
		if (op instanceof ExitPcodeOp) {
			return;
		}
		Varnode condVar = getConditionalBranchPredicate(op);
		recordFolded(op, OPIDX_CBRANCH_PRED, state.getVar(condVar, reason));
	}

	/**
	 * This attempts to resolve a folded constant address. If it succeeds, it delegates to
	 * {@link #branchToAddress(PcodeOp, Address)}. Otherwise, it delegates to
	 * {@link #doExecuteIndirectBranch(PcodeOp, PcodeFrame)}.
	 * 
	 * @param op the p-code op
	 * @param frame the frame
	 */
	protected void doFoldIndirectBranch(PcodeOp op, PcodeFrame frame) {
		if (state == null) {
			doExecuteIndirectBranch(op, frame);
			return;
		}
		MaskedBytes offset = recordFolded(op, OPIDX_BRANCH_TARGET,
			state.getVar(getIndirectBranchTarget(op), reason));
		// Don't call branchToOffset
		try {
			long concrete = arithmetic.toLong(offset, Purpose.BRANCH);
			Address target = op.getSeqnum().getTarget().getNewAddress(concrete, true);
			branchToAddress(op, checkInjectedTarget(target));
		}
		catch (ConcretionError e) {
			doExecuteIndirectBranch(op, frame);
		}
	}

	@Override
	public void executeIndirectBranch(PcodeOp op, PcodeFrame frame) {
		doFoldIndirectBranch(op, frame);
	}

	@Override
	public void executeIndirectCall(PcodeOp op, PcodeFrame frame) {
		doFoldIndirectBranch(op, frame);
	}

	@Override
	public void executeReturn(PcodeOp op, PcodeFrame frame) {
		doFoldIndirectBranch(op, frame);
	}

	protected PcodeUseropDefinition<?> getUserop(PcodeOp op, PcodeFrame frame,
			PcodeUseropLibrary<?> library) {
		int opNo = getCallotherOpNumber(op);
		String opName = getUseropName(opNo, frame);
		if (opName == null) {
			return null;
		}
		return library.getUserops().get(opName);
	}

	@Override
	public void executeCallother(PcodeOp op, PcodeFrame frame,
			PcodeUseropLibrary<MaskedBytes> library) {
		if (state == null) {
			super.executeCallother(op, frame, library);
			return;
		}

		PcodeUseropDefinition<?> opDef = getUserop(op, frame, library);
		if (opDef == null || opDef.canInlinePcode()) {
			// null case: Let super handle the error
			// inline case: Let the constant analysis examine the inlined ops
			super.executeCallother(op, frame, library);
			return;
		}

		// We can still use folded inputs, even if the userop is not itself foldable
		int n = op.getNumInputs();
		boolean tryFoldOutput = true;
		for (int i = 0; i < n; i++) {
			MaskedBytes in = recordFolded(op, i, state.getVar(op.getInput(i), reason));
			if (FoldedArithmetic.concreteOrNull(in) == null) {
				tryFoldOutput = false;
			}
		}
		if (!opDef.isFunctional()) {
			// Userop has carte blanche, so erase all assumptions about constants :(
			state.clear();
			return;
		}
		Varnode outVar = op.getOutput();
		if (outVar != null) {
			if (tryFoldOutput && !opDef.hasSideEffects() && !opDef.modifiesContext()) {
				super.executeCallother(op, frame, library);
				recordFolded(op, -1, state.getVar(outVar, Reason.INSPECT));
			}
			// It has an output that we didn't even try to fold
			state.setVar(outVar, MaskedBytes.ofUnknown(outVar.getSize()));
			passage.folded.remove(new Operand(op, -1));
		}
	}
}
