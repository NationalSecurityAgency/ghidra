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
package ghidra.pcode.emu.jit.analysis;

import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

import ghidra.pcode.emu.jit.JitPassage;
import ghidra.pcode.emu.jit.JitPassage.*;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.*;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.opbehavior.BinaryOpBehavior;
import ghidra.pcode.opbehavior.UnaryOpBehavior;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A modification to {@link PcodeExecutor} that is specialized for the per-block data flow analysis.
 * <p>
 * Normally, the p-code executor follows all of the control-flow branching, as you would expect in
 * the interpretation-based p-code emulator. For analysis, we do not intend to actually follow
 * branches. These should only ever occur at the end of a basic block, anyway.
 * <p>
 * We do record the branch ops into the graph as {@link JitOp op nodes}. A conditional branch
 * naturally participates in the data flow, as it uses the definition of its predicate varnode.
 * Similarly, indirect branches use the definitions of their target varnodes. Direct branch
 * operations are also added to the use-def graph, even though they do not use any variable
 * definition. Architecturally, the code generator emits JVM bytecode from the op nodes in the
 * use-def graph. For that to work, every p-code op must be entered into it. For bookkeeping, and
 * because the code generator will need them, we look up the {@link Branch} records created by the
 * passage decoder and store them in their respective branch op nodes.
 * <p>
 * This is all accomplished by overriding {@link #executeBranch(PcodeOp, PcodeFrame)} and similar
 * branch execution methods. Additionally, we override {@link #badOp(PcodeOp)} and
 * {@link #onMissingUseropDef(PcodeOp, PcodeFrame, String, PcodeUseropLibrary)}, because the
 * inherited implementations will throw exceptions. We need not throw an exception until/unless we
 * reach such bad code a run time. So, we enter them into the use-def graph as op nodes from which
 * we later generate the code to throw the exception.
 * <p>
 * Much of the "re-writes" from constant folding occurs here. Instead of actually replacing the
 * p-code ops, we wrap them in a different {@link JitOp} than usual. For outputs that get folded, we
 * re-write to a {@link JitCopy}. For an folded inputs, we keep the op but replace those inputs with
 * constants, as if they had been literals. The result breaks the use-def graph apart, which will
 * permit op-use analysis to remove the actual folded computations, among other unneeded things.
 */
class JitDataFlowExecutor extends PcodeExecutor<JitVal> {
	private final JitDataFlowModel dfm;
	private final JitPassage passage;
	private final Map<PcodeOp, PBranch> branches;
	private final BytesPcodeArithmetic bytes;

	/**
	 * Construct an executor from the given context
	 * 
	 * @param context the analysis context, namely to get the branches recorded by the passage
	 *            decoder
	 * @param dfm the data-flow model whose use-def graph to populate
	 * @param state the executor state, which tracks varnode definitions during execution
	 */
	protected JitDataFlowExecutor(JitAnalysisContext context, JitDataFlowModel dfm,
			PcodeExecutorState<JitVal> state) {
		super(context.getLanguage(), dfm.getArithmetic(), state, Reason.EXECUTE_READ);
		this.dfm = dfm;
		this.passage = context.getPassage();
		this.branches = passage.getBranches();
		this.bytes = BytesPcodeArithmetic.forLanguage(state.getLanguage());
	}

	/**
	 * Record a branch or call op into the use-def graph
	 * <p>
	 * We do not need to compute the branch target, because that op was already computed by the
	 * passage decoder. Past attempts to perform that computation here failed when dealing with
	 * injects and inlined p-code userops. It is much easier to let the decoder do it, because it
	 * has a copy of the original p-code. That op is recorded in the {@link Branch} for this op, so
	 * just look it up.
	 * 
	 * @param op the op
	 */
	protected void recordBranch(PcodeOp op) {
		RBranch branch = (RBranch) Objects.requireNonNull(branches.get(op));
		dfm.notifyOp(new JitBranchOp(op, branch));
	}

	/**
	 * Record a conditional branch op into the use-def graph
	 * <p>
	 * While we can lookup the {@link Branch} target as in
	 * {@link #executeBranch(PcodeOp, PcodeFrame)}, we must still obtain the predicate's definition
	 * and use it.
	 * 
	 * @param op the op
	 */
	protected void recordConditionalBranch(PcodeOp op) {
		RBranch branch = (RBranch) Objects.requireNonNull(branches.get(op));
		final JitVal cond;
		if (op instanceof ExitPcodeOp) {
			cond = JitFailVal.INSTANCE;
		}
		else {
			Varnode condVar = getConditionalBranchPredicate(op);
			cond = state.getVar(condVar, reason);
		}

		if (cond instanceof JitConstVal cc) {
			if (cc.value().equals(BigInteger.ZERO)) {
				dfm.notifyOp(new JitNopOp(op));
			}
			else {
				dfm.notifyOp(new JitBranchOp(op, branch));
			}
		}
		else {
			dfm.notifyOp(new JitCBranchOp(op, branch, cond));
		}
	}

	/**
	 * Record an indirect branch op into the use-def graph
	 * <p>
	 * The {@link IndBranch} will have the target decode context, but the address is dynamic. We
	 * have to obtain the target varnode's definition and use it.
	 * 
	 * @param op the op
	 */
	protected void recordIndirectBranch(PcodeOp op) {
		Varnode offVar = getIndirectBranchTarget(op);
		JitVal offset = state.getVar(offVar, reason);
		RBranch branch = (RBranch) Objects.requireNonNull(branches.get(op));
		if (offset instanceof JitConstVal) {
			dfm.notifyOp(new JitBranchOp(op, branch));
		}
		else {
			dfm.notifyOp(new JitBranchIndOp(op, offset, branch));
		}
	}

	@Override
	public void executeBranch(PcodeOp op, PcodeFrame frame) {
		recordBranch(op);
	}

	@Override
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		byte[] foldedCond = passage.getFoldedOperand(op, OPIDX_CBRANCH_PRED);
		if (foldedCond == null) {
			recordConditionalBranch(op);
		}
		else if (bytes.isTrue(foldedCond, Purpose.CONDITION)) {
			recordBranch(op);
		}
		else {
			dfm.notifyOp(new JitNopOp(op));
		}
	}

	@Override
	protected void doExecuteIndirectBranch(PcodeOp op, PcodeFrame frame) {
		byte[] foldedTarget = passage.getFoldedOperand(op, OPIDX_BRANCH_TARGET);
		if (foldedTarget == null) {
			recordIndirectBranch(op);
		}
		else {
			recordBranch(op);
		}
	}

	@Override
	public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<JitVal> library) {
		recordBranch(op);
	}

	/**
	 * We examine and apply folding here so that re-written ops are entered into the use-def graph
	 * for further analysis.
	 * <p>
	 * Were we to instead apply this during code generation, we'd miss the opportunity to remove
	 * unnecessary ops.
	 * 
	 * @param op the p-code op whose output to examine
	 * @return true if the output can be folded
	 */
	boolean tryNotifyFoldedOutput(PcodeOp op) {
		Varnode outVar = op.getOutput();
		byte[] foldedOut = passage.getFoldedOperand(op, -1);
		if (foldedOut != null) {
			JitOutVar out = dfm.generateOutVar(op.getOutput());
			JitVal outConst = arithmetic.fromConst(foldedOut);
			dfm.notifyOp(new JitCopyOp(op, out, outConst));
			/**
			 * Don't just put the const into the state. Put the re-written copy's output. Otherwise,
			 * the copy op will not get marked as "used" by block retirement, intervening
			 * callothers, etc. Ops that use the result as input will have those inputs re-written,
			 * anyway. This re-written op may still be removed if that output is never actually
			 * used.
			 */
			state.setVar(outVar, out);
			return true;
		}
		return false;
	}

	/**
	 * We examine and apply input folding here so that computed outputs resulting in folded
	 * constants no longer appear "used," permitting their removal by later analysis.
	 * <p>
	 * Were we to instead apply this during code generation, we'd miss the opportunity to remove the
	 * ops computing the folded constant.
	 * 
	 * @param op the p-code op
	 * @param index the input operand index (0-up)
	 * @return true if the input can be folded
	 */
	JitVal getFoldedOrVarInput(PcodeOp op, int index) {
		byte[] folded = passage.getFoldedOperand(op, index);
		if (folded != null) {
			return arithmetic.fromConst(folded);
		}
		return state.getVar(op.getInput(index), reason);
	}

	@Override
	public void executeUnaryOp(PcodeOp op, UnaryOpBehavior b) {
		if (tryNotifyFoldedOutput(op)) {
			return;
		}
		JitVal in1 = getFoldedOrVarInput(op, 0);
		JitVal out = arithmetic.unaryOp(op, in1);
		Varnode outVar = op.getOutput();
		state.setVar(outVar, out);
	}

	@Override
	public void executeBinaryOp(PcodeOp op, BinaryOpBehavior b) {
		if (tryNotifyFoldedOutput(op)) {
			return;
		}
		JitVal in1 = getFoldedOrVarInput(op, 0);
		JitVal in2 = getFoldedOrVarInput(op, 1);
		JitVal out = arithmetic.binaryOp(op, in1, in2);
		Varnode outVar = op.getOutput();
		state.setVar(outVar, out);
	}

	// Callother is handled in JitDataFlowUseropLibrary.WrappedUseropDefinition

	@Override
	public void executeLoad(PcodeOp op) {
		/**
		 * LATER: Try folding LOAD, but only on addresses that are near this instruction. That is a
		 * heuristic for likely constant memory, e.g., a constant pool in ARM. That loaded range
		 * would need to be considered for invalidation in the same manner as any range in the
		 * decoded passage.
		 */
		AddressSpace space = getLoadStoreSpace(op);
		// If folded, both breaks up the use-def graph and permits gen to use direct access.
		JitVal offset = getFoldedOrVarInput(op, OPIDX_DEREF_OFFSET);
		Varnode outVar = op.getOutput();
		beforeLoad(op, space, offset, outVar.getSize());

		JitVal out = state.getVar(space, offset, outVar.getSize(), true, reason);
		JitVal mod = arithmetic.modAfterLoad(op, space, offset, out);
		state.setVar(outVar, mod);
		afterLoad(op, space, offset, outVar.getSize(), mod);
	}

	@Override
	public void executeStore(PcodeOp op) {
		AddressSpace space = getLoadStoreSpace(op);
		JitVal offset = getFoldedOrVarInput(op, OPIDX_DEREF_OFFSET);
		// If folded, just breaks up the use-def graph
		Varnode valVar = getStoreValue(op); // for size
		JitVal val = getFoldedOrVarInput(op, OPIDX_STORE_VALUE);
		JitVal mod = arithmetic.modBeforeStore(op, space, offset, val);
		beforeStore(op, space, offset, valVar.getSize(), mod);

		state.setVar(space, offset, valVar.getSize(), true, mod);
		afterStore(op, space, offset, valVar.getSize(), mod);
	}

	@Override
	protected void badOp(PcodeOp op) {
		dfm.notifyOp(JitOp.stubOp(op));
	}

	@Override
	protected void onMissingUseropDef(PcodeOp op, PcodeFrame frame, String opName,
			PcodeUseropLibrary<JitVal> library) {
		dfm.notifyOp(new JitCallOtherMissingOp(op, opName));
	}
}
