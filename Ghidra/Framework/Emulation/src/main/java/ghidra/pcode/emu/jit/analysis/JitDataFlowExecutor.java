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

import java.util.Map;
import java.util.Objects;

import ghidra.pcode.emu.jit.JitPassage.Branch;
import ghidra.pcode.emu.jit.JitPassage.IndBranch;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A modification to {@link PcodeExecutor} that is specialized for the per-block data flow analysis.
 * 
 * <p>
 * Normally, the p-code executor follows all of the control-flow branching, as you would expect in
 * the interpretation-based p-code emulator. For analysis, we do not intend to actually follow
 * branches. These should only ever occur at the end of a basic block, anyway.
 * 
 * <p>
 * We do record the branch ops into the graph as {@link JitOp op nodes}. A conditional branch
 * naturally participates in the data flow, as it uses the definition of its predicate varnode.
 * Similarly, indirect branches use the definitions of their target varnodes. Direct branch
 * operations are also added to the use-def graph, even though they do not use any variable
 * definition. Architecturally, the code generator emits JVM bytecode from the op nodes in the
 * use-def graph. For that to work, every p-code op must be entered into it. For bookkeeping, and
 * because the code generator will need them, we look up the {@link Branch} records created by the
 * passage decoder and store them in their respective branch op nodes.
 * 
 * <p>
 * This is all accomplished by overriding {@link #executeBranch(PcodeOp, PcodeFrame)} and similar
 * branch execution methods. Additionally, we override {@link #badOp(PcodeOp)} and
 * {@link #onMissingUseropDef(PcodeOp, PcodeFrame, String, PcodeUseropLibrary)}, because the
 * inherited implementations will throw exceptions. We need not throw an exception until/unless we
 * reach such bad code a run time. So, we enter them into the use-def graph as op nodes from which
 * we later generate the code to throw the exception.
 */
class JitDataFlowExecutor extends PcodeExecutor<JitVal> {
	private final JitDataFlowModel dfm;
	private final Map<PcodeOp, Branch> branches;

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
		this.branches = context.getPassage().getBranches();
	}

	/**
	 * Record a branch or call op into the use-def graph
	 * 
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
		Branch branch = Objects.requireNonNull(branches.get(op));
		dfm.notifyOp(new JitBranchOp(op, branch));
	}

	/**
	 * Record a conditional branch op into the use-def graph
	 * 
	 * <p>
	 * While we can lookup the {@link Branch} target as in
	 * {@link #executeBranch(PcodeOp, PcodeFrame)}, we must still obtain the predicate's definition
	 * and use it.
	 * 
	 * @param op the op
	 */
	protected void recordConditionalBranch(PcodeOp op) {
		Branch branch = Objects.requireNonNull(branches.get(op));
		Varnode condVar = getConditionalBranchPredicate(op);
		JitVal cond = state.getVar(condVar, reason);
		dfm.notifyOp(new JitCBranchOp(op, branch, cond));
	}

	/**
	 * Record an indirect branch op into the use-def graph
	 * 
	 * <p>
	 * The {@link IndBranch} will have the target decode context, but the address is dynamic. We
	 * have to obtain the target varnode's definition and use it.
	 * 
	 * @param op the op
	 */
	protected void recordIndirectBranch(PcodeOp op) {
		Varnode offVar = getIndirectBranchTarget(op);
		JitVal offset = state.getVar(offVar, reason);
		IndBranch branch = (IndBranch) Objects.requireNonNull(branches.get(op));
		dfm.notifyOp(new JitBranchIndOp(op, offset, branch));
	}

	@Override
	public void executeBranch(PcodeOp op, PcodeFrame frame) {
		recordBranch(op);
	}

	@Override
	public void executeConditionalBranch(PcodeOp op, PcodeFrame frame) {
		recordConditionalBranch(op);
	}

	@Override
	public void executeIndirectBranch(PcodeOp op, PcodeFrame frame) {
		recordIndirectBranch(op);
	}

	@Override
	public void executeCall(PcodeOp op, PcodeFrame frame, PcodeUseropLibrary<JitVal> library) {
		recordBranch(op);
	}

	@Override
	public void executeIndirectCall(PcodeOp op, PcodeFrame frame) {
		recordIndirectBranch(op);
	}

	@Override
	public void executeReturn(PcodeOp op, PcodeFrame frame) {
		recordIndirectBranch(op);
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
