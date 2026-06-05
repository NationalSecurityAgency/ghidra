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

import java.util.*;

import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitDataFlowState.MiniDFState;
import ghidra.pcode.emu.jit.op.*;
import ghidra.pcode.emu.jit.var.JitMissingVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.AnnotatedPcodeUseropLibrary.PcodeUserop;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * The operator output use analysis for JIT-accelerated emulation.
 * 
 * <p>
 * This implements the Operation Elimination phase of the {@link JitCompiler} using a simple graph
 * traversal. The result is the set of {@link JitOp ops} whose outputs are (or could be) used by a
 * downstream op. This includes all "sink" ops and all ops on which they depend.
 * 
 * <p>
 * Some of the sink ops are easy to identify. These are ops that have direct effects on memory,
 * control flow, or other aspects of the emulated machine:
 * 
 * <ul>
 * <li><b>Memory outputs</b> - any p-code op whose output operand is a memory varnode.</li>
 * <li><b>Store ops</b> - a {@link JitStoreOp store} op.</li>
 * <li><b>Branch ops</b> - one of {@link JitBranchOp branch}, {@link JitCBranchOp cbranch}, or
 * {@link JitBranchIndOp branchind}.</li>
 * <li><b>User ops with side effects</b> - a {@link JitCallOtherOpIf callother} to a method where
 * {@link PcodeUserop#hasSideEffects() hasSideEffects}{@code =true}.</li>
 * <li><b>Errors</b> - e.g., {@link JitUnimplementedOp unimplemented}, {@link JitCallOtherMissingOp
 * missing userop}.</li>
 * </ul>
 * 
 * <p>
 * We identify these ops by invoking {@link JitOp#canBeRemoved()}. Ops that return {@code false} are
 * "sink" ops.
 * 
 * <p>
 * There is another class of ops to consider as "sinks," though: The definitions of SSA variables
 * that could be retired. This could be from exiting the passage, flowing to a block with fewer live
 * variables, or invoking a userop with the Standard strategy (see
 * {@link JitDataFlowUseropLibrary}). Luckily, we have already performed {@link JitVarScopeModel
 * scope} analysis, so we already know what varnodes are retired. However, to determine what SSA
 * variables are retired, we have to consider where the retirement happens. For block transitions,
 * it is always at the end of the block. Thus, we can use
 * {@link JitDataFlowBlockAnalyzer#getVar(Varnode)}. For userops, we capture the intra-block
 * analysis state into {@link JitCallOtherOpIf#dfState()} <em>at the time of invocation</em>. We can
 * then use {@link MiniDFState#getVar(Varnode)}. The defining op for each retired SSA variable is
 * considered used.
 * 
 * <p>
 * Retirement due to block flow requires a little more attention. Consider an op that defines a
 * variable, where that op exists in a block that ends with a conditional branch. The analyzer does
 * not know which flow the code will take, so we have to consider that it could take either. If for
 * either branch, the variable goes out of scope and is retired, we have to consider the defining op
 * as used.
 * 
 * <p>
 * The remainder of the algorithm is simply an upward traversal of the use-def graph to collect all
 * of the sink ops' dependencies. All the dependencies are considered used.
 * 
 * @implNote The {@link JitOpUpwardVisitor} permits seeding of values (constants and variables) and
 *           ops. Thus, we seed using the non-{@link JitOp#canBeRemoved() removable} ops, and the
 *           retireable SSA variables. We do not have to get the variables' defining ops, since the
 *           visitor will do that for us.
 */
public class JitOpUseModel {
	private final JitAnalysisContext context;
	private final JitControlFlowModel cfm;
	private final JitDataFlowModel dfm;
	private final JitVarScopeModel vsm;

	private final Set<JitOp> used = new HashSet<>();

	/**
	 * Construct the operator use model
	 * 
	 * @param context the analysis context
	 * @param cfm the control flow model
	 * @param dfm the data flow model
	 * @param vsm the variable scope model
	 */
	public JitOpUseModel(JitAnalysisContext context, JitControlFlowModel cfm,
			JitDataFlowModel dfm, JitVarScopeModel vsm) {
		this.context = context;
		this.cfm = cfm;
		this.dfm = dfm;
		this.vsm = vsm;

		if (context.getConfiguration().removeUnusedOperations()) {
			analyze();
		}
	}

	/**
	 * The implementation of the graph traversal
	 * 
	 * <p>
	 * This implements the use-def upward visitor to collect the dependencies of ops and variables
	 * identified elsewhere in the code. By calling {@link #visitOp(JitOp)},
	 * {@link #visitVal(JitVal)}, etc., all used ops are collected into {@link JitOpUseModel#used}.
	 */
	class OpUseCollector implements JitOpUpwardVisitor {
		final JitBlock block;
		final JitDataFlowBlockAnalyzer analyzer;

		/**
		 * Construct a collector for the given block
		 * 
		 * @param block the block whose ops are being examined
		 */
		public OpUseCollector(JitBlock block) {
			this.block = block;
			this.analyzer = dfm.getAnalyzer(block);
		}

		@Override
		public void visitOp(JitOp op) {
			if (!used.add(op)) {
				return;
			}
			JitOpUpwardVisitor.super.visitOp(op);
		}

		@Override
		public void visitMissingVar(JitMissingVar missingVar) {
			throw new AssertionError("missing: " + missingVar);
		}

		/**
		 * Visit a varnode that could be retired upon exiting a block
		 *
		 * <p>
		 * This applies whether exiting the passage altogether or just flowing to another block. It
		 * will find all definitions (including just-generated phi nodes) and visit them.
		 * 
		 * @param vn the retireable varnode
		 */
		void visitRetireable(Varnode vn) {
			for (JitVal val : analyzer.getOutput(vn)) {
				visitVal(val);
			}
		}

		/**
		 * Visit a varnode that will be retired before calling a userop
		 * 
		 * <p>
		 * This applies only when the userop is invoked using the Standard strategy.
		 * 
		 * @see JitDataFlowUseropLibrary
		 * @param vn the retired varnode
		 * @param callother the callother op
		 */
		void visitCallOtherRetireable(Varnode vn, JitCallOtherOpIf callother) {
			for (JitVal val : callother.dfState().getDefinitions(vn)) {
				visitVal(val);
			}
		}
	}

	/**
	 * Get the varnodes that will be retired before the given callother
	 * 
	 * @param block the block containing the callother
	 * @param op the callother op
	 * @return the block's live varnodes, or empty, depending on the callother invocation strategy.
	 */
	private Set<Varnode> getCallOtherRetireVarnodes(JitBlock block, JitCallOtherOpIf op) {
		// Should not see inline-replaced ops here
		if (op.userop().isFunctional()) {
			return Set.of();
		}
		return vsm.getLiveVars(block);
	}

	/**
	 * Get the varnodes that could be retired upon leaving this block
	 * 
	 * <p>
	 * If the block has an {@link JitBlock#branchesOut() exit} branch, then all live varnodes could
	 * be retired. The result is the union of retired varnodes among each flow
	 * {@link JitBlock#flowsFrom() from} the block. Note that every block must have a means of
	 * leaving, i.e., {@link JitBlock#branchesOut()} and {@link JitBlock#flowsFrom()} cannot both be
	 * empty.
	 * 
	 * @implNote Because retired varnodes are the difference in live varnodes, we can optimize the
	 *           set computation by taking the intersection of live varnodes among all flow
	 *           destinations and subtracting it from the live varnodes of this block.
	 * 
	 * @param block the block to examine
	 * @return the set of varnodes that could be retired
	 */
	private Set<Varnode> getCouldRetireVarnodes(JitBlock block) {
		if (!block.branchesOut().isEmpty()) {
			return vsm.getLiveVars(block);
		}
		if (block.flowsFrom().isEmpty()) {
			throw new AssertionError();
			// or just return Set.of()?
		}
		Set<Varnode> aliveAfterAnyFlow =
			new HashSet<>(vsm.getLiveVars(block.flowsFrom().values().iterator().next().to()));
		for (BlockFlow flow : block.flowsFrom().values()) {
			aliveAfterAnyFlow.retainAll(vsm.getLiveVars(flow.to()));
		}
		Set<Varnode> result = new HashSet<>(vsm.getLiveVars(block));
		result.removeAll(aliveAfterAnyFlow);
		return result;
	}

	/**
	 * Perform the analysis
	 * 
	 * <p>
	 * This first backfills any missing phi nodes that might not have been considered during data
	 * flow analysis. Then, it collects all the sinks and invokes the traversal on them. Note that
	 * we can end traversal any time we encounter an op that we have already marked as used, because
	 * we will already have marked its dependencies, too. The visit order does not matter, so we
	 * just iterate over the blocks and ops, marking things as we encounter them.
	 */
	private void analyze() {
		/**
		 * I want every value that could get written back out to the state, either because it's
		 * retired, or because the output operand is memory. I also need inputs to branches or to
		 * callother's, since those may have side effects depending on those inputs.
		 */

		Set<JitPhiOp> phisBefore = Set.copyOf(dfm.phiNodes());
		for (JitBlock block : cfm.getBlocks()) {

			for (PcodeOp op : block.getCode()) {
				if (dfm.getJitOp(op) instanceof JitCallOtherOpIf callother) {
					for (Varnode vn : getCallOtherRetireVarnodes(block, callother)) {
						// We only want the side effect: Adds needed phi.
						callother.dfState().getVar(vn); // Visit is later
					}
				}
			}

			for (Varnode vn : getCouldRetireVarnodes(block)) {
				JitDataFlowBlockAnalyzer analyzer = dfm.getAnalyzer(block);
				analyzer.getVar(vn); // Visit is later
			}
		}
		Set<JitPhiOp> extraPhis = new LinkedHashSet<>(dfm.phiNodes());
		extraPhis.removeAll(phisBefore);
		dfm.analyzeInterblock(extraPhis);

		for (JitBlock block : cfm.getBlocks()) {
			OpUseCollector collector = new OpUseCollector(block);

			// Locate memory outputs, stores, branches, callothers
			for (PcodeOp op : block.getCode()) {
				JitOp jitOp = dfm.getJitOp(op);
				if (jitOp instanceof JitCallOtherOpIf callotherOp) {
					for (Varnode vn : getCallOtherRetireVarnodes(block, callotherOp)) {
						collector.visitCallOtherRetireable(vn, callotherOp);
					}
				}
				if (!jitOp.canBeRemoved()) {
					collector.visitOp(jitOp);
				}
			}

			// Compute retire-able variables
			for (Varnode vn : getCouldRetireVarnodes(block)) {
				collector.visitRetireable(vn);
			}
		}
	}

	/**
	 * Check whether the given op node is used.
	 * 
	 * <p>
	 * If the op is used, then it cannot be eliminated.
	 * 
	 * @param op the op to check
	 * @return true if used, i.e., non-removable
	 */
	public boolean isUsed(JitOp op) {
		if (context.getConfiguration().removeUnusedOperations()) {
			return used.contains(op);
		}
		return true;
	}

	/**
	 * For diagnostics: Dump the analysis result to stderr
	 * 
	 * @see Diag#PRINT_OUM
	 */
	public void dumpResult() {
		System.err.println("STAGE: OpUse");
		for (JitBlock block : cfm.getBlocks()) {
			JitDataFlowBlockAnalyzer analyzer = dfm.getAnalyzer(block);
			System.err.println("  Block: " + block);
			for (Varnode vn : getCouldRetireVarnodes(block)) {
				for (JitVal val : analyzer.getOutput(vn)) {
					System.err.println("    Could retire: " + val);
				}
			}
			for (PcodeOp op : block.getCode()) {
				JitOp jitOp = dfm.getJitOp(op);
				if (!isUsed(jitOp)) {
					System.err.println("    Removed: %s: %s".formatted(op.getSeqnum(), jitOp));
				}
			}
		}
	}
}
