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

import java.util.HashSet;
import java.util.Set;

import ghidra.pcode.emu.jit.JitCompiler;
import ghidra.pcode.emu.jit.JitCompiler.Diag;
import ghidra.pcode.emu.jit.JitPassage.IntBranch;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.op.*;

/**
 * The p-code block reachability analysis for JIT-accelerated emulation.
 * <p>
 * The implements the Reachability phase of the {@link JitCompiler} using a simple graph traversal.
 * The result is the set of {@linkplain JitBlock basic blocks} and {@linkplain BlockFlow edges} that
 * are actually reachable from a passage's entries.
 * <p>
 * The traversal is seeded with each of the passage's entry points, and then each outbound flow is
 * considered. Consider a conditional branch. The control-flow graph will have two outbound flows,
 * one for the branch case, and one for the fall-through case. It's possible the data-flow phase
 * detected its condition was constant, and so it would be re-written as an unconditional branch or
 * nop, so we must examine the actual {@link JitOp} presented, not just the original p-code op, when
 * determining which flows can be taken. We perform this traversal in the downstream direction only.
 */
public class JitReachabilityModel {
	private final JitAnalysisContext context;
	private final JitControlFlowModel cfm;
	private final JitDataFlowModel dfm;

	private final Set<JitBlock> reachable = new HashSet<>();
	private final Set<BlockFlow> takeable = new HashSet<>();

	/**
	 * Create the reachability model
	 * 
	 * @param context the analysis context
	 * @param cfm the control-flow model
	 * @param dfm the data-flow model.
	 * @implNote We're being a bit lazy here requiring the DFM, because we use the re-written JitOps
	 *           so that reachability heeds folded indirect and conditional branches. If we don't
	 *           want this dependency, we could inspect the folded constants for the ops ourselves.
	 */
	public JitReachabilityModel(JitAnalysisContext context, JitControlFlowModel cfm,
			JitDataFlowModel dfm) {
		this.context = context;
		this.cfm = cfm;
		this.dfm = dfm;

		if (context.getConfiguration().removeUnreachableBlocks()) {
			analyze();
		}
	}

	private void visitBlock(JitBlock block) {
		if (!reachable.add(block)) {
			return;
		}
		for (BlockFlow flow : block.flowsFrom().values()) {
			IntBranch br = flow.branch();
			// Use DFM JitOp instead of PcodeOp opcodes, for folding re-writes
			JitOp op = dfm.getJitOp(br.from());
			switch (op) {
				case JitCBranchOp _ -> {
					// Add both fall-through and branch target
					visitFlow(flow);
				}
				case JitBranchOp _ -> {
					// Possibly re-written from CBRANCH. Either way, only include target
					if (!br.isFall()) {
						visitFlow(flow);
					}
				}
				case JitBranchIndOp _ -> {
					// Reverted from re-written BRANCH. Still, folded target is reachable
					assert !br.isFall();
					visitFlow(flow);
				}
				case JitNopOp _ -> {
					// Re-written CBRANCH, or just next op is target of another branch.
					// In case a CBRANCH, only include fall-through
					if (br.isFall()) {
						visitFlow(flow);
					}
				}
				default -> {
					// Next op is target of another branch. There is only fall-through.
					assert br.isFall();
					visitFlow(flow);
				}
			}
		}
	}

	private void visitFlow(BlockFlow flow) {
		takeable.add(flow);
		visitBlock(flow.to());
	}

	private void analyze() {
		/**
		 * See the set with every block that is an entry point
		 */
		for (JitBlock block : cfm.getBlocks()) {
			if (context.getOpEntry(block.first()) != null) {
				visitBlock(block);
			}
		}
	}

	/**
	 * Check whether the given block can be reached
	 * 
	 * @param block the block to check
	 * @return true if reachable, i.e., non-removable
	 */
	public boolean isReachable(JitBlock block) {
		if (context.getConfiguration().removeUnreachableBlocks()) {
			return reachable.contains(block);
		}
		return true;
	}

	/**
	 * Check whether the given flow can be taken
	 * 
	 * @param flow the flow to check
	 * @return true if it can be taken, i.e., analysis must consider this edge.
	 */
	public boolean isTakeable(BlockFlow flow) {
		if (context.getConfiguration().removeUnreachableBlocks()) {
			return takeable.contains(flow);
		}
		return true;
	}

	/**
	 * For diagnostics: Dump the analysis result to stder
	 * 
	 * @see Diag#PRINT_RM
	 */
	public void dumpResult() {
		System.err.println("STAGE: Reachability");
		for (JitBlock block : reachable) {
			System.err.println("  Reachable: " + block);
		}
	}
}
