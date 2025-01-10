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

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.BlockFlow;
import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.op.JitPhiOp;
import ghidra.pcode.emu.jit.var.JitMissingVar;
import ghidra.pcode.emu.jit.var.JitVal;
import ghidra.pcode.exec.PcodeExecutor;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

/**
 * An encapsulation of the per-block data flow analysis done by {@link JitDataFlowModel}
 * 
 * <p>
 * One of these is created for each basic block in the passage. This does both the intra-block
 * analysis and encapsulates parts of the inter-block analysis. The class also contains and provides
 * access to some of the analytic results.
 * 
 * @see JitDataFlowModel#getAnalyzer(JitBlock)
 */
public class JitDataFlowBlockAnalyzer {
	private final JitAnalysisContext context;
	private final JitDataFlowModel dfm;
	private final JitBlock block;

	private final JitDataFlowArithmetic arithmetic;
	private final JitDataFlowUseropLibrary library;

	private final JitDataFlowState state;
	private final boolean isEntry;

	JitDataFlowBlockAnalyzer(JitAnalysisContext context, JitDataFlowModel dfm, JitBlock block) {
		this.context = context;
		this.dfm = dfm;
		this.block = block;

		this.arithmetic = dfm.getArithmetic();
		this.library = dfm.getLibrary();

		this.state = new JitDataFlowState(context, dfm, block);
		this.isEntry = context.getOpEntry(block.first()) != null;
	}

	/**
	 * Perform the intra-block analysis for this block
	 * 
	 * <p>
	 * This just runs the block p-code through the analytic interpreter. See
	 * {@link JitDataFlowModel}'s section on intra-block analysis.
	 */
	void doIntrablock() {
		PcodeExecutor<JitVal> exec = new JitDataFlowExecutor(context, dfm, state);
		exec.execute(block, library);
	}

	/**
	 * The initial entry into the recursive phi option seeking algorithm
	 * 
	 * <p>
	 * See {@link JitDataFlowModel}'s section on inter-block analysis. This will modify the given
	 * phi op in place, adding to it each found option. There is also more details than discussed in
	 * the data flow model documentation. Keep in mind a varnode may be partially defined, e.g.,
	 * when reading {@link RAX}, perhaps only {@link EAX} has been defined. In such cases, we must
	 * catenate in the same manner we would when reading the varnode during intra-block analysis.
	 * The portions missing a definition will generate corresponding phi nodes, which are treated
	 * recursively.
	 * 
	 * @param phi the phi op for which we seek options
	 */
	void fillPhiFromDeps(JitPhiOp phi) {
		fillPhiFromDeps(phi, new HashSet<>());
	}

	/**
	 * Fill options in for the given phi op
	 * 
	 * <p>
	 * If our block is an entry, add that as a possible option. <em>Additionally</em>, consider each
	 * upstream block (dependency) as an option, recursively. Recursion will naturally terminate if
	 * there are no inward flows.
	 * 
	 * @param phi the phi op for which we seek options
	 * @param visited the blocks which have already been visited during recursion
	 */
	private void fillPhiFromDeps(JitPhiOp phi, Set<JitBlock> visited) {
		if (isEntry) {
			phi.addInputOption();
		}
		for (BlockFlow flow : block.flowsTo().values()) {
			JitDataFlowBlockAnalyzer analyzerFrom = dfm.getOrCreateAnalyzer(flow.from());
			analyzerFrom.fillPhiFromBlock(phi, flow, visited);
		}
	}

	/**
	 * Consider the given flow as an option for the given phi op, and fill it
	 * 
	 * <p>
	 * If we've already visited the given block, we return immediately, without further recursion.
	 * Otherwise, we examine the varnode output state of this block for suitable definitions. If
	 * needed, we fill any gaps (possibly the entire varnode sought) with new phi nodes and recurse.
	 * 
	 * @param phi the phi op for which we seek an option
	 * @param flow the flow from the block to consider
	 * @param visited the blocks which have already been visited during recursion
	 */
	private void fillPhiFromBlock(JitPhiOp phi, BlockFlow flow, Set<JitBlock> visited) {
		if (!visited.add(block)) {
			/**
			 * NOTE: We do not need to remove the block before we return. If we didn't find it by
			 * this path, we certainly not going to find it from here by another path.
			 */
			return;
		}

		Varnode phiVn = phi.out().varnode();
		List<JitVal> defs = state.getDefinitions(phiVn);
		if (defs.size() != 1) {
			defs = state.generatePhis(defs, dfm.phiQueue);
			JitVal catOpt = arithmetic.catenate(phiVn, defs);
			phi.addOption(flow, catOpt);
			/**
			 * New phi nodes will be picked up in next round of filling. Since parts are smaller
			 * than the whole, the size of such nodes should shrink until a singular definition is
			 * found.
			 */
			return;
		}

		JitVal val = defs.get(0);
		if (val instanceof JitMissingVar missing) {
			// Require the chain to have a node in this block
			JitPhiOp phi2 = missing.generatePhi(dfm, block);
			dfm.phiQueue.add(phi2);
			state.setVar(missing.varnode(), phi2.out());
			phi.addOption(flow, phi2.out());
			// Will get filled on subsequent round
			//fillPhiFromDeps(phi2, visited);
			return;
		}

		phi.addOption(flow, val);
	}

	/**
	 * Get a complete catalog of all varnodes read, including overlapping, subregs, etc.
	 * 
	 * @return the set of varnodes
	 */
	public Set<Varnode> getVarnodesRead() {
		return state.getVarnodesRead();
	}

	/**
	 * Get a complete catalog of all varnodes written, including overlapping, subregs, etc.
	 * 
	 * @return the set of varnodes
	 */
	public Set<Varnode> getVarnodesWritten() {
		return state.getVarnodesWritten();
	}

	/**
	 * Get an ordered list of all values involved in the latest definition of the given varnode.
	 * 
	 * @see JitDataFlowState#getDefinitions(Varnode)
	 * @param varnode the varnode whose definition(s) to retrieve
	 * @return the list of values
	 */
	public List<JitVal> getOutput(Varnode varnode) {
		return state.getDefinitions(varnode);
	}

	/**
	 * Get an ordered list of all values involved in the latest definition of the given register.
	 * 
	 * @see JitDataFlowState#getDefinitions(Register)
	 * @param register the register whose definition(s) to retrieve
	 * @return the list of values
	 */
	public List<JitVal> getOutput(Register register) {
		return state.getDefinitions(register);
	}

	/**
	 * Get the latest definition of the given varnode, synthesizing ops is required.
	 * 
	 * <p>
	 * NOTE: May produce phi nodes that need additional inter-block analysis
	 * 
	 * @see JitDataFlowModel#analyzeInterblock(Collection)
	 * @see JitDataFlowState#getVar(AddressSpace, JitVal, int, boolean, Reason)
	 * @param vn the varnode
	 * @return the latest definition for the block analyzed
	 */
	public JitVal getVar(Varnode vn) {
		return state.getVar(vn, Reason.EXECUTE_READ);
	}
}
