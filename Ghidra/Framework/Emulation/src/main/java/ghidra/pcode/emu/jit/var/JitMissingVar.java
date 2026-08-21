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
package ghidra.pcode.emu.jit.var;

import ghidra.pcode.emu.jit.analysis.JitControlFlowModel.JitBlock;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.analysis.JitDataFlowState;
import ghidra.pcode.emu.jit.op.JitPhiOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code variable whose definition could not be determined.
 * 
 * <p>
 * This is only applicable to {@code register} and {@code unique} variables. It indicates the
 * {@link JitDataFlowState} had not recorded a definition for the variable's varnode (or some
 * portion of it) prior in the same block. These should never enter the use-def graph. Instead, each
 * should be replaced by a {@link JitOutVar} defined by a {@link JitPhiOp phi} node. The phi node's
 * options are determined later during {@link JitDataFlowModel inter-block} analysis.
 * 
 * @see #generatePhi(JitDataFlowModel, JitBlock)
 */
public class JitMissingVar extends AbstractJitVarnodeVar {
	/**
	 * Construct a variable.
	 * 
	 * @param varnode the varnode
	 */
	public JitMissingVar(Varnode varnode) {
		super(-1, varnode);
	}

	/**
	 * Create the {@link JitPhiOp phi} node for this missing variable.
	 * 
	 * The resulting node and its {@link JitPhiOp#out() output} are added to the use-def graph. Note
	 * that this missing variable never enters the use-def graph. The phi's output takes the place
	 * of this variable.
	 * 
	 * @param dfm the data flow model
	 * @param block the block containing the op that accessed the varnode
	 * @return the generated phi op
	 * @see JitDataFlowModel Inter-block data flow analysis
	 */
	public JitPhiOp generatePhi(JitDataFlowModel dfm, JitBlock block) {
		return dfm.notifyOp(new JitPhiOp(block, dfm.generateOutVar(varnode)));
	}
}
