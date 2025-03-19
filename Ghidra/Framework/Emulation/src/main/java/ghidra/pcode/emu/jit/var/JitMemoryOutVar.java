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

import ghidra.pcode.emu.jit.JitBytesPcodeExecutorState;
import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.pcode.emu.jit.op.JitOp;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code variable node with a fixed location in memory and a defining p-code op.
 * 
 * <p>
 * This represents an output operand located in memory. It can be addressed directly. In contrast to
 * {@link JitLocalOutVar}, these <em>may not</em> be used by downstream p-code ops in the use-def
 * graph, because the output is written to the {@link JitBytesPcodeExecutorState state} immediately.
 * There's no benefit to further analysis. Instead, ops that use the same varnode will take a
 * {@link JitDirectMemoryVar}, which indicate input immediately from the
 * {@link JitBytesPcodeExecutorState state}.
 * 
 * @see JitDirectMemoryVar
 */
public class JitMemoryOutVar extends AbstractJitOutVar implements JitMemoryVar {
	/**
	 * Construct a variable.
	 * 
	 * @param id the unique id
	 * @param varnode the varnode
	 * @see JitDataFlowModel#generateOutVar(Varnode)
	 */
	public JitMemoryOutVar(int id, Varnode varnode) {
		super(id, varnode);
	}

	@Override
	public void addUse(JitOp op, int position) {
		throw new AssertionError();
	}
}
