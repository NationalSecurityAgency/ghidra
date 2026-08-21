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
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code variable node with a fixed location in memory.
 * 
 * <p>
 * This represents an input operand located in memory. Its value can be accessed directly from the
 * {@link JitBytesPcodeExecutorState state} at run time.
 * 
 * @see JitMemoryOutVar
 */
public class JitDirectMemoryVar extends AbstractJitVarnodeVar implements JitMemoryVar {
	/**
	 * Construct a variable.
	 * 
	 * @param id the unique id
	 * @param varnode the varnode
	 * @see JitDataFlowModel#generateDirectMemoryVar(Varnode)
	 */
	public JitDirectMemoryVar(int id, Varnode varnode) {
		super(id, varnode);
	}
}
