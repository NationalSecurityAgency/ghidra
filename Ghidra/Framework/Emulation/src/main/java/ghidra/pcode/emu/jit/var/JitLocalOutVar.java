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

import ghidra.pcode.emu.jit.analysis.JitDataFlowModel;
import ghidra.program.model.pcode.Varnode;

/**
 * A p-code register or unique variable with a defining p-code op.
 * 
 * <p>
 * This represents an output operand located in a thread's "local" state, i.e., it is a
 * {@code register} or {@code unique} variable. These can be used by downstream p-code ops in the
 * use-def graph, because we wish to analyze this flow and optimize the generated code.
 */
public class JitLocalOutVar extends AbstractJitOutVar {
	/**
	 * Construct a variable.
	 * 
	 * @param id the unique id
	 * @param varnode the varnode
	 * @see JitDataFlowModel#generateOutVar(Varnode)
	 */
	public JitLocalOutVar(int id, Varnode varnode) {
		super(id, varnode);
	}
}
