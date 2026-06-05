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

import ghidra.pcode.emu.jit.op.JitDefOp;
import ghidra.program.model.pcode.Varnode;

/**
 * An abstract implementation of {@link JitOutVar}.
 */
public abstract class AbstractJitOutVar extends AbstractJitVarnodeVar implements JitOutVar {
	private JitDefOp definition;

	/**
	 * Construct a variable.
	 * 
	 * @param id the unique id
	 * @param varnode the varnode
	 */
	public AbstractJitOutVar(int id, Varnode varnode) {
		super(id, varnode);
	}

	@Override
	public void setDefinition(JitDefOp definition) {
		this.definition = definition;
	}

	@Override
	public JitDefOp definition() {
		return definition;
	}
}
