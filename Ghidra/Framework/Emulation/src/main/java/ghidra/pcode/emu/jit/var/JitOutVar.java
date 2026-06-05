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

/**
 * A p-code variable node with a defining p-code op.
 */
public interface JitOutVar extends JitVarnodeVar {
	/**
	 * Set the defining p-code operator node
	 * 
	 * @param definition the defining node
	 */
	void setDefinition(JitDefOp definition);

	/**
	 * The defining p-code operator node
	 * 
	 * <p>
	 * This should "never" be null. The only exception is the short interim between constructing the
	 * node and setting its definition. Once this variable has been entered into the use-def graph,
	 * the definition should be non-null and final.
	 * 
	 * @return the defining node
	 */
	JitDefOp definition();
}
