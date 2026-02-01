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
package ghidra.asm.wild.symbol;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;

public class WildAssemblyNonTerminal extends AssemblyNonTerminal {

	protected final boolean takesOperandIndex;

	public WildAssemblyNonTerminal(String name, boolean takesOperandIndex) {
		super(name);
		this.takesOperandIndex = takesOperandIndex;
	}

	@Override
	public boolean takesOperandIndex() {
		return takesOperandIndex;
	}
}
