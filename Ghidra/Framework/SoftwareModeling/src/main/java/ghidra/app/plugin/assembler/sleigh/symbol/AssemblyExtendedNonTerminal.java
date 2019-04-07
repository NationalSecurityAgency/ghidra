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
package ghidra.app.plugin.assembler.sleigh.symbol;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyExtendedGrammar;

/**
 * The type of non-terminal for an "extended grammar"
 * @see AssemblyExtendedGrammar
 */
public class AssemblyExtendedNonTerminal extends AssemblyNonTerminal {
	//private int start;
	private final AssemblyNonTerminal nt;
	private final int end;

	/**
	 * Construct a new extended non terminal, derived from the given non-terminal
	 * @param start the start state for the extended non-terminal
	 * @param nt the non-terminal from which the extended non-terminal is derived
	 * @param end the end state for the extended non-terminal
	 */
	public AssemblyExtendedNonTerminal(int start, AssemblyNonTerminal nt, int end) {
		super(start + "[" + nt.name + "]" + end);
		//this.start = start;
		this.nt = nt;
		this.end = end;
	}

	@Override
	public String getName() {
		if (end == -1) {
			return nt.getName();
		}
		return name;
	}

	@Override
	public String toString() {
		if (end == -1) {
			return nt.toString();
		}
		return name;
	}
}
