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

import ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyGrammar;

/**
 * A symbol in a context-free grammar
 * 
 * Symbols can be either terminals or non-terminals. Non-terminals must have a defining production,
 * i.e., it must appear as the left-hand side of some production in the grammar. 
 * 
 * Traditionally, when displayed, non-terminals should be immediately distinguishable from
 * terminals. In classic CS literature, this usually means non-terminals are in CAPS, and terminals
 * are in lower-case. Because the assembler doesn't control the names provided by SLEIGH, we
 * surround non-terminals in [brackets].
 * 
 * @see AbstractAssemblyGrammar
 */
public abstract class AssemblySymbol implements Comparable<AssemblySymbol> {
	protected final String name;

	/**
	 * Construct a new symbol with the given name
	 * @param name the name
	 */
	public AssemblySymbol(String name) {
		this.name = name;
	}

	@Override
	public abstract String toString();

	/**
	 * Get the name of this symbol
	 * @return the name
	 */
	public String getName() {
		return name;
	}

	@Override
	public int compareTo(AssemblySymbol that) {
		return this.toString().compareTo(that.toString()); // LAZY
	}

	@Override
	public boolean equals(Object that) {
		if (!(that instanceof AssemblySymbol)) {
			return false;
		}
		return this.toString().equals(that.toString()); // LAZY
	}

	@Override
	public int hashCode() {
		return toString().hashCode(); // LAZY
	}

	/**
	 * Check if this symbol consumes an operand index of its constructor
	 * @return true if the symbol represents an operand
	 */
	public boolean takesOperandIndex() {
		return true;
	}
}
