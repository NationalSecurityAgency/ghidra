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
package ghidra.app.plugin.assembler.sleigh.grammars;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyExtendedNonTerminal;

/**
 * Defines a production of an "extended" grammar
 * 
 * @see AssemblyExtendedGrammar
 */
public class AssemblyExtendedProduction
		extends AbstractAssemblyProduction<AssemblyExtendedNonTerminal> {
	private final int finalState;
	private final AssemblyProduction ancestor;

	/**
	 * Construct an extended production based on the given ancestor
	 * @param lhs the extended left-hand side
	 * @param rhs the extended right-hand side
	 * @param finalState the end state of the final symbol of the RHS
	 * @param ancestor the original production from which this extended production is derived
	 */
	public AssemblyExtendedProduction(AssemblyExtendedNonTerminal lhs,
			AssemblySentential<AssemblyExtendedNonTerminal> rhs, int finalState,
			AssemblyProduction ancestor) {
		super(lhs, rhs);
		this.finalState = finalState;
		this.ancestor = ancestor;
	}

	@Override
	public AssemblyExtendedNonTerminal getLHS() {
		return super.getLHS();
	}

	/**
	 * Get the final state of this production
	 * @return the end state of the last symbol of the RHS
	 */
	public int getFinalState() {
		return finalState;
	}

	/**
	 * Get the original production from which this production was derived
	 * @return the original production
	 */
	public AssemblyProduction getAncestor() {
		return ancestor;
	}
}
