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

import java.util.List;

import org.apache.commons.collections4.list.AbstractListDecorator;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;

/**
 * Defines a production in a context-free grammar, usually for parsing mnemonic assembly
 *
 * @see AbstractAssemblyGrammar
 * @param <NT> the type of non-terminals
 */
public abstract class AbstractAssemblyProduction<NT extends AssemblyNonTerminal>
		extends AbstractListDecorator<AssemblySymbol>
		implements Comparable<AbstractAssemblyProduction<NT>> {
	private final NT lhs;
	private final AssemblySentential<NT> rhs;

	int idx = -1;

	/**
	 * Construct a production with the given LHS and RHS
	 * @param lhs the left-hand side
	 * @param rhs the right-hand side
	 */
	public AbstractAssemblyProduction(NT lhs, AssemblySentential<NT> rhs) {
		rhs.finish();
		this.lhs = lhs;
		this.rhs = rhs;
	}

	@Override
	protected List<AssemblySymbol> decorated() {
		return rhs;
	}

	/**
	 * Get the index of the production
	 * 
	 * Instead of using deep comparison, the index is often used as the identify of the production
	 * within a grammar.
	 * @return the index
	 */
	public int getIndex() {
		return idx;
	}

	/**
	 * Get the left-hand side
	 * @return the LHS
	 */
	public NT getLHS() {
		return lhs;
	}

	/**
	 * Get the right-hand side
	 * @return the RHS
	 */
	public AssemblySentential<NT> getRHS() {
		return rhs;
	}

	@Override
	public String toString() {
		String result = idx + ". " + lhs + " => " + rhs;
		return result;
	}

	@Override
	public boolean equals(Object that) {
		if (!(that instanceof AbstractAssemblyProduction)) {
			return false;
		}
		AbstractAssemblyProduction<?> aap = (AbstractAssemblyProduction<?>) that;
		if (!this.lhs.equals(aap.lhs)) {
			return false;
		}
		if (!this.rhs.equals(aap.rhs)) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(AbstractAssemblyProduction<NT> that) {
		int result;
		result = this.lhs.compareTo(that.lhs);
		if (result != 0) {
			return result;
		}
		result = this.rhs.compareTo(that.rhs);
		if (result != 0) {
			return result;
		}
		return 0;
	}

	@Override
	public int hashCode() {
		int result = 0;
		result += lhs.hashCode();
		result *= 31;
		result += rhs.hashCode();
		return result;
	}

	@Override
	public AssemblySentential<NT> subList(int fromIndex, int toIndex) {
		return rhs.subList(fromIndex, toIndex);
	}

	/**
	 * Get the "name" of this production
	 * 
	 * This is mostly just notional and for debugging. The name is taken as the name of the LHS.
	 * @return the name of the LHS
	 */
	public String getName() {
		return lhs.getName();
	}
}
