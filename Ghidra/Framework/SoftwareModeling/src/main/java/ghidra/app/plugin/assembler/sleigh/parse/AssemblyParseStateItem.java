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
package ghidra.app.plugin.assembler.sleigh.parse;

import java.util.*;

import ghidra.app.plugin.assembler.sleigh.grammars.*;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;

/**
 * An item in the state of an LR(0) parser
 * 
 * An item is a production with a dot indicating a position while parsing
 */
public class AssemblyParseStateItem implements Comparable<AssemblyParseStateItem> {
	private final AssemblyProduction prod;
	private final int pos;

	/**
	 * Construct a new item starting at the far left of the given production
	 * @param prod the production
	 */
	public AssemblyParseStateItem(AssemblyProduction prod) {
		this(prod, 0);
	}

	/**
	 * Construct a new item starting immediately before the symbol at the given position in the
	 * given production
	 * @param prod the production
	 * @param pos the position of the dot
	 */
	public AssemblyParseStateItem(AssemblyProduction prod, int pos) {
		this.prod = prod;
		this.pos = pos;
		if (pos > prod.size()) {
			throw new AssertionError("INTERNAL: Attempt to advance beyond end of RHS");
		}
	}

	/**
	 * Advance the dot by one position, producing a new item
	 * @return the new item
	 */
	public AssemblyParseStateItem read() {
		return new AssemblyParseStateItem(prod, pos + 1);
	}

	/**
	 * Get the symbol immediately to the right of the dot
	 * 
	 * This is the symbol which must be matched to advance the dot.
	 * @return the symbol, or null if the item is completed, i.e., the dot is at the far right
	 */
	public AssemblySymbol getNext() {
		if (completed()) {
			return null;
		}
		return prod.get(pos);
	}

	/**
	 * "Fill" one step out to close a state containing this item
	 * 
	 * To compute the full closure, you must continue stepping out until no new items are generated
	 * @param grammar the grammar containing the production
	 * @return a subset of items in the closure of a state containing this item
	 */
	public Collection<AssemblyParseStateItem> getClosure(AssemblyGrammar grammar) {
		AssemblySymbol next = getNext();
		if (next == null) {
			return Collections.emptySet();
		}
		if (!(next instanceof AssemblyNonTerminal)) {
			return Collections.emptySet();
		}
		AssemblyNonTerminal nt = (AssemblyNonTerminal) next;
		Set<AssemblyParseStateItem> result = new TreeSet<>();
		for (AssemblyProduction subst : grammar.productionsOf(nt)) {
			result.add(new AssemblyParseStateItem(subst, 0));
		}
		return result;
	}

	@Override
	public boolean equals(Object that) {
		if (!(that instanceof AssemblyParseStateItem)) {
			return false;
		}
		AssemblyParseStateItem apsi = (AssemblyParseStateItem) that;
		if (!(this.prod.getIndex() == apsi.prod.getIndex())) {
			return false;
		}
		if (this.pos != apsi.pos) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(AssemblyParseStateItem that) {
		int result;
		result = this.prod.getIndex() - that.prod.getIndex();
		if (result != 0) {
			return result;
		}
		result = this.pos - that.pos;
		if (result != 0) {
			return result;
		}

		return 0;
	}

	@Override
	public int hashCode() {
		int result = 0;
		result += prod.getIndex();
		result *= 31;
		result += pos;
		return result;
	}

	@Override
	public String toString() {
		AssemblySentential<?> prec = prod.subList(0, pos);
		AssemblySentential<?> proc = prod.subList(pos, prod.size());
		StringBuilder sb = new StringBuilder(prod.getIndex() + ". " + prod.getLHS() + " => ");
		if (prec.size() != 0) {
			sb.append(prec + " ");
		}
		sb.append("*");
		if (proc.size() != 0) {
			sb.append(" " + proc);
		}
		return sb.toString();
	}

	/**
	 * Check if this item is completed
	 * 
	 * The item is completed if all symbols have been matched, i.e., the dot is at the far right of
	 * the production.
	 * @return true iff the item is completed
	 */
	public boolean completed() {
		return (pos == prod.size());
	}

	/**
	 * Get the position of the dot
	 * 
	 * The position is the number of symbols to the left of the dot.
	 * @return
	 */
	public int getPos() {
		return pos;
	}

	/**
	 * Get the production associated with this item
	 * @return the production
	 */
	public AssemblyProduction getProduction() {
		return prod;
	}
}
