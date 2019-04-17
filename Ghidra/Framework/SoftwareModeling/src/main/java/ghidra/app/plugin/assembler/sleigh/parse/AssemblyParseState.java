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

import org.apache.commons.collections4.set.AbstractSetDecorator;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.util.SleighUtil;

/**
 * A state in an LR(0) parsing machine
 * 
 * Each item consists of a kernel and an implied closure. Only the kernel is necessary to define
 * the item, but the whole closure must be considered when deriving new states.
 */
public class AssemblyParseState extends AbstractSetDecorator<AssemblyParseStateItem>
		implements Comparable<AssemblyParseState> {
	private final AssemblyGrammar grammar;
	private final Set<AssemblyParseStateItem> kernel = new LinkedHashSet<>();
	private Set<AssemblyParseStateItem> closure;

	/**
	 * Construct a new state associated with the given grammar
	 * @param grammar the grammar
	 */
	public AssemblyParseState(AssemblyGrammar grammar) {
		this.grammar = grammar;
	}

	/**
	 * Construct a new state associated with the given grammar, seeded with the given item
	 * @param grammar the grammar
	 * @param item an item in the state
	 */
	public AssemblyParseState(AssemblyGrammar grammar, AssemblyParseStateItem item) {
		this(grammar);
		kernel.add(item);
	}

	@Override
	protected Set<AssemblyParseStateItem> decorated() {
		return kernel;
	}

	/**
	 * Get the closure of this item, caching the result
	 * @return the closure
	 */
	public Set<AssemblyParseStateItem> getClosure() {
		if (closure != null) {
			return closure;
		}
		closure = new LinkedHashSet<>(kernel);
		Set<AssemblyParseStateItem> newItems = new LinkedHashSet<>();
		do {
			newItems.clear();
			for (AssemblyParseStateItem item : closure) {
				newItems.addAll(item.getClosure(grammar));
			}
		}
		while (closure.addAll(newItems));
		return closure;
	}

	@Override
	public boolean equals(Object that) {
		if (!(that instanceof AssemblyParseState)) {
			return false;
		}
		return this.kernel.equals(((AssemblyParseState) that).kernel);
	}

	@Override
	public int compareTo(AssemblyParseState that) {
		int result;
		result = this.kernel.size() - that.kernel.size();
		if (result != 0) {
			return result;
		}
		// This only works because TreeSet presents the items in order
		result = SleighUtil.compareInOrder(this.kernel, that.kernel);
		if (result != 0) {
			return result;
		}
		return 0;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		Iterator<AssemblyParseStateItem> it = kernel.iterator();
		if (!it.hasNext()) {
			return "";
		}
		sb.append("\n\n"); // Helps with debugging
		sb.append(it.next());
		while (it.hasNext()) {
			sb.append("\n");
			sb.append(it.next());
		}
		return sb.toString();
	}

	@Override
	public int hashCode() {
		int result = 0;
		for (AssemblyParseStateItem item : kernel) {
			result *= 31;
			result += item.hashCode();
		}
		return result;
	}
}
