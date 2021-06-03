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

import java.util.*;

import org.apache.commons.collections4.map.LazyMap;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyConstructorSemantic;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.pattern.DisjointPattern;

/**
 * Defines a context free grammar, used to parse mnemonic assembly instructions
 * 
 * This stores the CFG and the associated semantics for each production. It also has mechanisms for
 * tracking "purely recursive" productions. These are productions of the form I =&gt; I, and they
 * necessarily create ambiguity. Thus, when constructing a parser, it is useful to identify them
 * early.
 */
public class AssemblyGrammar
		extends AbstractAssemblyGrammar<AssemblyNonTerminal, AssemblyProduction> {
	// a nested map of semantics by production, by constructor
	protected final Map<AssemblyProduction, Map<Constructor, AssemblyConstructorSemantic>> semantics =
		LazyMap.lazyMap(new TreeMap<>(), () -> new TreeMap<>());
	// a map of purely recursive, e.g., I => I, productions by name of LHS
	protected final Map<String, AssemblyProduction> pureRecursive = new TreeMap<>();

	@Override
	protected AssemblyProduction newProduction(AssemblyNonTerminal lhs,
			AssemblySentential<AssemblyNonTerminal> rhs) {
		return new AssemblyProduction(lhs, rhs);
	}

	@Override
	public void addProduction(AssemblyProduction prod) {
		if (isPureRecursive(prod)) {
			pureRecursive.put(prod.getLHS().getName(), prod);
		}
		else {
			super.addProduction(prod);
		}
	}

	/**
	 * Add a production associated with a SLEIGH constructor semantic
	 * @param lhs the left-hand side
	 * @param rhs the right-hand side
	 * @param pattern the pattern associated with the constructor
	 * @param cons the SLEIGH constructor
	 * @param indices the indices of RHS non-terminals that represent an operand in the constructor
	 */
	public void addProduction(AssemblyNonTerminal lhs, AssemblySentential<AssemblyNonTerminal> rhs,
			DisjointPattern pattern, Constructor cons, List<Integer> indices) {
		AssemblyProduction prod = newProduction(lhs, rhs);
		addProduction(prod);
		Map<Constructor, AssemblyConstructorSemantic> map = semantics.get(prod);
		AssemblyConstructorSemantic sem = map.get(cons);
		if (sem == null) {
			sem = new AssemblyConstructorSemantic(cons, indices);
			map.put(cons, sem);
		}
		else if (!indices.equals(sem.getOperandIndices())) {
			throw new IllegalStateException(
				"Productions of the same constructor must have same operand indices");
		}

		sem.addPattern(pattern);
	}

	/**
	 * Get the semantics associated with a given production
	 * @param prod the production
	 * @return all semantics associated with the given production
	 */
	public Collection<AssemblyConstructorSemantic> getSemantics(AssemblyProduction prod) {
		return Collections.unmodifiableCollection(semantics.get(prod).values());
	}

	@Override
	public void combine(AbstractAssemblyGrammar<AssemblyNonTerminal, AssemblyProduction> that) {
		super.combine(that);
		if (that instanceof AssemblyGrammar) {
			AssemblyGrammar ag = (AssemblyGrammar) that;
			this.semantics.putAll(ag.semantics);
			this.pureRecursive.putAll(ag.pureRecursive);
		}
	}

	/**
	 * Get all productions in the grammar that are purely recursive
	 * @return
	 */
	public Collection<AssemblyProduction> getPureRecursive() {
		return pureRecursive.values();
	}

	/**
	 * Obtain, if present, the purely recursive production having the given LHS
	 * @param lhs the left-hand side
	 * @return the desired production, or null
	 */
	public AssemblyProduction getPureRecursion(AssemblyNonTerminal lhs) {
		return pureRecursive.get(lhs.getName());
	}
}
