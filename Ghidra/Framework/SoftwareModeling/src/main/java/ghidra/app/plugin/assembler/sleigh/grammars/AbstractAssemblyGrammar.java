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

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.apache.commons.collections4.MultiValuedMap;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal;
import ghidra.generic.util.datastruct.TreeSetValuedTreeMap;

/**
 * Defines a context-free grammar, usually for the purpose of parsing mnemonic assembly instructions
 * 
 * As in classic computer science, a CFG consists of productions of non-terminals and terminals.
 * The left-hand side of the a production must be a single non-terminal, but the right-hand side
 * may be any string of symbols. To avoid overloading the term "String," here we call it a
 * "Sentential."
 * 
 * To define a grammar, simply construct an appropriate subclass (probably {@link AssemblyGrammar})
 * and call {@link #addProduction(AbstractAssemblyProduction)} or
 * {@link #addProduction(AssemblyNonTerminal, AssemblySentential)}. The grammar object will collect
 * the non-terminals and terminals.
 * 
 * By default, the start symbol is taken from the left-hand side of the first production added to
 * the grammar.
 * 
 * @param <NT> the type of non-terminals
 * @param <P> the type of productions, which must have the same types of (non-)terminals.
 */
public abstract class AbstractAssemblyGrammar<NT extends AssemblyNonTerminal, P extends AbstractAssemblyProduction<NT>>
		implements Iterable<P> {
	protected final MultiValuedMap<String, P> productions = new TreeSetValuedTreeMap<>();
	protected final List<P> prodList = new ArrayList<>();
	protected final Map<String, NT> nonterminals = new TreeMap<>();
	protected final Map<String, AssemblyTerminal> terminals = new TreeMap<>();
	protected final Map<String, AssemblySymbol> symbols = new TreeMap<>();
	protected String startName;

	/**
	 * Because a subclass may have a different type of production, it must provide a mechanism for
	 * constructing an appropriate production given just the LHS and RHS.
	 * 
	 * @param lhs the left-hand side of the production
	 * @param rhs the right-hand side of the production
	 * @return the constructed production
	 */
	protected abstract P newProduction(NT lhs, AssemblySentential<NT> rhs);

	/**
	 * Add a production to the grammar
	 * @param lhs the left-hand side
	 * @param rhs the right-hand side
	 */
	public void addProduction(NT lhs, AssemblySentential<NT> rhs) {
		P prod = newProduction(lhs, rhs);
		addProduction(prod);
	}

	/**
	 * Add a production to the grammar
	 * @param prod the production
	 */
	public void addProduction(P prod) {
		String lname = prod.getName();
		if (productions.put(lname, prod)) {
			prod.idx = prodList.size();
			prodList.add(prod);
		}
		NT lhs = prod.getLHS();
		if (startName == null) {
			setStart(lhs);
		}
		String lhsName = lhs.getName();
		symbols.put(lhsName, lhs);
		nonterminals.put(lhsName, lhs);
		for (AssemblySymbol sym : prod) {
			if (sym instanceof AssemblyNonTerminal) {
				@SuppressWarnings("unchecked")
				NT nt = (NT) sym;
				String name = nt.getName();
				symbols.put(name, nt);
				nonterminals.put(name, nt);
			}
			else {
				AssemblyTerminal t = (AssemblyTerminal) sym;
				String name = t.getName();
				symbols.put(name, t);
				terminals.put(name, t);
			}
		}
	}

	/**
	 * Check if the given production is purely recursive, i.e., of the form I =&gt; I
	 * @param prod the production to check
	 * @return true iff the production is purely recursive
	 */
	protected boolean isPureRecursive(P prod) {
		if (prod.size() != 1) {
			return false;
		}
		if (!prod.getLHS().equals(prod.getRHS().get(0))) {
			return false;
		}
		return true;
	}

	/**
	 * Change the start symbol for the grammar
	 * @param nt the new start symbol
	 */
	public void setStart(AssemblyNonTerminal nt) {
		setStartName(nt == null ? null : nt.getName());
	}

	/**
	 * Change the start symbol for the grammar
	 * @param startName the name of the new start symbol
	 */
	public void setStartName(String startName) {
		this.startName = startName;
	}

	/**
	 * Get the start symbol for the grammar
	 * @return the start symbol
	 */
	public NT getStart() {
		return nonterminals.get(startName);
	}

	/**
	 * Get the name of the start symbol for the grammar
	 * @return the name of the start symbol
	 */
	public String getStartName() {
		return startName;
	}

	/**
	 * Get the named non-terminal
	 * @param name the name of the desired non-terminal
	 * @return the non-terminal, or null if it is not in this grammar
	 */
	public NT getNonTerminal(String name) {
		return nonterminals.get(name);
	}

	/**
	 * Get the named terminal
	 * @param name the name of the desired terminal
	 * @return the terminal, or null if it is not in this grammar
	 */
	public AssemblyTerminal getTerminal(String name) {
		return terminals.get(name);
	}

	/**
	 * Add all the productions of a given grammar to this one
	 * @param that the grammar whose productions to add
	 */
	public void combine(AbstractAssemblyGrammar<NT, P> that) {
		for (P prod : that.prodList) {
			addProduction(prod);
		}
	}

	/**
	 * Print the productions of this grammar to the given stream
	 * @param out the stream
	 */
	public void print(PrintStream out) {
		for (P prod : prodList) {
			out.println(prod);
		}
	}

	/**
	 * Check that the grammar is consistent
	 * 
	 * The grammar is consistent if every non-terminal appearing in the grammar, also appears as
	 * the left-hand side of some production. If not, such non-terminals are said to be undefined.
	 * @throws AssemblyGrammarException the grammar is inconsistent, i.e., contains undefined
	 *                                  non-terminals.
	 */
	public void verify() throws AssemblyGrammarException {
		if (!productions.containsKey(startName)) {
			throw new AssemblyGrammarException("Start symbol has no defining production");
		}
		for (P prod : productions.values()) {
			for (AssemblySymbol sym : prod) {
				if (sym instanceof AssemblyNonTerminal) {
					AssemblyNonTerminal nt = (AssemblyNonTerminal) sym;
					if (!(productions.containsKey(nt.getName()))) {
						throw new AssemblyGrammarException("Grammar has non-terminal '" +
							nt.getName() + "' without a defining production");
					}
				}
			}
		}
	}

	/**
	 * Traverse the productions
	 */
	@Override
	public Iterator<P> iterator() {
		return Collections.unmodifiableList(prodList).iterator();
	}

	/**
	 * Get the non-terminals
	 * @return
	 */
	public Collection<NT> nonTerminals() {
		return Collections.unmodifiableCollection(nonterminals.values());
	}

	/**
	 * Get the terminals
	 * @return
	 */
	public Collection<AssemblyTerminal> terminals() {
		return Collections.unmodifiableCollection(terminals.values());
	}

	/**
	 * Get all productions where the left-hand side non-terminal has the given name
	 * @param name the name of the non-terminal
	 * @return all productions "defining" the named non-terminal
	 */
	public Collection<P> productionsOf(String name) {
		if (!productions.containsKey(name)) {
			return Collections.emptySet();
		}
		return productions.get(name);
	}

	/**
	 * Get all productions where the left-hand side is the given non-terminal
	 * @param nt the non-terminal whose defining productions to find
	 * @return all productions "defining" the given non-terminal
	 */
	public Collection<P> productionsOf(AssemblyNonTerminal nt) {
		return productionsOf(nt.getName());
	}

	/**
	 * Check if the grammar contains any symbol with the given name
	 * @param name the name to find
	 * @return true iff a terminal or non-terminal has the given name
	 */
	public boolean contains(String name) {
		return symbols.containsKey(name);
	}
}
