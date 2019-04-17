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

import java.io.PrintStream;
import java.util.*;

import org.apache.commons.collections4.MultiValuedMap;

import ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.grammars.AbstractAssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.symbol.*;
import ghidra.generic.util.datastruct.TreeSetValuedTreeMap;

/**
 * A class to compute the first and follow of every non-terminal in a grammar
 * 
 * See Alfred V. Aho, Monica S. Lam, Ravi Sethi, Jeffrey D. Ullman, <i>Compilers: Principles,
 * Techniques, &amp; Tools</i>. Bostom, MA: Pearson, 2007, pp. 220-2.
 */
public class AssemblyFirstFollow {
	private final AbstractAssemblyGrammar<?, ?> grammar;

	// non-terminals which may derive epsilon
	private final Set<AssemblyNonTerminal> nullable = new TreeSet<>();
	private final MultiValuedMap<AssemblyNonTerminal, AssemblyTerminal> first =
		new TreeSetValuedTreeMap<>();
	private final MultiValuedMap<AssemblyNonTerminal, AssemblyTerminal> follow =
		new TreeSetValuedTreeMap<>();

	/**
	 * Compute the first and follow sets for every non-terminal in the given grammar
	 * @param grammar the grammar
	 */
	public AssemblyFirstFollow(AbstractAssemblyGrammar<?, ?> grammar) {
		this.grammar = grammar;

		computeNullable();
		computeFirsts();
		computeFollows();
	}

	/**
	 * Compute the nullable set
	 */
	protected void computeNullable() {
		boolean changed = true;
		while (changed) {
			changed = false;
			for (AbstractAssemblyProduction<?> prod : grammar) {
				if (nullable.containsAll(prod)) {
					changed |= nullable.add(prod.getLHS());
				}
			}
		}
	}

	/**
	 * Compute the first set for each non-terminal
	 */
	protected void computeFirsts() {
		boolean changed = true;
		while (changed) {
			changed = false;
			// [A] => 'a' ALPHA implies 'a' in First[A]
			// [A] => ALPHA [X] BETA  implies First[A] includes First[X] and First(ALPHA)
			// Walk each production from the left over nullable non-terminals
			// Add the first of all each symbol
			// Terminate after a terminal or non-nullable symbol
			for (AbstractAssemblyProduction<?> prod : grammar) {
				for (AssemblySymbol sym : prod) {
					if (sym instanceof AssemblyNonTerminal) {
						AssemblyNonTerminal nt = (AssemblyNonTerminal) sym;
						changed |= first.putAll(prod.getLHS(), first.get(nt));
						if (!nullable.contains(sym)) {
							break; // next production
						}
					}
					else if (sym instanceof AssemblyTerminal) {
						AssemblyTerminal t = (AssemblyTerminal) sym;
						changed |= first.put(prod.getLHS(), t);
						break; // next production
					}
				}
			}
		}
	}

	/**
	 * Compute the follow set for each non-terminal
	 */
	protected void computeFollows() {
		// Put EOI after the start symbol
		// follow.put(grammar.getStart(), AssemblyEOI.EOI);

		boolean changed = true;
		while (changed) {
			changed = false;
			// [A] => ... [X] ALPHA [B] ... implies Follow[X] includes First(ALPHA) and First[B]
			// [A] => ... [B] ALPHA implies Follow[B] includes Follow[A]
			// Walk each production from left, scanning for non-terminals
			// For each, walk to the right, adding the first of each to the current (not LHS)
			// Finish the subwalk after a terminal or non-nullable symbol
			// If you hit the end, add follow(LHS) to follow the current symbol
			for (AbstractAssemblyProduction<?> prod : grammar) {
				nextX: for (int i = 0; i < prod.size(); i++) {
					AssemblySymbol px = prod.get(i);
					if (px instanceof AssemblyNonTerminal) {
						AssemblyNonTerminal X = (AssemblyNonTerminal) px;
						int j;
						for (j = i + 1; j < prod.size(); j++) {
							AssemblySymbol B = prod.get(j);
							if (B instanceof AssemblyNonTerminal) {
								AssemblyNonTerminal nt = (AssemblyNonTerminal) B;
								changed |= follow.putAll(X, first.get(nt));
								if (!nullable.contains(B)) {
									continue nextX;
								}
							}
							else if (B instanceof AssemblyTerminal) {
								AssemblyTerminal t = (AssemblyTerminal) B;
								changed |= follow.put(X, t);
								continue nextX;
							}
						}
						// If I got here, I never encountered a non-nullable symbol
						// Do a simple substitution for understanding:
						//    [A] => ... [X] ALPHA  (we never hit non-nullable B)
						changed |= follow.putAll(X, follow.get(prod.getLHS()));
					}
				}
			}
		}
	}

	/**
	 * Get the nullable set
	 * 
	 * That is the set of all non-terminals, which through some derivation, can produce epsilon.
	 * @return the set
	 */
	public Collection<AssemblyNonTerminal> getNullable() {
		return Collections.unmodifiableSet(nullable);
	}

	/**
	 * Get the first set for a given non-terminal
	 * 
	 * That is the set of all terminals, which through some derivation from the given non-terminal,
	 * can appear first in a sentential form.
	 * @param nt the non-terminal
	 * @return the set
	 */
	public Collection<AssemblyTerminal> getFirst(AssemblyNonTerminal nt) {
		return Collections.unmodifiableCollection(first.get(nt));
	}

	/**
	 * Get the follow set for a given non-terminal
	 * 
	 * That is the set of all terminals, which through some derivation from the start symbol, can
	 * appear immediately after the given non-terminal in a sentential form.
	 * @param nt the non-terminal
	 * @return the set
	 */
	public Collection<AssemblyTerminal> getFollow(AssemblyNonTerminal nt) {
		return Collections.unmodifiableCollection(follow.get(nt));
	}

	/**
	 * For debugging, print out the computed sets to the given stream
	 * @param out the stream
	 */
	public void print(PrintStream out) {
		out.print("Nullable: ");
		for (AssemblyNonTerminal nt : nullable) {
			out.print(nt + " ");
		}
		out.println();
		out.println("Firsts:");
		for (AssemblyNonTerminal nt : grammar.nonTerminals()) {
			out.print(nt + "\t");
			for (AssemblyTerminal f : first.get(nt)) {
				out.print(f + " ");
			}
			out.println();
		}
		out.println("Follows:");
		for (AssemblyNonTerminal nt : grammar.nonTerminals()) {
			out.print(nt + "\t");
			for (AssemblyTerminal f : follow.get(nt)) {
				out.print(f + " ");
			}
			out.println();
		}
	}
}
