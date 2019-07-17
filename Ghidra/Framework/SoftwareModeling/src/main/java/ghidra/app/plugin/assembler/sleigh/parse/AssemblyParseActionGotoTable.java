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

import java.util.Collection;

import org.apache.commons.collections4.MultiValuedMap;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyProduction;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyEOI;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNonTerminal;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal;
import ghidra.app.plugin.assembler.sleigh.util.TableEntryKey;
import ghidra.generic.util.datastruct.TreeSetValuedTreeMap;

/**
 * The Action/Goto table for a LALR(1) parser
 * 
 * This table is unconventional in that it permits a single cell to be populated by more than one
 * action. Typically, such a situation would indicate an ambiguity, or the need for a longer
 * look-ahead value. Because we do not presume to control the grammar (which was automatically
 * derived from another source), the parsing algorithm will simply branch, eventually trying both
 * options.
 */
public class AssemblyParseActionGotoTable {
	// A map representing the actual (sparse) table
	protected final MultiValuedMap<TableEntryKey, Action> map = new TreeSetValuedTreeMap<>();
	// A map tracking the terminal columns for each state (optimization)
	protected final MultiValuedMap<Integer, AssemblyTerminal> possibleTerms =
		new TreeSetValuedTreeMap<>();

	/**
	 * Add an action entry to the given cell
	 * @param fromState the state (row) in the table
	 * @param next the symbol (column) in the table
	 * @param action the entry to add to the cell
	 * @return true, if the given entry was not already present
	 */
	public boolean put(int fromState, AssemblySymbol next, Action action) {
		if (next instanceof AssemblyTerminal) {
			possibleTerms.put(fromState, (AssemblyTerminal) next);
		}
		return map.put(new TableEntryKey(fromState, next), action);
	}

	/**
	 * Add a SHIFT (S<i>n</i>) entry to the given cell
	 * @param fromState the state (row) in the table
	 * @param next the symbol (column) in the table
	 * @param newState the state (<i>n</i>) after the shift is applied
	 * @return true, if the given entry was not already present
	 */
	public boolean putShift(int fromState, AssemblyTerminal next, int newState) {
		return put(fromState, next, new ShiftAction(newState));
	}

	/**
	 * Add a REDUCE (R<i>n</i>) entry to the given cell
	 * @param fromState the state (row) in the table
	 * @param next the symbol (column) in the table
	 * @param prod the production (having index <i>n</i>) associated with the reduction
	 * @return true, if the given entry was not already present
	 */
	public boolean putReduce(int fromState, AssemblyTerminal next, AssemblyProduction prod) {
		return put(fromState, next, new ReduceAction(prod));
	}

	/**
	 * Add a GOTO entry to the given cell
	 * @param fromState the state (row) in the table
	 * @param next the symbol (column) in the table
	 * @param newState the target state
	 * @return true, if the given entry was not already present
	 */
	public boolean putGoto(int fromState, AssemblyNonTerminal next, int newState) {
		return put(fromState, next, new GotoAction(newState));
	}

	/**
	 * Add an ACCEPT entry for the given state at the end of input
	 * @param fromState the state (row) in the table
	 * @return true, if the state does not already accept on end of input
	 */
	public boolean putAccept(int fromState) {
		return put(fromState, AssemblyEOI.EOI, AcceptAction.ACCEPT);
	}

	/**
	 * Get the terminals that are expected, i.e., have entries for the given state
	 * @param fromState the state (row) in the table
	 * @return the collection of populated columns (terminals) for the given state
	 */
	public Collection<AssemblyTerminal> getExpected(int fromState) {
		return possibleTerms.get(fromState);
	}

	/**
	 * Get all entries in a given cell
	 * @param fromState the state (row) in the table
	 * @param next the symbol (column) in the table
	 * @return all action entries in the given cell
	 */
	public Collection<Action> get(int fromState, AssemblySymbol next) {
		return map.get(new TableEntryKey(fromState, next));
	}

	/**
	 * An action in the Action/Goto table
	 */
	public static abstract class Action implements Comparable<Action> {
		@Override
		public int hashCode() {
			return toString().hashCode();
		}

		@Override
		public boolean equals(Object that) {
			if (!(that instanceof Action)) {
				return false;
			}
			return this.toString().equals(that.toString());
		}

		@Override
		public int compareTo(Action that) {
			return this.toString().compareTo(that.toString());
		}
	}

	/**
	 * A SHIFT (S<i>n</i>) entry
	 */
	public static class ShiftAction extends Action {
		protected int newStateNum;

		public ShiftAction(int newStateNum) {
			this.newStateNum = newStateNum;
		}

		@Override
		public String toString() {
			return "S" + newStateNum;
		}
	}

	/**
	 * A REDUCE (R<i>n</i>) entry
	 */
	public static class ReduceAction extends Action {
		protected AssemblyProduction prod;

		public ReduceAction(AssemblyProduction prod) {
			this.prod = prod;
		}

		@Override
		public String toString() {
			return "R" + prod.getIndex();
		}
	}

	/**
	 * A GOTO (G<i>n</i>) entry
	 */
	public static class GotoAction extends Action {
		protected int newStateNum;

		public GotoAction(int newStateNum) {
			this.newStateNum = newStateNum;
		}

		@Override
		public String toString() {
			return "G" + newStateNum;
		}
	}

	/**
	 * An ACCEPT (acc) entry
	 */
	public static class AcceptAction extends Action {
		public static final AcceptAction ACCEPT = new AcceptAction();

		@Override
		public String toString() {
			return "acc";
		}
	}
}
