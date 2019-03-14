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
package ghidra.app.plugin.assembler.sleigh.util;

import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseActionGotoTable;
import ghidra.app.plugin.assembler.sleigh.parse.AssemblyParseTransitionTable;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblySymbol;

/**
 * An entry in a (sparse) LR(0) transition table or LALR(1) action/goto table
 *
 * @see AssemblyParseTransitionTable
 * @see AssemblyParseActionGotoTable
 * @param <T> the type of each entry in a table cell
 */
public class TableEntry<T> extends TableEntryKey {
	private final T value;

	/**
	 * Create a new table entry with the given value at the given state and symbol
	 * @param state the row
	 * @param sym the column
	 * @param value the value
	 */
	public TableEntry(int state, AssemblySymbol sym, T value) {
		super(state, sym);
		this.value = value;
	}

	/**
	 * Get the value of the entry
	 * @return the value
	 */
	public T getValue() {
		return value;
	}
}
