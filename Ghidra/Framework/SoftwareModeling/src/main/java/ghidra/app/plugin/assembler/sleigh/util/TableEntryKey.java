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
 * A key in a (sparse) LR(0) transition table or LALR(1) action/goto table
 * 
 * @see AssemblyParseTransitionTable
 * @see AssemblyParseActionGotoTable
 */
public class TableEntryKey implements Comparable<TableEntryKey> {
	private final int state;
	private final AssemblySymbol sym;

	/**
	 * Create a new key for the given state and symbol
	 * @param state the row
	 * @param sym the column
	 */
	public TableEntryKey(int state, AssemblySymbol sym) {
		this.state = state;
		this.sym = sym;
	}

	@Override
	public int hashCode() {
		int result = 0;
		result += state;
		result *= 31;
		result += sym.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object that) {
		if (!(that instanceof TableEntryKey)) {
			return false;
		}
		TableEntryKey ek = (TableEntryKey) that;
		if (this.state != ek.state) {
			return false;
		}
		if (!this.sym.equals(ek.sym)) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(TableEntryKey that) {
		int result;
		result = this.state - that.state;
		if (result != 0) {
			return result;
		}
		result = this.sym.compareTo(that.sym);
		if (result != 0) {
			return result;
		}
		return 0;
	}

	/**
	 * Get the state (row) of the key in the table
	 * @return the state
	 */
	public int getState() {
		return state;
	}

	/**
	 * Get the symbol (column) of the entry in the table
	 * @return the symbol
	 */
	public AssemblySymbol getSym() {
		return sym;
	}
}
