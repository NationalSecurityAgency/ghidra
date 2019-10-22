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
package ghidra.app.plugin.core.symtable;

import ghidra.program.model.symbol.Symbol;

/**
 * A simple data object for the Name column table cell.  This class allows us to control
 * how sorting is performed by caching the slow (potentially) to calculate symbol name.
 */
class SymbolTableNameValue implements Comparable<SymbolTableNameValue> {

	private Symbol symbol;
	private String name;

	SymbolTableNameValue(Symbol symbol, String name) {
		this.symbol = symbol;
		this.name = name;

		// name will be non-null when cached by the table model
		if (name == null) {
			name = symbol.toString();
		}
	}

	Symbol getSymbol() {
		return symbol;
	}

	@Override
	public int compareTo(SymbolTableNameValue o) {
		return name.compareToIgnoreCase(o.name);
	}

	@Override
	public String toString() {
		return name;
	}
}
