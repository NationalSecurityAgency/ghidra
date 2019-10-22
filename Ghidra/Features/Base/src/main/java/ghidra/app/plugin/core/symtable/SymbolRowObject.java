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

class SymbolRowObject implements Comparable<SymbolRowObject> {

	// symbol can be null after it is deleted
	private final Symbol symbol;
	private final long key;

	SymbolRowObject(Symbol s) {
		this.symbol = s;
		this.key = s.getID();
	}

	// this constructor is used to create a row object to serve as a key for deleting items
	// in the model after a symbol has been deleted
	SymbolRowObject(long symbolId) {
		this.symbol = null;
		this.key = symbolId;
	}

	Symbol getSymbol() {
		return symbol;
	}

	long getKey() {
		return key;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (int) (key ^ (key >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		SymbolRowObject other = (SymbolRowObject) obj;
		if (key != other.key) {
			return false;
		}
		return true;
	}

	@Override
	public int compareTo(SymbolRowObject o) {
		return ((Long) key).compareTo(o.key);
	}
}
