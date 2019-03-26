/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.program.database.symbol;

import ghidra.program.model.symbol.*;

import java.util.Iterator;

/**
 * Filters a symbol iterator to only return a specific symbol type
 */
public class TypeFilteredSymbolIterator implements SymbolIterator {
	private SymbolIterator it;
	private SymbolType type;
	private Symbol nextSymbol;

	/**
	 * Construct a new TypeFilteredSymbolIterator
	 * @param it the symbol iterator to filter
	 * @param type the symbol type to filter on.
	 */
	public TypeFilteredSymbolIterator(SymbolIterator it, SymbolType type) {
		this.it = it;
		this.type = type;
	}

	/**
	 * @see ghidra.program.model.symbol.SymbolIterator#hasNext()
	 */
	public boolean hasNext() {
		if (nextSymbol != null) {
			return true;
		}
		return findNext();
	}

	/**
	 * @see ghidra.program.model.symbol.SymbolIterator#next()
	 */
	public Symbol next() {
		if (hasNext()) {
			Symbol s = nextSymbol;
			nextSymbol = null;
			return s;
		}
		return null;
	}

	private boolean findNext() {
		while (it.hasNext()) {
			Symbol s = it.next();
			if (s.getSymbolType() == type) {
				nextSymbol = s;
				return true;
			}
		}
		return false;
	}

	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Symbol> iterator() {
		return this;
	}

}
