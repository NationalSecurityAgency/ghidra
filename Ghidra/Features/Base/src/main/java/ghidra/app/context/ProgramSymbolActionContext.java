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
package ghidra.app.context;

import java.awt.Component;
import java.util.Iterator;
import java.util.NoSuchElementException;

import docking.ComponentProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ProgramSymbolActionContext extends ProgramActionContext {

	private final long[] symbolIDs;

	public ProgramSymbolActionContext(ComponentProvider provider, Program program, long[] symbolIDs,
			Component sourceComponent) {
		super(provider, program, sourceComponent);
		this.symbolIDs = symbolIDs;
	}

	public int getSymbolCount() {
		return symbolIDs != null ? symbolIDs.length : 0;
	}

	public Symbol getFirstSymbol() {
		if (symbolIDs == null || symbolIDs.length == 0) {
			return null;
		}
		return program.getSymbolTable().getSymbol(symbolIDs[0]);
	}

	public SymbolIterator getSymbols() {
		return new MySymbolIterator();
	}

	private class MySymbolIterator implements SymbolIterator {

		private int index = -1;
		private Symbol symbol = null;

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Symbol> iterator() {
			return this;
		}

		@Override
		public boolean hasNext() {
			if (symbol != null) {
				return true;
			}
			if (symbolIDs == null) {
				return false;
			}
			while (index < (symbolIDs.length - 1)) {
				symbol = program.getSymbolTable().getSymbol(symbolIDs[++index]);
				if (symbol != null) {
					return true;
				}
			}
			return false;
		}

		@Override
		public Symbol next() {
			if (hasNext()) {
				Symbol s = symbol;
				symbol = null;
				return s;
			}
			throw new NoSuchElementException();
		}

	}
}
