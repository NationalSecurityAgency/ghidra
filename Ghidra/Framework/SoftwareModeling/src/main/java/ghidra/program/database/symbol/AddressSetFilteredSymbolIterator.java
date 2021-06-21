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
package ghidra.program.database.symbol;

import java.io.IOException;
import java.util.Iterator;

import db.DBRecord;
import db.RecordIterator;
import ghidra.program.database.util.Query;
import ghidra.program.database.util.QueryRecordIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

/**
 *
 * Iterator (in address order) over primary symbols in an address set.
 * 
 * 
 */
class AddressSetFilteredSymbolIterator implements SymbolIterator {
	private SymbolManager symbolMgr;
	private AddressRangeIterator rangeIter;
	private QueryRecordIterator recIter;
	private Symbol currentSymbol;
	private SymbolDatabaseAdapter adapter;
	private boolean forward;
	private Query query;

	/**
	 * Construct a new AddressSetFilteredSymbolIterator.
	 * @param symbolMgr the symbol manager
	 * @param set the address set to iterator over.
	 * @param query the query to use as a filter
	 * @param forward the direction of the iterator.
	 */
	AddressSetFilteredSymbolIterator(SymbolManager symbolMgr, AddressSetView set, Query query,
			boolean forward) {
		this.symbolMgr = symbolMgr;
		rangeIter = set.getAddressRanges(forward);
		adapter = symbolMgr.getDatabaseAdapter();
		this.forward = forward;
		this.query = query;
	}

	@Override
	public boolean hasNext() {
		if (currentSymbol == null) {
			try {
				findNext();
			}
			catch (IOException e) {
				symbolMgr.dbError(e);
			}
		}
		return currentSymbol != null;
	}

	@Override
	public Symbol next() {
		if (hasNext()) {
			Symbol s = currentSymbol;
			currentSymbol = null;
			return s;
		}
		return null;
	}

	private void findNext() throws IOException {
		if (recIter != null && recIter.hasNext()) {
			DBRecord rec = recIter.next();
			currentSymbol = symbolMgr.getSymbol(rec);
		}
		else {
			while (rangeIter.hasNext()) {
				AddressRange range = rangeIter.next();
				RecordIterator it =
					adapter.getSymbols(range.getMinAddress(), range.getMaxAddress(), forward);
				recIter = new QueryRecordIterator(it, query, forward);
				if (recIter.hasNext()) {
					DBRecord rec = recIter.next();
					currentSymbol = symbolMgr.getSymbol(rec);
					break;
				}
			}
		}
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Iterator<Symbol> iterator() {
		return this;
	}
}
