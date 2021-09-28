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
import ghidra.program.database.util.*;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

/**
 *
 * Iterator (in address order) over all symbols that match the given query in an address set.
 * 
 * 
 */
class AddressSetFilteredSymbolIterator implements SymbolIterator {
	private SymbolManager symbolMgr;
	private QueryRecordIterator recIter;
	private SymbolDatabaseAdapter adapter;

	/**
	 * Construct a new AddressSetFilteredSymbolIterator.
	 * @param symbolMgr the symbol manager
	 * @param set the address set to iterator over (required).
	 * @param query the query to use as a filter
	 * @param forward the direction of the iterator.
	 */
	AddressSetFilteredSymbolIterator(SymbolManager symbolMgr, AddressSetView set, Query query,
			boolean forward) {
		this.symbolMgr = symbolMgr;
		adapter = symbolMgr.getDatabaseAdapter();
		try {
			RecordIterator it = adapter.getSymbols(set, forward);
			recIter = new QueryRecordIterator(it, query, forward);
		}
		catch (IOException e) {
			symbolMgr.dbError(e);
			recIter = new QueryRecordIterator(new EmptyRecordIterator(), query, forward);
		}
	}

	@Override
	public boolean hasNext() {
		try {
			return recIter.hasNext();
		}
		catch (IOException e) {
			symbolMgr.dbError(e);
		}
		return false;
	}

	@Override
	public Symbol next() {
		if (hasNext()) {
			try {
				DBRecord rec = recIter.next();
				return symbolMgr.getSymbol(rec);
			}
			catch (IOException e) {
				symbolMgr.dbError(e);
			}
		}
		return null;
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
