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
package ghidra.program.model.pcode;

import java.util.HashMap;
import java.util.Iterator;

import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class GlobalSymbolMap {
	private Program program;
	private HighFunction func;
	private SymbolTable symbolTable;
	private HashMap<Address, HighCodeSymbol> addrMappedSymbols;	// Hashed by addr
	private HashMap<Long, HighCodeSymbol> symbolMap;  			// Hashed by unique key
	private long uniqueSymbolId;		// Next available symbol id

	public GlobalSymbolMap(HighFunction f) {
		program = f.getFunction().getProgram();
		func = f;
		symbolTable = program.getSymbolTable();
		addrMappedSymbols = new HashMap<Address, HighCodeSymbol>();
		symbolMap = new HashMap<Long, HighCodeSymbol>();
		uniqueSymbolId = 0;
	}

	private void insertSymbol(HighCodeSymbol sym, Address addr) {
		long uniqueId = sym.getId();
		if ((uniqueId >> 56) == (HighSymbol.ID_BASE >> 56)) {
			long val = uniqueId & 0x7fffffff;
			if (val > uniqueSymbolId) {
				uniqueSymbolId = val;
			}
		}
		symbolMap.put(uniqueId, sym);
		addrMappedSymbols.put(addr, sym);
	}

	/**
	 * Create a HighCodeSymbol based on the id of the underlying CodeSymbol. The CodeSymbol
	 * is looked up in the SymbolTable and then a HighSymbol is created with the name and
	 * dataType associated with the CodeSymbol. If a CodeSymbol cannot be found, null is returned.
	 * @param id is the database id of the CodeSymbol
	 * @param dataType is the recovered data-type of the symbol
	 * @param sz is the size in bytes of the desired symbol
	 * @return the CodeSymbol wrapped as a HighSymbol or null
	 */
	public HighCodeSymbol populateSymbol(long id, DataType dataType, int sz) {
		if ((id >> 56) == (HighSymbol.ID_BASE >> 56)) {
			return null;		// This is an internal id, not a database key
		}
		Symbol symbol = symbolTable.getSymbol(id);
		if (symbol == null || !(symbol instanceof CodeSymbol)) {
			return null;
		}
		if (dataType == null) {
			Object dataObj = symbol.getObject();
			if (dataObj instanceof Data) {
				dataType = ((Data) dataObj).getDataType();
				sz = dataType.getLength();
			}
			else {
				dataType = DataType.DEFAULT;
				sz = 1;
			}
		}
		HighCodeSymbol highSym = new HighCodeSymbol((CodeSymbol) symbol, dataType, sz, func);
		insertSymbol(highSym, symbol.getAddress());
		return highSym;
	}

	/**
	 * Create a HighSymbol corresponding to an underlying Data object. The name of the symbol is
	 * generated dynamically. A symbol is always returned unless the address is invalid,
	 * in which case null is returned.
	 * @param id is the id to associate with the new symbol
	 * @param addr is the address of the Data object
	 * @param dataType is the recovered data-type of the symbol
	 * @param sz is the size in bytes of the symbol
	 * @return the new HighSymbol or null
	 */
	public HighCodeSymbol newSymbol(long id, Address addr, DataType dataType, int sz) {
		HighCodeSymbol symbol = new HighCodeSymbol(id, addr, dataType, sz, func);
		insertSymbol(symbol, addr);
		return symbol;
	}

	public HighCodeSymbol getSymbol(long id) {
		return symbolMap.get(id);
	}

	public HighCodeSymbol getSymbol(Address addr) {
		return addrMappedSymbols.get(addr);
	}

	public Iterator<HighCodeSymbol> getSymbols() {
		return symbolMap.values().iterator();
	}
}
