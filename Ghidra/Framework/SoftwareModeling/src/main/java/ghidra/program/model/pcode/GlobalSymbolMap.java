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
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/**
 * A container for global symbols in the decompiler's model of a function. It contains
 * HighSymbol objects for any symbol accessed by the particular function that is in either
 * the global scope or some other global namespace. Currently the container is populated
 * indirectly from the HighGlobal objects marshaled back from the decompiler, using either
 * the populateSymbol() or newSymbol() methods. HighSymbols are stored by Address and by id,
 * which matches the formal SymbolDB id when it exists.
 */
public class GlobalSymbolMap {
	private Program program;
	private HighFunction func;			// Is the full decompiler model of the function to which this belongs
	private SymbolTable symbolTable;	// Used for cross-referencing with Ghidra's database backed Symbols
	private HashMap<Address, HighSymbol> addrMappedSymbols;	// Look up symbols by address
	private HashMap<Long, HighSymbol> symbolMap;  			// Look up symbol by id
	private long uniqueSymbolId;		// Next available symbol id

	/**
	 * Construct a global symbol map attached to a particular function model.
	 * @param f is the decompiler function model
	 */
	public GlobalSymbolMap(HighFunction f) {
		program = f.getFunction().getProgram();
		func = f;
		symbolTable = program.getSymbolTable();
		addrMappedSymbols = new HashMap<Address, HighSymbol>();
		symbolMap = new HashMap<Long, HighSymbol>();
		uniqueSymbolId = 0;
	}

	private void insertSymbol(HighSymbol sym, Address addr) {
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
	 * Create a HighSymbol based on the id of the underlying Ghidra Symbol. The Symbol
	 * is looked up in the SymbolTable and then a HighSymbol is created with the name and
	 * dataType associated with the Symbol. If a Symbol cannot be found, null is returned.
	 * @param id is the database id of the CodeSymbol
	 * @param dataType is the recovered data-type of the symbol
	 * @param sz is the size in bytes of the desired symbol
	 * @return the CodeSymbol wrapped as a HighSymbol or null
	 */
	public HighSymbol populateSymbol(long id, DataType dataType, int sz) {
		if ((id >> 56) == (HighSymbol.ID_BASE >> 56)) {
			return null;		// This is an internal id, not a database key
		}
		Symbol symbol = symbolTable.getSymbol(id);
		if (symbol == null) {
			return null;
		}
		HighSymbol highSym = null;
		if (symbol instanceof CodeSymbol) {
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
			highSym = new HighCodeSymbol((CodeSymbol) symbol, dataType, sz, func);
		}
		else if (symbol instanceof FunctionSymbol) {
			highSym = new HighFunctionShellSymbol(id, symbol.getName(), symbol.getAddress(),
				func.getDataTypeManager());
		}
		else {
			return null;
		}
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
		if (dataType == null) {
			dataType = DataType.DEFAULT;
			sz = 1;
		}
		HighCodeSymbol symbol = new HighCodeSymbol(id, addr, dataType, sz, func);
		insertSymbol(symbol, addr);
		return symbol;
	}

	/**
	 * Retrieve a HighSymbol based on an id
	 * @param id is the id
	 * @return the matching HighSymbol or null
	 */
	public HighSymbol getSymbol(long id) {
		return symbolMap.get(id);
	}

	/**
	 * Retrieve a HighSymbol based on an Address
	 * @param addr is the given Address
	 * @return the matching HighSymbol or null
	 */
	public HighSymbol getSymbol(Address addr) {
		return addrMappedSymbols.get(addr);
	}

	/**
	 * Get an iterator over all HighSymbols in this container
	 * @return the iterator
	 */
	public Iterator<HighSymbol> getSymbols() {
		return symbolMap.values().iterator();
	}
}
