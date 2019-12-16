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

import ghidra.program.database.symbol.CodeSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import ghidra.xml.XmlPullParser;

/**
 * A global symbol as part of the decompiler's model of a function. This symbol can
 * be backed by a formal CodeSymbol, obtained using getCodeSymbol(). This symbol can be backed
 * by a formal Data object, obtained using getData(). If there is a backing CodeSymbol, this takes its name,
 * otherwise the name is dynamically generated using SymbolUtilities. The data-type attached to this does
 * not necessarily match the backing CodeSymbol or Data object.
 */
public class HighCodeSymbol extends HighSymbol {

	private CodeSymbol symbol;

	/**
	 * Construct with a backing CodeSymbol.  An attempt is made to also find a backing Data object.
	 * @param sym is the backing CodeSymbol
	 * @param dataType is the (possibly distinct) data-type associated with the new HighSymbol
	 * @param sz is the storage size, in bytes, of the symbol
	 * @param func is the decompiler function model owning the new HighSymbol
	 */
	public HighCodeSymbol(CodeSymbol sym, DataType dataType, int sz, HighFunction func) {
		super(sym.getID(), sym.getName(), dataType, func);
		symbol = sym;
		setNameLock(true);
		setTypeLock(true);
		Data data = null;
		Object dataObj = symbol.getObject();
		if (dataObj instanceof Data) {
			data = (Data) dataObj;
		}
		VariableStorage store;
		try {
			store = new VariableStorage(symbol.getProgram(), symbol.getAddress(), sz);
		}
		catch (InvalidInputException e) {
			store = VariableStorage.UNASSIGNED_STORAGE;
		}
		SymbolEntry entry;
		if (data != null) {
			entry = new MappedDataEntry(this, store, data);
		}
		else {
			entry = new MappedEntry(this, store, null);
		}
		addMapEntry(entry);
	}

	/**
	 * Construct with just a (global) storage address and size. There will be no backing CodeSymbol.
	 * An attempt is made to find a backing Data object.
	 * @param id is the id to associate with the new HighSymbol
	 * @param addr is the starting Address of the symbol storage
	 * @param dataType is the data-type associated with the new symbol
	 * @param sz is the size of the symbol storage in bytes
	 * @param func is the decompiler function model owning the new symbol
	 */
	public HighCodeSymbol(long id, Address addr, DataType dataType, int sz, HighFunction func) {
		super(id, SymbolUtilities.getDynamicName(func.getFunction().getProgram(), addr), dataType,
			func);
		symbol = null;
		setNameLock(true);
		setTypeLock(true);
		Program program = func.getFunction().getProgram();
		Data data = program.getListing().getDataAt(addr);
		VariableStorage store;
		try {
			store = new VariableStorage(program, addr, sz);
		}
		catch (InvalidInputException e) {
			store = VariableStorage.UNASSIGNED_STORAGE;
		}
		SymbolEntry entry;
		if (data != null) {
			entry = new MappedDataEntry(this, store, data);
		}
		else {
			entry = new MappedEntry(this, store, null);
		}
		addMapEntry(entry);
	}

	/**
	 * Constructor for HighSymbol which is unattached to a HighFunction
	 * @param id is the unique id to assign
	 * @param nm is the name of the symbol
	 * @param data is an underlying Data object defining the storage and data-type
	 * @param dtmanage is the data-type manager for XML reference
	 */
	public HighCodeSymbol(long id, String nm, Data data, PcodeDataTypeManager dtmanage) {
		super(id, nm, data.getDataType(), true, true, dtmanage);
		Program program = dtmanage.getProgram();
		VariableStorage store;
		try {
			store = new VariableStorage(program, data.getMinAddress(), data.getLength());
		}
		catch (InvalidInputException e) {
			store = VariableStorage.UNASSIGNED_STORAGE;
		}
		SymbolEntry entry = new MappedDataEntry(this, store, data);
		addMapEntry(entry);
	}

	@Override
	public boolean isGlobal() {
		return true;
	}

	/**
	 * Get the CodeSymbol backing this, if it exists
	 * @return the CodeSymbol or null
	 */
	public CodeSymbol getCodeSymbol() {
		return symbol;
	}

	/**
	 * Get the Data object backing this, if it exists
	 * @return the Data object or null
	 */
	public Data getData() {
		SymbolEntry entry = entryList[0];
		if (entry instanceof MappedDataEntry) {
			return ((MappedDataEntry) entry).getData();
		}
		return null;
	}

	@Override
	public void restoreXML(XmlPullParser parser) throws PcodeXMLException {
		super.restoreXML(parser);
		symbol = null;
	}

}
