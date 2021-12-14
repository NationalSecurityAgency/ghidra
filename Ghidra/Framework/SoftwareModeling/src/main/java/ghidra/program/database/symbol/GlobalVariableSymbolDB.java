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

import db.DBRecord;
import ghidra.program.database.DBObjectCache;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.AssertException;

public class GlobalVariableSymbolDB extends VariableSymbolDB {

	// NOTE: global variable symbols are not yet supported (API does not yet facilitate creation)

	/**
	 * Constructs a new GlobalVariableSymbolDB which are restricted to the global namespace
	 * @param symbolMgr the symbol manager
	 * @param cache symbol object cache
	 * @param variableMgr variable storage manager
	 * @param address the address of the symbol (stack address)
	 * @param record the record for the symbol
	 */
	public GlobalVariableSymbolDB(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache,
			VariableStorageManagerDB variableMgr, Address address, DBRecord record) {
		super(symbolMgr, cache, SymbolType.GLOBAL_VAR, variableMgr, address, record);
		if (record.getLongValue(
			SymbolDatabaseAdapter.SYMBOL_PARENT_COL) != Namespace.GLOBAL_NAMESPACE_ID) {
			throw new AssertException();
		}
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.GLOBAL_VAR;
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		// symbol is locked to program's global namespace
		return symbolMgr.getProgram().getGlobalNamespace() == parent;
	}

	@Override
	public Object getObject() {
		if (!checkIsValid()) {
			return null;
		}
		VariableStorage storage = getVariableStorage();
		if (storage == null) {
			return null;
		}
		return storage;
	}

	@Override
	protected String doGetName() {
		if (!checkIsValid()) {
			// TODO: SCR
			return "[Invalid Global Variable Symbol - Deleted!]";
		}

		VariableStorage storage = getVariableStorage();
		if (storage == null || storage.isBadStorage()) {
			return Function.DEFAULT_LOCAL_PREFIX + "_!BAD!";
		}

		if (getSource() == SourceType.DEFAULT) {
			return getDefaultLocalName(getProgram(), storage);
		}

		return super.doGetName();
	}

	// TODO: move method to SymbolUtilities when support for global variables has been added
	private static String getDefaultLocalName(Program program, VariableStorage storage) {

		StringBuilder buffy = new StringBuilder("global");
		for (Varnode v : storage.getVarnodes()) {
			buffy.append('_');
			Register reg = program.getRegister(v);
			if (reg != null) {
				buffy.append(reg.getName());
			}
			else {
				Address addr = v.getAddress();
				buffy.append(addr.getAddressSpace().getName() + Long.toHexString(addr.getOffset()));
			}
		}
		return buffy.toString();
	}

}
