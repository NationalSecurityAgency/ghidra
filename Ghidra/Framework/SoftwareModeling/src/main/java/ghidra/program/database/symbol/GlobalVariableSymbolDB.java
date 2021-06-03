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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SymbolType;

public class GlobalVariableSymbolDB extends VariableSymbolDB {

	/**
	 * Constructs a new GlobalVariableSymbolDB
	 * @param symbolMgr the symbol manager
	 * @param cache symbol object cache
	 * @param address the address of the symbol (stack address)
	 * @param record the record for the symbol
	 */
	public GlobalVariableSymbolDB(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache,
			VariableStorageManagerDB variableMgr, Address address, DBRecord record) {
		super(symbolMgr, cache, SymbolType.GLOBAL_VAR, variableMgr, address, record);
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.GLOBAL_VAR;
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
		return storage.getRegister();
	}

	@Override
	protected String doGetName() {
		if (!checkIsValid()) {
			// TODO: SCR 
			return "[Invalid VariableSymbol - Deleted!]";
		}
		VariableStorage storage = getVariableStorage();
		if (storage == null) {
			return Function.DEFAULT_LOCAL_PREFIX + "_!BAD!";
		}
		return super.doGetName();
	}

}
