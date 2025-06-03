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
import ghidra.program.model.symbol.*;

/**
 * Symbols that represent classes
 */
public class ClassSymbol extends SymbolDB {

	private GhidraClassDB ghidraClass;

	/**
	 * Construct a new Class Symbol
	 * @param symbolMgr the symbol manager
	 * @param cache symbol object cache
	 * @param address the address to associate with the symbol
	 * @param record the record associated with the symbol.
	 */
	public ClassSymbol(SymbolManager symbolMgr, DBObjectCache<SymbolDB> cache, Address address,
			DBRecord record) {
		super(symbolMgr, cache, address, record);

	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.CLASS;
	}

	@Override
	public Object getObject() {
		lock.acquire();
		try {
			checkIsValid();
			if (ghidraClass == null) {
				ghidraClass = new GhidraClassDB(this, symbolMgr.getProgram().getNamespaceManager());
			}
			return ghidraClass;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isPrimary() {
		return true;
	}

	@Override
	public boolean isExternal() {
		Symbol parentSymbol = getParentSymbol();
		return parentSymbol != null ? parentSymbol.isExternal() : false;
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		return super.isValidParent(parent) &&
			SymbolType.CLASS.isValidParent(symbolMgr.getProgram(), parent, address, isExternal());
	}
}
