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
 * Symbol class for namespaces.
 */
public class NamespaceSymbol extends SymbolDB {

	private NamespaceDB namespace;

	/**
	 * Construct a new namespace symbol
	 * @param mgr the symbol manager.
	 * @param cache symbol object cache
	 * @param record the record for this symbol.
	 */
	NamespaceSymbol(SymbolManager mgr, DBObjectCache<SymbolDB> cache, DBRecord record) {
		super(mgr, cache, Address.NO_ADDRESS, record);
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
	public SymbolType getSymbolType() {
		return SymbolType.NAMESPACE;
	}

	@Override
	public Namespace getObject() {
		lock.acquire();
		try {
			if (!checkIsValid()) {
				return null;
			}
			if (namespace == null) {
				namespace = new NamespaceDB(this, symbolMgr.getProgram().getNamespaceManager());
			}
			return namespace;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isValidParent(Namespace parent) {
		// TODO: Not sure what other constraints should be placed on namespace movement
		return super.isValidParent(parent) && SymbolType.NAMESPACE
				.isValidParent(symbolMgr.getProgram(), parent, address, isExternal());
	}
}
