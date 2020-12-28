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
import ghidra.program.util.ProgramLocation;

/**
 * Symbol class for namespaces.
 */

public class NamespaceSymbol extends SymbolDB {

	NamespaceDB namespace;

	/**
	 * Construct a new namespace symbol
	 * @param mgr the symbol manager.
	 * @param cache symbol object cache
	 * @param addr the address for this symbol.
	 * @param record the record for this symbol.
	 */
	NamespaceSymbol(SymbolManager mgr, DBObjectCache<SymbolDB> cache, Address addr, DBRecord record) {
		super(mgr, cache, addr, record);
	}

	/**
	 * @see ghidra.program.database.symbol.SymbolDB#isPrimary()
	 */
	@Override
	public boolean isPrimary() {
		return true;
	}

	@Override
	public boolean isExternal() {
		Symbol parentSymbol = getParentSymbol();
		return parentSymbol != null ? parentSymbol.isExternal() : false;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getSymbolType()
	 */
	@Override
	public SymbolType getSymbolType() {
		return SymbolType.NAMESPACE;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getProgramLocation()
	 */
	@Override
	public ProgramLocation getProgramLocation() {
		return null;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getObject()
	 */
	@Override
	public Object getObject() {
		return getNamespace();
	}

	private Namespace getNamespace() {
		if (namespace == null) {
			namespace = new NamespaceDB(this, symbolMgr.getProgram().getNamespaceManager());
		}
		return namespace;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#isValidParent(ghidra.program.model.symbol.Namespace)
	 */
	@Override
	public boolean isValidParent(Namespace parent) {
		// TODO: Not sure what other constraints should be placed on namespace movement
		return SymbolType.NAMESPACE.isValidParent(symbolMgr.getProgram(), parent, address,
			isExternal());

//		if (parent == symbolMgr.getProgram().getGlobalNamespace()) {
//			return true;
//		}
//		if (isExternal() != parent.isExternal()) {
//			return false;
//		}
//		Symbol newParentSym = parent.getSymbol();
//		if (symbolMgr.getProgram() != newParentSym.getProgram()) {
//			return false;
//		}
//		if (isExternal() && symbolMgr.getFunctionSymbol(parent) != null) {
//			// External function can not have a child namespace
//			return false;
//		}
//		return true;
	}
}
