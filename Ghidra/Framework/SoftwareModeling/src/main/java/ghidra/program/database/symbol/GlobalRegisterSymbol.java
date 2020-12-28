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
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.ProgramLocation;

/**
 * Symbols for global registers.
 */

public class GlobalRegisterSymbol extends SymbolDB {

	/**
	 * Construct a new GlobalRegisterSymbol.
	 * @param mgr the symbol manager
	 * @param cache symbol object cache
	 * @param addr the address for this symbol.
	 * @param record the record for this symbol.
	 */
	public GlobalRegisterSymbol(SymbolManager mgr, DBObjectCache<SymbolDB> cache, Address addr,
			DBRecord record) {
		super(mgr, cache, addr, record);
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getSymbolType()
	 */
	public SymbolType getSymbolType() {
		return SymbolType.GLOBAL_VAR;
	}

	@Override
	public boolean isExternal() {
		return false;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getObject()
	 */
	public Object getObject() {
		Register reg = symbolMgr.getProgram().getRegister(getAddress());
		return reg;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#isPrimary()
	 */
	@Override
	public boolean isPrimary() {
		return true;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#getProgramLocation()
	 */
	public ProgramLocation getProgramLocation() {
		return null;
	}

	/**
	 * @see ghidra.program.model.symbol.Symbol#isValidParent(ghidra.program.model.symbol.Namespace)
	 */
	@Override
	public boolean isValidParent(Namespace parent) {
		return SymbolType.GLOBAL_VAR.isValidParent(symbolMgr.getProgram(), parent, address,
			isExternal());
	}
}
