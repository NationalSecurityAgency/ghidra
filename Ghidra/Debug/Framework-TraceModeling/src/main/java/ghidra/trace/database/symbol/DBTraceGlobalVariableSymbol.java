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
package ghidra.trace.database.symbol;

import db.DBRecord;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SymbolType;
import ghidra.trace.model.symbol.TraceGlobalVariableSymbol;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.annot.DBAnnotatedObjectInfo;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceGlobalVariableSymbol extends AbstractDBTraceVariableSymbol
		implements TraceGlobalVariableSymbol {
	static final String TABLE_NAME = "GlobalVars";

	public DBTraceGlobalVariableSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.GLOBAL_VAR;
	}

	@Override
	public DBTraceFunctionSymbol getFunction() {
		return null;
	}

	@Override
	public Address getAddress() {
		// TODO: Reference implementation in Program is not complete. If ever, make this similar.
		return getVariableStorage().getRegister().getAddress();
	}

	@Override
	public boolean setPrimary() {
		return false;
	}

	@Override
	public boolean isPrimary() {
		return true;
	}

	@Override
	public int getFirstUseOffset() {
		// TODO: Reference implementation in Program is not complete. If ever, make this similar.
		return 0;
	}
}
