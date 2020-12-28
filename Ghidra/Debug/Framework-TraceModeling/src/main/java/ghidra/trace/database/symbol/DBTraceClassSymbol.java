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
import ghidra.program.model.symbol.SymbolType;
import ghidra.trace.model.symbol.TraceClassSymbol;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.annot.DBAnnotatedObjectInfo;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceClassSymbol extends DBTraceNamespaceSymbol implements TraceClassSymbol {
	@SuppressWarnings("hiding")
	static final String TABLE_NAME = "Classes";

	// TODO: Emit lifespan change events

	public DBTraceClassSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.CLASS;
	}
}
