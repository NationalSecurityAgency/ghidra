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

import ghidra.program.model.symbol.SymbolType;
import ghidra.trace.model.symbol.TraceLocalVariableSymbolView;

public class DBTraceLocalVariableSymbolView
		extends AbstractDBTraceSymbolSingleTypeWithAddressView<DBTraceLocalVariableSymbol>
		implements TraceLocalVariableSymbolView {

	public DBTraceLocalVariableSymbolView(DBTraceSymbolManager manager) {
		super(manager, SymbolType.LOCAL_VAR.getID(), manager.localVarStore);
	}
}
