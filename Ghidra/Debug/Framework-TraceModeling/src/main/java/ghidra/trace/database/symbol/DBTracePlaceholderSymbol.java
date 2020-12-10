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

public class DBTracePlaceholderSymbol extends AbstractDBTraceSymbol {
	protected final long id;

	public DBTracePlaceholderSymbol(DBTraceSymbolManager manager, long id) {
		super(manager, null, null);
		this.id = id;
	}

	@Override
	public long getID() {
		return id;
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.getSymbolType(DBTraceSymbolManager.unpackTypeID(id));
	}

	@Override
	public boolean isPrimary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean setPrimary() {
		throw new UnsupportedOperationException();
	}

	@Override
	public Object getObject() {
		throw new UnsupportedOperationException();
	}
}
