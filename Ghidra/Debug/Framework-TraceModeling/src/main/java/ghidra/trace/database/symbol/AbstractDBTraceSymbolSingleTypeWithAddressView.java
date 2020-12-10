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

import java.util.Collection;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.util.database.DBCachedObjectStore;

public abstract class AbstractDBTraceSymbolSingleTypeWithAddressView<T extends AbstractDBTraceSymbol>
		extends AbstractDBTraceSymbolSingleTypeView<T> {

	public AbstractDBTraceSymbolSingleTypeWithAddressView(DBTraceSymbolManager manager, byte typeID,
			DBCachedObjectStore<T> store) {
		super(manager, typeID, store);
	}

	public T getChildWithNameAt(String name, Address address, TraceNamespaceSymbol parent) {
		// TODO Auto-generated method stub
		return null;
	}

	public T getGlobalWithNameAt(String name, Address address) {
		// TODO Auto-generated method stub
		return null;
	}

	public Collection<? extends T> getIntersecting(AddressRange range,
			boolean includeDynamicSymbols) {
		// TODO Auto-generated method stub
		return null;
	}

	public Collection<? extends T> getAt(Address address, boolean includeDynamicSymbols) {
		// TODO Auto-generated method stub
		return null;
	}
}
