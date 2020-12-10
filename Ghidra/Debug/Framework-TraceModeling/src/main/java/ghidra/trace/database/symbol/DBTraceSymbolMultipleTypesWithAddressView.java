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

import com.google.common.collect.Collections2;

import generic.CatenatedCollection;
import ghidra.program.model.address.*;
import ghidra.trace.model.symbol.TraceNamespaceSymbol;
import ghidra.trace.model.symbol.TraceSymbolWithAddressView;
import ghidra.util.LockHold;

public class DBTraceSymbolMultipleTypesWithAddressView<T extends AbstractDBTraceSymbol>
		extends DBTraceSymbolMultipleTypesView<T> implements TraceSymbolWithAddressView<T> {

	public DBTraceSymbolMultipleTypesWithAddressView(DBTraceSymbolManager manager,
			Collection<? extends AbstractDBTraceSymbolSingleTypeWithAddressView<? extends T>> parts) {
		super(manager, parts);
	}

	@SafeVarargs
	public DBTraceSymbolMultipleTypesWithAddressView(DBTraceSymbolManager manager,
			AbstractDBTraceSymbolSingleTypeWithAddressView<? extends T>... parts) {
		super(manager, parts);
	}

	@SuppressWarnings("unchecked")
	protected Collection<? extends AbstractDBTraceSymbolSingleTypeWithAddressView<? extends T>> getParts() {
		return (Collection<? extends AbstractDBTraceSymbolSingleTypeWithAddressView<? extends T>>) parts;
	}

	@Override
	public T getChildWithNameAt(String name, Address address, TraceNamespaceSymbol parent) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			for (AbstractDBTraceSymbolSingleTypeWithAddressView<? extends T> p : getParts()) {
				T symbol = p.getChildWithNameAt(name, address, parent);
				if (symbol != null) {
					return symbol;
				}
			}
			return null;
		}
	}

	@Override
	public Collection<? extends T> getIntersecting(AddressRange range,
			boolean includeDynamicSymbols) {
		return new CatenatedCollection<>(Collections2.transform(getParts(),
			p -> p.getIntersecting(range, includeDynamicSymbols)));
	}

	@Override
	public Collection<? extends T> getAt(Address address, boolean includeDynamicSymbols) {
		return getIntersecting(new AddressRangeImpl(address, address), includeDynamicSymbols);
	}
}
