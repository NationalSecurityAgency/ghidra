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
package ghidra.trace.model.symbol;

import java.util.Collection;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * A view for symbols located in stack or register space not associated with a particular thread.
 *
 * @param <T> the type of symbol in the view
 */
public interface TraceSymbolWithAddressView<T extends TraceSymbol> extends TraceSymbolView<T> {

	T getChildWithNameAt(String name, Address address, TraceNamespaceSymbol parent);

	default T getGlobalWithNameAt(String name, Address address) {
		return getChildWithNameAt(name, address, getManager().getGlobalNamespace());
	}

	Collection<? extends T> getIntersecting(AddressRange range, boolean includeDynamicSymbols);

	Collection<? extends T> getAt(Address address, boolean includeDynamicSymbols);

	default boolean hasAt(Address address, boolean includeDynamicSymbols) {
		return !getAt(address, includeDynamicSymbols).isEmpty();
	}
}
