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
 * A symbol view for things with an address in stack or register space, but not associated with a
 * trace thread.
 *
 * <p>
 * <b>NOTE:</b> This class is somewhat vestigial. It would be used to index parameters, locals, and
 * global variables by their storage addresses. However, functions (and thus parameters and locals)
 * are no longer supported. Furthermore, global variables are not fully implemented, yet.
 * 
 * @implNote If this is later used for global variables, we might need to consider that the variable
 *           is no longer implicitly bound in time by a parent function. We might remove this and
 *           use {@link TraceSymbolWithLocationView} instead. Even if we brought back function
 *           support, being able to query by those implicit bounds would probably be useful.
 *
 * @param <T> the type of symbols in the view
 */
public interface TraceSymbolWithAddressView<T extends TraceSymbol> extends TraceSymbolView<T> {

	/**
	 * Get the child of the given parent having the given name at the given address.
	 * 
	 * @param name the name of the symbol
	 * @param address the address of the symbol
	 * @param parent the parent namespace
	 * @return the symbol, or null
	 */
	T getChildWithNameAt(String name, Address address, TraceNamespaceSymbol parent);

	/**
	 * A shorthand for {@link #getChildWithNameAt(String, Address, TraceNamespaceSymbol)} where
	 * parent is the global namespace.
	 * 
	 * @param name the name of the symbol
	 * @param address the address of the symbol
	 * @return the symbol, or null
	 */
	default T getGlobalWithNameAt(String name, Address address) {
		return getChildWithNameAt(name, address, getManager().getGlobalNamespace());
	}

	/**
	 * Get symbols in this view intersecting the given address range.
	 * 
	 * @param range the range
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getIntersecting(AddressRange range, boolean includeDynamicSymbols);

	/**
	 * Get symbols in this view containing the given address.
	 * 
	 * @param address the address of the symbol
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getAt(Address address, boolean includeDynamicSymbols);

	/**
	 * Check if this view contains any symbols at the given address.
	 * 
	 * @param address the address of the symbol
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return true if any symbols in this view satisfy the query
	 */
	default boolean hasAt(Address address, boolean includeDynamicSymbols) {
		return !getAt(address, includeDynamicSymbols).isEmpty();
	}
}
