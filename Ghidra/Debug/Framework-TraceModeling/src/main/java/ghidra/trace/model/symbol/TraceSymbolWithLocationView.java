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

import java.util.*;

import ghidra.program.model.address.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;

/**
 * A symbol view for things bound by an address range and lifespan.
 *
 * <p>
 * <b>NOTE:</b> We may eventually drop the {@code thread} parameter from these methods, as we
 * transition to using register-space overlays.
 *
 * @param <T> the type of symbols in the view
 */
public interface TraceSymbolWithLocationView<T extends TraceSymbol> extends TraceSymbolView<T> {

	/**
	 * Get the child of the given parent having the given name at the given point.
	 * 
	 * @param name the name of the symbol
	 * @param snap the snapshot key
	 * @param thread the thread, if in register space
	 * @param address the address of the symbol
	 * @param parent the parent namespace
	 * @return the symbol, or null
	 */
	T getChildWithNameAt(String name, long snap, TraceThread thread, Address address,
			TraceNamespaceSymbol parent);

	/**
	 * A shorthand for
	 * {@link #getChildWithNameAt(String, long, TraceThread, Address, TraceNamespaceSymbol)} where
	 * parent is the global namespace.
	 * 
	 * @param name the name of the symbol
	 * @param snap the snapshot key
	 * @param thread the thread, if in register space
	 * @param address the address of the symbol
	 * @return the symbol, or null
	 */
	default T getGlobalWithNameAt(String name, long snap, TraceThread thread, Address address) {
		return getChildWithNameAt(name, snap, thread, address, getManager().getGlobalNamespace());
	}

	/**
	 * Get symbols in this view intersecting the given box.
	 * 
	 * @param span the time bound of the box
	 * @param thread the thread, if in register space
	 * @param range the address bound of the box
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @param forward true if the collection should be ordered forward by address, false for
	 *            backward by address.
	 * @return the symbols in this view satisfying the query
	 */
	Collection<? extends T> getIntersecting(Lifespan span, TraceThread thread,
			AddressRange range, boolean includeDynamicSymbols, boolean forward);

	/**
	 * Get symbols in this view at the given point.
	 * 
	 * <p>
	 * The result will be ordered with the primary symbol first.
	 * 
	 * @param snap the snapshot key
	 * @param thread the thread, if in register space
	 * @param address the address of the symbols
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return the symbols in this view satisfying the query
	 */
	default Collection<? extends T> getAt(long snap, TraceThread thread, Address address,
			boolean includeDynamicSymbols) {
		try (LockHold hold = getManager().getTrace().lockRead()) {
			List<? extends T> result =
				new ArrayList<>(getIntersecting(Lifespan.at(snap), thread,
					new AddressRangeImpl(address, address), includeDynamicSymbols, true));
			result.sort(TraceSymbolManager.PRIMALITY_COMPARATOR);
			return result;
		}
	}

	/**
	 * Check if this view contains any symbols at the given point.
	 * 
	 * @param snap the snapshot key
	 * @param thread the thread, if in register space
	 * @param address the address of the symbols
	 * @param includeDynamicSymbols true to include dynamically-generated symbols
	 * @return true if any symbols in this view satisfy the query
	 */
	default boolean hasAt(long snap, TraceThread thread, Address address,
			boolean includeDynamicSymbols) {
		try (LockHold hold = getManager().getTrace().lockRead()) {
			return !getIntersecting(Lifespan.at(snap), thread,
				new AddressRangeImpl(address, address), includeDynamicSymbols, true).isEmpty();
		}
	}
}
