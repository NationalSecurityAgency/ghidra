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

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.LockHold;

public interface TraceSymbolWithLocationView<T extends TraceSymbol> extends TraceSymbolView<T> {

	T getChildWithNameAt(String name, long snap, TraceThread thread, Address address,
			TraceNamespaceSymbol parent);

	default T getGlobalWithNameAt(String name, long snap, TraceThread thread, Address address) {
		return getChildWithNameAt(name, snap, thread, address, getManager().getGlobalNamespace());
	}

	Collection<? extends T> getIntersecting(Range<Long> span, TraceThread thread,
			AddressRange range, boolean includeDynamicSymbols, boolean forward);

	/**
	 * Get the symbols at the given snap and address, starting with the primary
	 * 
	 * TODO: Document me
	 * 
	 * @param snap
	 * @param thread
	 * @param address
	 * @param includeDynamicSymbols
	 * @return
	 */
	default Collection<? extends T> getAt(long snap, TraceThread thread, Address address,
			boolean includeDynamicSymbols) {
		try (LockHold hold = getManager().getTrace().lockRead()) {
			List<? extends T> result =
				new ArrayList<>(getIntersecting(Range.closed(snap, snap), thread,
					new AddressRangeImpl(address, address), includeDynamicSymbols, true));
			result.sort(TraceSymbolManager.PRIMALITY_COMPARATOR);
			return result;
		}
	}

	default boolean hasAt(long snap, TraceThread thread, Address address,
			boolean includeDynamicSymbols) {
		try (LockHold hold = getManager().getTrace().lockRead()) {
			return !getIntersecting(Range.singleton(snap), thread,
				new AddressRangeImpl(address, address), includeDynamicSymbols, true).isEmpty();
		}
	}
}
