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
package ghidra.trace.model.map;

import java.util.function.Predicate;

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.database.spatial.SpatialMap;

public interface TraceAddressSnapRangePropertyMapOperations<T>
		extends SpatialMap<TraceAddressSnapRange, T, TraceAddressSnapRangeQuery> {
	default T put(Address address, Range<Long> lifespan, T value) {
		return put(
			new ImmutableTraceAddressSnapRange(new AddressRangeImpl(address, address), lifespan),
			value);
	}

	default T put(Address minAddress, Address maxAddress, long minSnap, long maxSnap, T value) {
		return put(new ImmutableTraceAddressSnapRange(minAddress, maxAddress, minSnap, maxSnap),
			value);
	}

	default T put(Address minAddress, Address maxAddress, long snap, T value) {
		return put(new ImmutableTraceAddressSnapRange(minAddress, maxAddress, snap, snap), value);
	}

	default T put(AddressRange range, Range<Long> lifespan, T value) {
		return put(new ImmutableTraceAddressSnapRange(range, lifespan), value);
	}

	AddressSetView getAddressSetView(Range<Long> span, Predicate<T> predicate);

	AddressSetView getAddressSetView(Range<Long> span);

	/**
	 * For maps where values are the entries, remove a value
	 * 
	 * @param value the entry to remove
	 */
	void deleteValue(T value);
}
