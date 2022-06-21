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
package ghidra.trace.model.property;

import com.google.common.collect.Range;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

public interface TracePropertySetter<T> {
	/**
	 * Get the class for values of the map
	 * 
	 * @return the value class
	 */
	Class<? super T> getValueClass();

	/**
	 * Set a value at the given address over the given lifespan
	 * 
	 * @see #set(Range, AddressRange, Object)
	 * @param lifespan the lifespan
	 * @param address the address
	 * @param value the value
	 */
	void set(Range<Long> lifespan, Address address, T value);

	/**
	 * Set a value over the given ranges
	 * 
	 * <p>
	 * Setting a value of null still creates an entry, so that Void-typed maps function.
	 * 
	 * <p>
	 * When setting an overlapping value, existing entries are deleted or truncated to make space
	 * for the new entry. If an existing entry overlaps and its starting snap is contained in the
	 * new entry's span, the existing entry is deleted, regardless of whether or not its ending snap
	 * is also contained in the new entry's span. If the starting snap of the existing entry
	 * precedes the span of the new entry, the existing entry is truncated -- its ending snap is set
	 * to one less than the new entry's starting snap. Address ranges are never truncated.
	 * 
	 * @param lifespan the lifespan
	 * @param range the address range
	 * @param value the value
	 */
	void set(Range<Long> lifespan, AddressRange range, T value);

	/**
	 * Remove or truncate entries so that the given span and range has no values
	 * 
	 * <p>
	 * This applies the same truncation rule as in {@link #set(Range, AddressRange, Object)}, except
	 * that no replacement entry is created.
	 * 
	 * @param span the range of snaps
	 * @param range the address range
	 */
	void clear(Range<Long> span, AddressRange range);
}
