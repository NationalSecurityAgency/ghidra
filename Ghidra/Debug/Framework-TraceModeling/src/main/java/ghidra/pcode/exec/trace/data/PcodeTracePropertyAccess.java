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
package ghidra.pcode.exec.trace.data;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;

/**
 * A trace-property access shim for a specific property
 *
 * @see PcodeTraceAccess
 * @see PcodeTraceDataAccess
 *
 * @param <T> the type of the property's values
 */
public interface PcodeTracePropertyAccess<T> {
	/**
	 * Get the property's value at the given address
	 * 
	 * <p>
	 * This may search for the same property from other related data sources, e.g., from mapped
	 * static images.
	 * 
	 * @param address the address
	 * @return the value, or null if not set
	 */
	T get(Address address);

	/**
	 * Set the property's value at the given address
	 * 
	 * <p>
	 * The value is affective for future snapshots up to but excluding the next snapshot where
	 * another value is set at the same address.
	 * 
	 * @param address the address
	 * @param value the value to set
	 */
	void put(Address address, T value);

	/**
	 * Clear the property's value across a range
	 * 
	 * @param range the range
	 */
	void clear(AddressRange range);
}
