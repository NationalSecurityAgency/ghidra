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
package ghidra.util.bytesearch;

import ghidra.program.model.address.Address;

/**
 * Represents a match of a pattern at a given address in program memory.
 * 
 * @param <T> The specific implementation of the pattern that was used to create this match
 * 
 */
public class AddressMatch<T> extends Match<T> {
	private Address address;

	/**
	 * Constructor
	 * @param pattern the byte pattern that matched
	 * @param offset offset within a searched buffer
	 * @param length the length of the matching sequence
	 * @param address the address in the program where the match occurred
	 */
	public AddressMatch(T pattern, long offset, int length, Address address) {
		super(pattern, offset, length);
		this.address = address;
	}

	/** 
	 * @return the address where this match occurred
	 */
	public Address getAddress() {
		return address;
	}

	@Override
	public String toString() {
		return getPattern().toString() + " @ " + address;
	}

	@Override
	public int hashCode() {
		return super.hashCode() + address.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!super.equals(obj)) {
			return false;
		}
		AddressMatch<?> other = (AddressMatch<?>) obj;
		return address.equals(other.address);
	}

}
