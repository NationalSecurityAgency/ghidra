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
package ghidra.util.search.memory;

import java.util.Objects;

import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;

/**
 * A class that represents a memory search hit at an address.
 */
public class MemSearchResult implements Comparable<MemSearchResult> {

	private Address address;
	private int length;

	public MemSearchResult(Address address, int length) {
		this.address = Objects.requireNonNull(address);

		if (length <= 0) {
			throw new IllegalArgumentException("Length must be greater than 0");
		}
		this.length = length;
	}

	public Address getAddress() {
		return address;
	}

	public int getLength() {
		return length;
	}

	@Override
	public int compareTo(MemSearchResult o) {
		return address.compareTo(o.address);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((address == null) ? 0 : address.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		MemSearchResult other = (MemSearchResult) obj;
		return SystemUtilities.isEqual(address, other.address);
	}

	@Override
	public String toString() {
		return address.toString();
	}

	/**
	 * Returns true if the given address equals the address of this search result  
	 * @param a the other address
	 * @return true if the given address equals the address of this search result
	 */
	public boolean addressEquals(Address a) {
		return address.equals(a);
	}
}
