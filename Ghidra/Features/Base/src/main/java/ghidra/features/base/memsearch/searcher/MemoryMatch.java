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
package ghidra.features.base.memsearch.searcher;

import java.util.Arrays;
import java.util.Objects;

import ghidra.features.base.memsearch.matcher.ByteMatcher;
import ghidra.program.model.address.Address;

/**
 * A class that represents a memory search hit at an address. Matches can also be updated with
 * new byte values (from a scan or refresh action). The original bytes that matched the original
 * search are maintained in addition to the "refreshed" bytes.
 */
public class MemoryMatch implements Comparable<MemoryMatch> {

	private final Address address;
	private byte[] bytes;
	private byte[] previousBytes;
	private final ByteMatcher matcher;

	public MemoryMatch(Address address, byte[] bytes, ByteMatcher matcher) {
		if (bytes == null || bytes.length < 1) {
			throw new IllegalArgumentException("Must provide at least 1 byte");
		}
		this.address = Objects.requireNonNull(address);
		this.bytes = bytes;
		this.previousBytes = bytes;
		this.matcher = matcher;
	}

	public MemoryMatch(Address address) {
		this.address = address;
		this.matcher = null;
	}

	public void updateBytes(byte[] newBytes) {
		previousBytes = bytes;
		if (!Arrays.equals(bytes, newBytes)) {
			bytes = newBytes;
		}
	}

	public Address getAddress() {
		return address;
	}

	public int getLength() {
		return bytes.length;
	}

	public byte[] getBytes() {
		return bytes;
	}

	public byte[] getPreviousBytes() {
		return previousBytes;
	}

	public ByteMatcher getByteMatcher() {
		return matcher;
	}

	@Override
	public int compareTo(MemoryMatch o) {
		return address.compareTo(o.address);
	}

	@Override
	public int hashCode() {
		return address.hashCode();
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

		MemoryMatch other = (MemoryMatch) obj;
		// just compare addresses. The bytes are mutable and we want matches to be equal even
		// if the bytes are different
		return Objects.equals(address, other.address);
	}

	@Override
	public String toString() {
		return address.toString();
	}

	public boolean isChanged() {
		return !bytes.equals(previousBytes);
	}
}
