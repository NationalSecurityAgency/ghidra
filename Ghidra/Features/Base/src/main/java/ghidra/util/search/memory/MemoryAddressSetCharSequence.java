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

import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.AssertException;

/**
 * This class implements the CharSequence interface using Memory and an AddressSet.  The
 * idea is that each byte in memory at the addresses specified in the AddressSet will form
 * a contiguous sequence of characters.
 */

public class MemoryAddressSetCharSequence implements CharSequence {

	private final Memory memory;
	private final AddressSetView set;
	private final AddressSetMapping mapping;

	public MemoryAddressSetCharSequence(Memory memory, AddressSetView addressSet)
			throws MemoryAccessException {
		this.memory = memory;
		this.set = addressSet;

		if (addressSet.getNumAddresses() > Integer.MAX_VALUE) {
			throw new AssertException(
				"The MemAddressSetCharSequence class only supports address sets of size <= 0x7ffffffff byte addresses.");
		}

		if (!memory.getAllInitializedAddressSet().contains(addressSet)) {
			throw new MemoryAccessException(
				"Not all addresses in given address set are in memory!");
		}

		mapping = new AddressSetMapping(addressSet);
	}

	public MemoryAddressSetCharSequence(Memory memory, Address start, Address end)
			throws MemoryAccessException {
		this(memory, new AddressSet(start, end));
	}

	/**
	 * Takes an index and returns the matching Address
	 * @param index index to search on
	 * @return Address address matched to index
	 */
	public Address getAddressAtIndex(int index) {
		return mapping.getAddress(index);
	}

	@Override
	public int length() {
		return (int) set.getNumAddresses(); //safe cast because we check in constructor
	}

	@Override
	public char charAt(int index) {
		Address address = getAddressAtIndex(index);

		try {
			byte b = memory.getByte(address);
			return (char) (b & 0xff);
		}
		catch (MemoryAccessException e) {
			throw new AssertException("Can't happen since we already checked in constructor");
		}
	}

	@Override
	public CharSequence subSequence(int start, int end) {
		if (start < 0 || start >= length() || end < 0 || end >= length()) {
			throw new IndexOutOfBoundsException("Start and end must be in [0, " + (length() - 1));
		}

		Address startAddress = getAddressAtIndex(start);
		Address endAddress = getAddressAtIndex(end);
		AddressSet intersectSet = set.intersectRange(startAddress, endAddress);

		try {
			return new MemoryAddressSetCharSequence(memory, intersectSet);
		}
		catch (MemoryAccessException e) {
			throw new AssertException("Can't happen since we already checked");
		}
	}

}
