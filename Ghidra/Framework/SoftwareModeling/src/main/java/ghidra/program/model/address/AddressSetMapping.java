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
package ghidra.program.model.address;

import java.util.*;

/**
 * Class that provides random access to {@link Address}es in an {@link AddressSet}, based on the index of the address in the set, not the {@link Address#getOffset() address offset value}.<p>
 * <p>
 * For instance, a {@link AddressSet} containing addresses [0,1,2,3,4,90,91,92,93,94], {@link #getAddress(int) getAddress(1)} will return an {@link Address} with an
 * offset value of 1, but {@link #getAddress(int) getAddress(5)} will return an {@link Address} instance with an offset value of 90.
 * <p>
 * This collapses a sparse address space with holes into a contiguous list of addresses.
 */

public class AddressSetMapping {

	private AddressSetView set;
	private List<AddressRange> ranges;
	private int[] indexes;
	private AddressRange currentRange;
	private int currentRangeStart = -1;
	private int currentRangeEnd = -1;
	private int currentRangeIndex = -1;
	private final int maxIndex;

	public AddressSetMapping(AddressSetView set) {
		if (set == null) {
			throw new IllegalArgumentException("The address set can't be null");
		}
		if (set.getNumAddresses() > Integer.MAX_VALUE) {
			throw new IllegalArgumentException(
				"This class does not support AddressSets whose size >= 0x7fffffff byte addresses.");
		}
		this.set = set;
		ranges = getAddressRangesFromAddressSet();
		indexes = getStartIndexesForAllAddressRanges();
		maxIndex = (int) set.getNumAddresses();
	}

	/**
	 * Returns the Address at the specified position in the AddressSet.
	 * @param index the index into the ordered list of addresses within an AddressSet.
	 * @return the Address at the specified position.
	 */
	public Address getAddress(int index) {
		if (index < 0 || index >= maxIndex) {
			return null;
		}

		if (!indexInCurrentRange(index)) {
			setCurrentRange(index);
		}

		return getAddress(currentRange, index - currentRangeStart);
	}

	/**
	 * Sets the current range cache.  This class maintains the concept of a "current range",
	 * which is a index into the range list and the start and end indexes for that range.
	 * This way if the getAddress call uses an index into the "current range", it doesn't
	 * have to do a binary search to find the range.
	 * @param index
	 */
	private void setCurrentRange(int index) {
		// optimized for sequential access, so first just check if the index is one more
		// than the the current range of indexes, if so just move to the next range.
		if (index == currentRangeEnd + 1) {
			currentRangeIndex++;
			currentRange = ranges.get(currentRangeIndex);
		}
		// otherwise we must do a binary search to find the correct address range for the
		// given index.
		else {
			currentRangeIndex = Arrays.binarySearch(indexes, index);
			if (currentRangeIndex < 0) {
				currentRangeIndex = -currentRangeIndex - 2;
			}
		}
		// ok, found the current range, set the range index variables so that accesses in
		// this range will be fast.
		currentRange = ranges.get(currentRangeIndex);
		currentRangeStart = indexes[currentRangeIndex];
		currentRangeEnd = currentRangeStart + (int) currentRange.getLength() - 1;
	}

	/**
	 * Check if the given index in in the "current range".
	 * @param index the index to check
	 */
	private boolean indexInCurrentRange(int index) {
		return index >= currentRangeStart && index <= currentRangeEnd;
	}

	/**
	 * Returns an n'th address in an address range.
	 * @param range the range to extract an address
	 * @param offset the index in the range to get an address.
	 */
	private Address getAddress(AddressRange range, int offset) {
		return range.getMinAddress().add(offset);
	}

	/**
	 * Compute the index for each range in the address set.
	 */
	private int[] getStartIndexesForAllAddressRanges() {
		int[] starts = new int[ranges.size() + 1];

		starts[0] = 0;
		int i = 1;
		for (AddressRange range : ranges) {
			starts[i] = starts[i - 1] + (int) range.getLength();
			i++;
		}
		return starts;
	}

	/**
	 * Convert the address range into a list of AddressRanges
	 */
	private List<AddressRange> getAddressRangesFromAddressSet() {
		List<AddressRange> list = new ArrayList<>();
		for (AddressRange addressRange : set) {
			list.add(addressRange);
		}
		return list;
	}

}
