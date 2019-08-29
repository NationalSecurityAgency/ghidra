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
package ghidra.app.util.viewer.util;

import java.math.BigInteger;
import java.util.Arrays;

import docking.widgets.fieldpanel.support.*;
import ghidra.program.model.address.*;
import ghidra.util.Msg;

/**
 * This class maps a set of address ranges into a contiguous set of indexes from 0 to the
 * total size of the address set. This is used primarily by the listing panel to simplify the
 * display and scrolling logic.
 *
 * Because of the nature of the listing display, not all addresses have displayable content.  For
 * example, a closed data structure can consume thousands of addresses where only the first address
 * has anything to display while the structure is closed.  This can cause poor scrollbar behavior.
 * To fix this, a new method {@link #removeUnviewableAddressRanges(AddressSet)} was added that
 * removes those ranges from the index mapping, but the original addresses are also maintained for
 * purposes of determining "gap" addresses (an address is a gap address if the original address set
 * does not include its immediate predecessor.)  The original addresses are also used so that this
 * index mapping can be reset and then given a different set of address ranges to remove as not viewable.
 * (Useful for when data is open/closed or created/deleted)
 */

public class AddressIndexMap {
	// This number is used to divide the total number of viewable addresses to determine the
	// minimum gap size of address ranges that contain no viewable content.  Setting to 100 means the
	// minimum gap size will be 1% which seems to yield good scrollbar behavior.
	public static BigInteger PERCENT_DIVIDER = BigInteger.valueOf(100);

	// Never let the minimumUnviewableGapSize go below this value.
	public static BigInteger DEFAULT_UNVIEWABLE_GAP_SIZE = BigInteger.valueOf(50);
	private BigInteger numAddresses;
	private BigInteger[] indexList;
	private Address[] addressList;

	private BigInteger minIndex = BigInteger.valueOf(-1);
	private BigInteger maxIndex = minIndex;
	private int lastUsedRangeIndex;
	private AddressSetView originalAddressSet;
	private AddressSet currentViewAddressSet;
	private BigInteger minimumUnviewableGapSize;

	/**
	 * Constructs an empty AddressIndexMap
	 */
	public AddressIndexMap() {
		numAddresses = BigInteger.ZERO;
		indexList = new BigInteger[1];
		indexList[0] = BigInteger.ZERO;
		addressList = new Address[0];
		currentViewAddressSet = new AddressSet();
		originalAddressSet = new AddressSet();
	}

	/**
	 * Constructs an AddressIndexMap for the given address set.
	 *
	 * @param addrSet the address set to index.
	 */
	public AddressIndexMap(AddressSetView addrSet) {
		this.originalAddressSet = addrSet;
		this.currentViewAddressSet = new AddressSet(addrSet);

		buildMapping();
	}

	private AddressIndexMap(AddressIndexMap source) {
		this.numAddresses = source.numAddresses;
		indexList = source.indexList;
		addressList = source.addressList;
		currentViewAddressSet = source.currentViewAddressSet;
		originalAddressSet = source.getOriginalAddressSet();
	}

	/**
	 * Returns the total number of addresses
	 * @return the number of addresses in the view
	 */
	public BigInteger getIndexCount() {
		return numAddresses;
	}

	/**
	 * Returns true if address of the given index is not the successor of the
	 * previous index's address.
	 *
	 * @param index the index to test for gap in the address set.
	 * @return true if the given index represents the first address after a gap in the address set.
	 */
	public boolean isGapIndex(BigInteger index) {
		if (BigInteger.ZERO.equals(index)) {
			return false;
		}
		if (index.compareTo(minIndex) > 0 && index.compareTo(maxIndex) < 0) {
			return false;
		}
		return isGapAddress(getAddress(index));
	}

	/**
	 * Returns true if the given address is the first address after gap of missing addresses.
	 *
	 * @param address the address to check for being a gap address
	 * @return true if the given address is the first address after gap of missing addresses.
	 */
	public boolean isGapAddress(Address address) {
		if (address == null) {
			return false;
		}
		if (address.equals(originalAddressSet.getMinAddress())) {
			return false;
		}
		AddressRange rangeContaining = originalAddressSet.getRangeContaining(address);
		return rangeContaining.getMinAddress().equals(address);
	}

	/**
	 * Returns the i'th address in the set.
	 *
	 * @param index
	 *            the index of the address to retrieve.
	 * @return the address associated with the given index
	 */
	public Address getAddress(BigInteger index) {
		if (index == null || index.compareTo(BigInteger.ZERO) < 0 ||
			index.compareTo(numAddresses) >= 0) {
			return null;
		}
		int arrIndex = 0;

		int compareTo = index.compareTo(minIndex);
		if (compareTo == 0) {
			return addressList[lastUsedRangeIndex];
		}
		if (index.compareTo(minIndex) > 0 && index.compareTo(maxIndex) < 0) {
			arrIndex = lastUsedRangeIndex;
		}
		else {
			arrIndex = Arrays.binarySearch(indexList, index);
			if (arrIndex >= 0) {
				minIndex = indexList[arrIndex];
				maxIndex = indexList[arrIndex + 1];
				lastUsedRangeIndex = arrIndex;
				return addressList[arrIndex];
			}
			arrIndex = -arrIndex - 2;
			minIndex = indexList[arrIndex];
			maxIndex = indexList[arrIndex + 1];
			lastUsedRangeIndex = arrIndex;
		}
		BigInteger offset = index.subtract(indexList[arrIndex]);
		try {
			return addressList[arrIndex].addNoWrap(offset);
		}
		catch (AddressOverflowException e) {
			Msg.showError(this, null, "Bad Index Map", e.getMessage());
			return null;
		}
	}

	/**
	 * Returns the index for the given address.  If the address is not mapped, null will be returned
	 *
	 * @param addr the address for which to retrieve the index.
	 * @return the index associated with the given address.
	 */
	public BigInteger getIndex(Address addr) {
		int arrIndex = Arrays.binarySearch(addressList, addr);
		if (arrIndex >= 0) {
			return indexList[arrIndex];
		}
		arrIndex = -arrIndex - 2;
		if (arrIndex < 0) {
			return null;
		}
		if (!(addr.getAddressSpace().equals(addressList[arrIndex].getAddressSpace()))) {
			return null;
		}
		BigInteger offset =
			addr.getOffsetAsBigInteger().subtract(addressList[arrIndex].getOffsetAsBigInteger());
		BigInteger index = indexList[arrIndex].add(offset);

		if (index.compareTo(indexList[arrIndex + 1]) >= 0) {
			return null;
		}
		return index;
	}

	/**
	 * Returns the index for the given address.  If the address is not mapped, the result is
	 * defined as follows:
	 *    if the address is less than the smallest address in the map, then null is returned
	 *    if the address is greater the the largest address in the map, then a value one bigger than
	 *         the index of the largest address in the map.
	 *    if the address is in a "gap", then the index of the next largest address that is in the
	 *    		map is returned.
	 *
	 * @param addr
	 *            the address for which to retrieve the index.
	 * @return the associated index for the given address or if there is none, then the index
	 *         of then next address greater than the given address or null if there is none.
	 */
	public BigInteger getIndexAtOrAfter(Address addr) {
		int rangeIndex = Arrays.binarySearch(addressList, addr);
		if (rangeIndex >= 0) {
			return indexList[rangeIndex];
		}
		rangeIndex = -rangeIndex - 2;
		if (rangeIndex < 0) {
			return BigInteger.ZERO;
		}
		if (!(addr.getAddressSpace().equals(addressList[rangeIndex].getAddressSpace()))) {
			return indexList[rangeIndex + 1];
		}
		BigInteger offset =
			addr.getOffsetAsBigInteger().subtract(addressList[rangeIndex].getOffsetAsBigInteger());
		BigInteger index = indexList[rangeIndex].add(offset);

		if (index.compareTo(indexList[rangeIndex + 1]) >= 0) {
			return indexList[rangeIndex + 1];
		}
		return index;
	}

	/**
	 * Returns the Address set corresponding to the set of indexes
	 *
	 * @param sel the FieldSelection containing the set of indexes to include.
	 * @return the AddressSet for the given field selection.
	 */
	public AddressSet getAddressSet(FieldSelection sel) {
		AddressSet addrSet = new AddressSet();
		int n = sel.getNumRanges();
		for (int i = 0; i < n; i++) {
			FieldRange range = sel.getFieldRange(i);
			FieldLocation end = range.getEnd();
			BigInteger endIndex = end.getIndex();
			if (end.getFieldNum() == 0 && end.getRow() == 0 && end.getCol() == 0) {
				endIndex = endIndex.subtract(BigInteger.ONE);
			}
			addToAddressSet(addrSet, range.getStart().getIndex(), endIndex);
		}
		return addrSet;
	}

	/**
	 * Returns a FieldSelection containing the set of indexes represented by the
	 * given address set
	 *
	 * @param set
	 *            the set of addresses to convert into a set of indexes.
	 * @return a FieldSelection for the given address set.
	 */
	public FieldSelection getFieldSelection(AddressSetView set) {
		AddressSetView addrSet = currentViewAddressSet.intersect(set);
		FieldSelection fs = new FieldSelection();
		for (AddressRange range : addrSet) {
			BigInteger minRangeIndex = getIndex(range.getMinAddress());
			BigInteger maxRangeIndex = getIndex(range.getMaxAddress());
			// If you can't get an index for min or max then discard the range (don't add to selection).
			if (maxRangeIndex != null && minRangeIndex != null) {
				fs.addRange(minRangeIndex, maxRangeIndex.add(BigInteger.ONE));
			}
		}
		return fs;
	}

	/**
	 * Returns the total set of addresses in this map include addresses that have been closed
	 * @return the total set of addresses in the map including addresses that have been closed
	 */
	public AddressSetView getOriginalAddressSet() {
		return originalAddressSet;
	}

	/**
	 * Returns the total set of addresses in this index mapping (not including those that have been closed)
	 * @return  the total set of addresses in this index mapping (not including those that have been closed)
	 */
	public AddressSetView getIndexedAddressSet() {
		return currentViewAddressSet;
	}

	/**
	 * Returns the the maximum address for the range containing the given address.
	 *
	 * @param addr the address to find its containing range's max address.
	 * @return  the the maximum address for the range containing the given address.
	 */
	public BigInteger getMaxIndex(Address addr) {
		int rangeIndex = Arrays.binarySearch(addressList, addr);
		if (rangeIndex < 0) {
			rangeIndex = -rangeIndex - 2;
		}
		if (rangeIndex < 0) {
			return null;
		}
		return indexList[rangeIndex + 1].subtract(BigInteger.ONE);

	}

	/**
	 * Returns the the minimum address for the range containing the given address.
	 *
	 * @param addr the address to find its containing range's min address.
	 * @return  the the minimum address for the range containing the given address.
	 */
	public BigInteger getMinIndex(Address addr) {
		int rangeIndex = Arrays.binarySearch(addressList, addr);
		if (rangeIndex < 0) {
			rangeIndex = -rangeIndex - 2;
		}
		if (rangeIndex < 0) {
			return null;
		}
		return indexList[rangeIndex];

	}

	/**
	 * Removes the given addresses from the set of addresses that get mapped into indexes.  This
	 * is used to remove large number of addresses that are contained in closed data in order to
	 * make scrollbars scroll smoothly.
	 * <P>
	 * The original address set is maintained to determine the gap addresses and also for resetting
	 * the index map to the entire set of addresses
	 * @param addressSet the set of addresses to remove from the set of addresses that get mapped.
	 */
	public void removeUnviewableAddressRanges(AddressSet addressSet) {
		currentViewAddressSet.delete(addressSet);
		buildMapping();
	}

	/**
	 * Returns the suggested minimum size of address ranges that contain no viewable code units (i.e.
	 * collapsed data).  Ranges larger that this should be removed from the index mapping to get
	 * better scrollbar behavior. Currently this is 1% of the total viewed address space.
	 *
	 * @return the suggested minimum size for a range of addresses with no viewable content.
	 */
	public BigInteger getMiniumUnviewableGapSize() {
		return minimumUnviewableGapSize;
	}

	/**
	 * Resets the mapping to the entire original address set.
	 */
	public AddressIndexMap reset() {
		AddressIndexMap currentMap = new AddressIndexMap(this);
		this.currentViewAddressSet = new AddressSet(originalAddressSet);
		buildMapping();
		return currentMap;
	}

	private void addToAddressSet(AddressSet set, BigInteger startIndex, BigInteger endIndex) {
		int rangeIndex = Arrays.binarySearch(indexList, startIndex);
		if (rangeIndex < 0) {
			rangeIndex = -rangeIndex - 2;
		}
		if (rangeIndex >= addressList.length) {
			return;
		}
		Address startAddr = getAddress(rangeIndex, startIndex);
		while (endIndex.compareTo(indexList[rangeIndex + 1]) >= 0) {
			Address endAddr =
				getAddress(rangeIndex, indexList[rangeIndex + 1].subtract(BigInteger.ONE));
			set.addRange(startAddr, endAddr);
			if (++rangeIndex >= addressList.length) {
				return;
			}
			startAddr = addressList[rangeIndex];
		}
		set.addRange(startAddr, getAddress(rangeIndex, endIndex));

	}

	/**
	 * gets the address for the given index given the rangeIndex of the range that contains that index
	 * @param rangeIndex the index of the range of indexes that contains the index of interest.
	 * @param index the index to get an address for
	 * @return the address corresponding to the given index.
	 */
	private Address getAddress(int rangeIndex, BigInteger index) {
		if (index.equals(indexList[rangeIndex])) {
			return addressList[rangeIndex];
		}
		try {
			return addressList[rangeIndex].addNoWrap(index.subtract(indexList[rangeIndex]));
		}
		catch (AddressOverflowException e) {
			Msg.error(this, "AddressOverflow can't happen here", e);
			return null;
		}
	}

	private void buildMapping() {
		int numRanges = currentViewAddressSet.getNumAddressRanges();
		indexList = new BigInteger[numRanges + 1];
		addressList = new Address[numRanges];

		BigInteger index = BigInteger.ZERO;
		int i = 0;
		for (AddressRange range : currentViewAddressSet) {
			indexList[i] = index;
			addressList[i] = range.getMinAddress();
			index = index.add(range.getBigLength());
			i++;
		}
		indexList[numRanges] = index;
		numAddresses = index;
		minIndex = BigInteger.valueOf(-1);
		maxIndex = minIndex;

		// make the minimum viewable gap size to be 1% of the total view size (but not smaller than default)
		minimumUnviewableGapSize = numAddresses.divide(PERCENT_DIVIDER);
		if (minimumUnviewableGapSize.compareTo(DEFAULT_UNVIEWABLE_GAP_SIZE) < 0) {
			minimumUnviewableGapSize = DEFAULT_UNVIEWABLE_GAP_SIZE;
		}
	}

}
