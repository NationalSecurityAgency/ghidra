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
package ghidra.app.plugin.core.searchtext;

import ghidra.app.plugin.core.searchtext.iterators.SearchAddressIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

import java.util.*;

/**
 * An iterator for returning addresses that can take in 1 or more search iterators to iterator over
 * addresses provided by each of those search iterators.
 */
class ListingDisplaySearchAddressIterator {

	private Address lastAddress;
	private Map<SearchAddressIterator, Address> lastAddressMap =
		new HashMap<SearchAddressIterator, Address>();
	private boolean forward;

	ListingDisplaySearchAddressIterator(Address startAddress, List<SearchAddressIterator> iterators,
			boolean forward) {
		this.forward = forward;
		updateLastAddress(startAddress);

		for (SearchAddressIterator iterator : iterators) {
			lastAddressMap.put(iterator, null);
		}
	}

	private void updateLastAddress(Address startAddress) {
		if (startAddress == null) {
			return;
		}

		if (forward) {
			if (startAddress.getOffset() > 0) {
				lastAddress = startAddress.subtract(1);
			}
		}
		else {
			// don't add past the address range
			AddressSpace addressSpace = startAddress.getAddressSpace();
			Address maxAddress = addressSpace.getMaxAddress();
			long maxOffset = maxAddress.getOffset();
			long startOffset = startAddress.getOffset();
			long result = startOffset + 1;
			if (result > startOffset && result < maxOffset) {
				lastAddress = startAddress.add(1);
			}
		}
	}

	boolean hasNext() {
		Address address = getAlreadyFoundNextAddress();
		if (address != null) {
			return true;
		}

		maybePushIteratorsForward();

		for (SearchAddressIterator iterator : lastAddressMap.keySet()) {
			if (iterator.hasNext()) {
				return true;
			}
		}

		// any remaining addresses we've already pulled-out?
		return getAlreadyFoundNextAddress() != null;
	}

	private Address getAlreadyFoundNextAddress() {
		List<Address> addresses = new ArrayList<Address>();
		Collection<Address> values = lastAddressMap.values();
		for (Address address : values) {
			if (address != null) {
				addresses.add(address);
			}
		}

		// smallest first for forward
		Collections.sort(addresses);
		if (!forward) {
			Collections.reverse(addresses);
		}

		for (Address address : addresses) {
			if (isGreaterThanLastAddress(address)) {
				return address;
			}
		}

		return null;
	}

	Address next() {
		Address address = maybePushIteratorsForward();
		lastAddress = address;
		return address;
	}

	private Address maybePushIteratorsForward() {
		Set<SearchAddressIterator> keys = lastAddressMap.keySet();
		for (SearchAddressIterator iterator : keys) {
			Address current = lastAddressMap.get(iterator);
			if (isGreaterThanLastAddress(current)) {
				continue; // last value for this iterator is still good--don't move forward
			}

			Address address = movePastLastAddress(iterator);
			lastAddressMap.put(iterator, address);
		}
		return getAlreadyFoundNextAddress();
	}

	private Address movePastLastAddress(SearchAddressIterator iterator) {
		while (iterator.hasNext()) {
			Address address = iterator.next();
			if (isGreaterThanLastAddress(address)) {
				return address;
			}
		}
		return null;
	}

	private boolean isGreaterThanLastAddress(Address address) {
		if (address == null) {
			return false;
		}
		if (lastAddress == null) {
			return true;
		}

		if (forward) {
			return lastAddress.compareTo(address) < 0;
		}
		return lastAddress.compareTo(address) > 0;
	}
}
