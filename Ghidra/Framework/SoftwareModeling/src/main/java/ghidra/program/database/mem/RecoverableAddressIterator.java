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
package ghidra.program.database.mem;

import java.util.ConcurrentModificationException;
import java.util.Iterator;

import ghidra.program.model.address.*;

/**
 * <code>RecoverableAddressIterator</code> provides the ability to iterator over an {@link AddressSet}
 * which is getting modified concurrent with the iteration of Addresses contained within it.  Do to 
 * multiple levels of prefetch caching, the results returned may be stale relative to the actual
 * {@link AddressSet} at any point in time.  The primary intent is to return addresses in proper order
 * and avoid throwing a {@link ConcurrentModificationException} which the standard iterators are
 * subject to.
 * <p>
 * NOTES:
 * <ol>
 * <li>The iterator methods are not symchronized but could be made so if restricted to 
 * use in conjunction with the {@link SynchronizedAddressSet} where it would synchronize on 
 * the set itself.</li>
 * <li>This class and {@link SynchronizedAddressSet} could be made public alongside {@link AddressSet}
 * if so desired in the future.  Its current use has been limited until proven to be thread-safe
 * and useful.</li>
 * </ol>
 */
class RecoverableAddressIterator implements AddressIterator {

	private AddressSetView set;
	private boolean forward;
	private AddressIterator iterator;
	private Address next;

	/**
	 * Construct iterator
	 * @param set address set
	 * @param start address to start iterating at in the address set or null for all addresses
	 * @param forward if true address are return from lowest to highest, else from highest to lowest
	 */
	RecoverableAddressIterator(AddressSetView set, Address start, boolean forward) {
		this.set = set;
		this.forward = forward;
		initIterator(start);
		this.next = iterator.next();
	}

	private void initIterator(Address start) {
		if (start == null) {
			iterator = set.getAddresses(forward);
		}
		else {
			iterator = set.getAddresses(start, forward);
		}
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}

	@Override
	public Address next() {
		Address addr = next;
		if (addr != null) {
			try {
				next = iterator.next();
			}
			catch (ConcurrentModificationException e) {
				next = recoverNext(addr);
			}
		}
		return addr;
	}

	private Address recoverNext(Address lastAddr) {
		while (true) {
			try {
				initIterator(lastAddr);
				Address a = iterator.next();
				if (a != null && a.equals(lastAddr)) {
					a = iterator.next();
				}
				return a;
			}
			catch (ConcurrentModificationException e) {
				// set must have changed - try re-initializing again
			}
		}
	}

	@Override
	public boolean hasNext() {
		return next != null;
	}

}
