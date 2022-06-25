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

import java.util.*;

import ghidra.program.model.address.*;

/**
 * <code>RecoverableAddressRangeIterator</code> provides the ability to iterator over an {@link AddressSet}
 * which is getting modified concurrent with the iteration of {@link AddressRange}es contained within it.  Do to 
 * multiple levels of prefetch caching, the results returned may be stale relative to the actual
 * {@link AddressSet} at any point in time.  The primary intent is to return address ranges in proper order
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
class RecoverableAddressRangeIterator implements AddressRangeIterator {

	private AddressSetView set;
	private boolean forward;
	private AddressRangeIterator iterator;
	private AddressRange next;

	/**
	 * Construct iterator
	 * @param set address set
	 * @param start the address the the first range should contain.
	 * @param forward true iterators forward, false backwards
	 */
	RecoverableAddressRangeIterator(AddressSetView set, Address start, boolean forward) {
		this.set = set;
		this.forward = forward;
		initIterator(start);
		try {
			this.next = iterator.next();
		}
		catch (NoSuchElementException e) {
			this.next = null;
		}
	}

	private void initIterator(Address start) {
		if (start == null) {
			iterator = set.getAddressRanges(forward);
		}
		else {
			iterator = set.getAddressRanges(start, forward);
		}
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return this;
	}

	@Override
	public AddressRange next() throws NoSuchElementException {
		AddressRange range = next;
		if (range == null) {
			throw new NoSuchElementException();
		}
		try {
			next = iterator.next();
		}
		catch (ConcurrentModificationException e) {
			next = recoverNext(range);
		}
		catch (NoSuchElementException e) {
			next = null;
		}
		return range;
	}

	private AddressRange recoverNext(AddressRange lastRange) {
		while (true) {
			try {
				Address lastAddr = forward ? lastRange.getMaxAddress() : lastRange.getMinAddress();
				initIterator(lastAddr);
				AddressRange r = iterator.next();
				if (!r.intersects(lastRange)) {
					return r;
				}
				if (forward) {
					if (r.getMaxAddress().compareTo(lastAddr) > 0) {
						return new AddressRangeImpl(lastAddr.next(), r.getMaxAddress());
					}
				}
				else if (r.getMinAddress().compareTo(lastAddr) < 0) { // reverse
					return new AddressRangeImpl(r.getMinAddress(), lastAddr.previous());
				}
				return iterator.next(); // skip range and return next
			}
			catch (ConcurrentModificationException e) {
				// set must have changed - try re-initializing again
			}
			catch (NoSuchElementException e) {
				return null;
			}
		}
	}

	@Override
	public boolean hasNext() {
		return next != null;
	}

}
