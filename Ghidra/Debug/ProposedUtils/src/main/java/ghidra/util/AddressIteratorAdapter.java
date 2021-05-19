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
package ghidra.util;

import java.util.Iterator;
import java.util.NoSuchElementException;

import generic.NestedIterator;
import generic.util.PeekableIterator;
import ghidra.program.model.address.*;

public class AddressIteratorAdapter extends NestedIterator<AddressRange, Address>
		implements AddressIterator {

	protected static class ForwardAddressIterator implements PeekableIterator<Address> {
		private final Address end;

		private Address cur;

		public ForwardAddressIterator(AddressRange range) {
			this(range.getMinAddress(), range.getMaxAddress());
		}

		public ForwardAddressIterator(Address min, Address max) {
			this.end = max;
			this.cur = min;
		}

		@Override
		public boolean hasNext() {
			return cur != null && cur.compareTo(end) <= 0;
		}

		@Override
		public Address next() {
			Address next = cur;
			cur = cur.next();
			return next;
		}

		@Override
		public Address peek() throws NoSuchElementException {
			return cur;
		}
	}

	protected static class BackwardAddressIterator implements PeekableIterator<Address> {
		private final Address end;

		private Address cur;

		public BackwardAddressIterator(AddressRange range) {
			this(range.getMinAddress(), range.getMaxAddress());
		}

		public BackwardAddressIterator(Address min, Address max) {
			this.end = min;
			this.cur = max;
		}

		@Override
		public boolean hasNext() {
			return cur != null && cur.compareTo(end) >= 0;
		}

		@Override
		public Address next() {
			Address next = cur;
			cur = cur.previous();
			return next;
		}

		@Override
		public Address peek() throws NoSuchElementException {
			return cur;
		}
	}

	public static Iterable<Address> forRange(AddressRange range, boolean forward) {
		return () -> forward ? new ForwardAddressIterator(range)
				: new BackwardAddressIterator(range);
	}

	public AddressIteratorAdapter(Iterator<AddressRange> outer, boolean forward) {
		super(outer, forward ? ForwardAddressIterator::new : BackwardAddressIterator::new);
	}

	public AddressIteratorAdapter(Iterator<AddressRange> outer, Address start, boolean forward) {
		super(outer, forward ? ar -> {
			if (!ar.contains(start)) {
				return new ForwardAddressIterator(ar);
			}
			return new ForwardAddressIterator(start, ar.getMaxAddress());
		} : ar -> {
			if (!ar.contains(start)) {
				return new BackwardAddressIterator(ar);
			}
			return new BackwardAddressIterator(ar.getMinAddress(), start);
		});
	}

	@Override
	public Iterator<Address> iterator() {
		return this;
	}
}
