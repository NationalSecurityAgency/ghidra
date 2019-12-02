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

import java.util.Iterator;

/**
 * A class to break a range of addresses into 'chunks' of a give size.   This is useful to
 * break-up processing of large swaths of addresses, such as when performing work in a
 * background thread.  Doing this allows the client to iterator over the range, pausing
 * enough to allow the UI to update.
 */
public class AddressRangeChunker implements Iterable<AddressRange> {

	private Address end;
	private Address nextStartAddress;
	private int chunkSize;

	public AddressRangeChunker(AddressRange range, int chunkSize) throws IllegalArgumentException {
		this(range.getMinAddress(), range.getMaxAddress(), chunkSize);
	}

	public AddressRangeChunker(Address start, Address end, int chunkSize)
			throws IllegalArgumentException {

		if (start == null) {
			throw new IllegalArgumentException("Start address cannot be null");
		}

		if (end == null) {
			throw new IllegalArgumentException("End address cannot be null");
		}

		if (start.compareTo(end) > 0) {
			throw new IllegalArgumentException("Start address cannot be greater than end address");
		}

		// note: this could be changed to allow different spaces, chunking as necessary to
		//       break them apart
		AddressSpace startSpace = start.getAddressSpace();
		AddressSpace endSpace = end.getAddressSpace();
		if (!startSpace.equals(endSpace)) {
			throw new IllegalArgumentException("Address must be in the same address space");
		}

		if (chunkSize < 1) {
			throw new IllegalArgumentException("Chunk size must be greater than 0");
		}

		this.end = end;
		this.nextStartAddress = start;
		this.chunkSize = chunkSize;
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return new Iterator<AddressRange>() {

			@Override
			public boolean hasNext() {
				return nextStartAddress != null;
			}

			@Override
			public AddressRange next() {
				if (nextStartAddress == null) {
					return null;
				}

				long available = end.subtract(nextStartAddress) + 1; // +1 to be inclusive

				int size = chunkSize;
				if (available >= 0 && available < chunkSize) {
					size = (int) available;
				}

				Address currentStart = nextStartAddress;
				Address currentEnd = nextStartAddress.add(size - 1); // -1 since inclusive
				if (currentEnd.compareTo(end) == 0) {
					nextStartAddress = null; // no more
				}
				else {
					nextStartAddress = currentEnd.add(1);
				}

				return new AddressRangeImpl(currentStart, currentEnd);
			}

			@Override
			public void remove() {
				throw new UnsupportedOperationException();
			}

		};
	}
}
