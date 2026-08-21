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
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.util.MathUtilities;

/**
 * A class to break a range of addresses into 'chunks' of a give size. This is useful to break-up
 * processing of large swaths of addresses, such as when performing work in a background thread.
 * Doing this allows the client to iterator over the range, pausing enough to allow the UI to
 * update.
 */
public class AddressRangeChunker implements Iterable<AddressRange> {

	private Address end;
	private Address nextStartAddress;
	private long chunkSizeUnsigned;

	public AddressRangeChunker(AddressRange range, long chunkSizeUnsigned)
			throws IllegalArgumentException {
		this(range.getMinAddress(), range.getMaxAddress(), chunkSizeUnsigned);
	}

	public AddressRangeChunker(Address start, Address end, long chunkSizeUnsigned)
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

		if (chunkSizeUnsigned == 0) {
			throw new IllegalArgumentException("Chunk size must be greater than 0");
		}

		this.end = end;
		this.nextStartAddress = start;
		this.chunkSizeUnsigned = chunkSizeUnsigned;
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

				long availableLess1 = end.subtract(nextStartAddress);

				long sizeLess1 = MathUtilities.unsignedMin(chunkSizeUnsigned - 1, availableLess1);

				Address currentStart = nextStartAddress;
				Address currentEnd = nextStartAddress.addWrap(sizeLess1);
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

	@Override
	public Spliterator<AddressRange> spliterator() {
		long countAddrsLess1 = end.subtract(nextStartAddress);
		// Can't do the (count+size-1)/size thing since count+size may overflow
		long size = Long.divideUnsigned(countAddrsLess1, chunkSizeUnsigned) + 1;
		if (size <= 0) {
			// Known but too big to encode in (signed) long. 0 is actually 2**64.
			return Spliterators.spliteratorUnknownSize(iterator(), Spliterator.DISTINCT |
				Spliterator.NONNULL | Spliterator.ORDERED | Spliterator.SORTED);
		}
		return Spliterators.spliterator(iterator(), size,
			Spliterator.DISTINCT | Spliterator.NONNULL | Spliterator.ORDERED | Spliterator.SORTED |
				Spliterator.SIZED);
	}

	/**
	 * Stream the chunks
	 * 
	 * @return the stream
	 */
	public Stream<AddressRange> stream() {
		return StreamSupport.stream(spliterator(), false);
	}
}
