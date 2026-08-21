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

/**
 * {@link AddressRangeIterator} that takes a single address range and breaks it down into smaller
 * address ranges of a specified maximum size. This is useful for clients that want to break
 * down the processing of large address ranges into manageable chunks. For example, searching the
 * bytes in memory can be broken so that chunks can be read into reasonably sized buffers.
 */
public class AddressRangeSplitter implements AddressRangeIterator {
	private AddressRange remainingRange;
	private int splitSize;
	private boolean forward;

	/**
	 * Constructor
	 * @param range the address range to split apart
	 * @param splitSize the max size of each sub range
	 * @param forward if true, the sub ranges will be returned in address order; otherwise they
	 * will be returned in reverse address order.
	 */
	public AddressRangeSplitter(AddressRange range, int splitSize, boolean forward) {
		remainingRange = range;
		this.splitSize = splitSize;
		this.forward = forward;
	}

	@Override
	public boolean hasNext() {
		return remainingRange != null;
	}

	@Override
	public AddressRange next() {
		if (remainingRange == null) {
			return null;
		}
		if (isRangeSmallEnough()) {
			AddressRange returnValue = remainingRange;
			remainingRange = null;
			return returnValue;
		}
		return forward ? extractChunkFromStart() : extractChunkFromEnd();
	}

	private AddressRange extractChunkFromStart() {
		Address start = remainingRange.getMinAddress();
		Address end = start.add(splitSize - 1);
		remainingRange = new AddressRangeImpl(end.next(), remainingRange.getMaxAddress());
		return new AddressRangeImpl(start, end);
	}

	private AddressRange extractChunkFromEnd() {
		Address end = remainingRange.getMaxAddress();
		Address start = end.subtract(splitSize - 1);

		remainingRange = new AddressRangeImpl(remainingRange.getMinAddress(), start.previous());
		return new AddressRangeImpl(start, end);
	}

	private boolean isRangeSmallEnough() {
		try {
			int size = remainingRange.getBigLength().intValueExact();
			return size <= splitSize;
		}
		catch (ArithmeticException e) {
			return false;
		}
	}

}
