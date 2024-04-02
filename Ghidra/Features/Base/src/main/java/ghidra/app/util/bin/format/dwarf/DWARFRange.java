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
package ghidra.app.util.bin.format.dwarf;

import ghidra.program.model.address.AddressRange;

/**
 * Holds the start (inclusive) and end (exclusive, 1 past the last included address) addresses 
 * of a range.
 * <p>
 * DWARF ranges are slightly different than Ghidra {@link AddressRange ranges} because the
 * end address of a Ghidra AddressRange is inclusive, and the DWARF range is exclusive.
 * <p>
 * DWARF ranges can represent an empty range, Ghidra AddressRanges can not.<br>
 * Ghidra AddressRanges can include the maximum 64bit address (0xffffffffffffffff), but DWARF ranges
 * can not include that. 
 */
public class DWARFRange implements Comparable<DWARFRange> {
	public static final DWARFRange EMPTY = new DWARFRange(0, 0);

	private final long start;
	private final long end;

	/**
	 * Constructs a new {@link DWARFRange} using start and end values.
	 *
	 * @param start long starting address, inclusive
	 * @param end long ending address, exclusive
	 */
	public DWARFRange(long start, long end) {
		if (Long.compareUnsigned(end, start) < 0) {
			throw new IllegalArgumentException(
				"Range max (%d) cannot be less than min (%d).".formatted(end, start));
		}
		this.start = start;
		this.end = end;
	}

	@Override
	public String toString() {
		return "[%x,%x)".formatted(start, end);
	}

	@Override
	public int compareTo(DWARFRange other) {
		int tmp = Long.compareUnsigned(start, other.start);
		if (tmp == 0) {
			tmp = Long.compareUnsigned(end, other.end);
		}
		return tmp;
	}

	public boolean isEmpty() {
		return start == end;
	}

	public boolean contains(long addr) {
		return Long.compareUnsigned(start, addr) <= 0 && Long.compareUnsigned(addr, end) < 0;
	}

	/**
	 * Returns starting address.
	 *
	 * @return long starting address
	 */
	public long getFrom() {
		return this.start;
	}

	/**
	 * Returns ending address, exclusive.
	 *
	 * @return long ending address, exclusive.
	 */
	public long getTo() {
		return this.end;
	}

}
