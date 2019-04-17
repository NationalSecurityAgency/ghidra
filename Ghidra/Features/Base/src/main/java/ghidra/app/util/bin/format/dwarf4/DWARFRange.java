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
package ghidra.app.util.bin.format.dwarf4;

/**
 * Holds the start (inclusive) and end (exclusive) addresses of a range.
 */
public class DWARFRange implements Comparable<DWARFRange> {

	private final long start;
	private final long end;

	/**
	 * Constructs a new {@link DWARFRange} using start and end values.
	 *
	 * @param start long starting address, inclusive
	 * @param end long ending address, exclusive
	 */
	public DWARFRange(long start, long end) {
		if (end < start) {
			throw new IllegalArgumentException(
				"Range max (" + end + ") cannot be less than min (" + start + ").");
		}
		this.start = start;
		this.end = end;
	}

	@Override
	public String toString() {
		return "(" + this.start + "," + this.end + ")";
	}

	@Override
	public int compareTo(DWARFRange other) {
		int tmp = Long.compare(start, other.start);
		if (tmp == 0) {
			tmp = Long.compare(end, other.end);
		}
		return tmp;
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
