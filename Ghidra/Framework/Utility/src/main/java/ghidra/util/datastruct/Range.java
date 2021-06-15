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
package ghidra.util.datastruct;

/**
 * A class for holding a minimum and maximum signed int values that define a range.
 */
public class Range implements Comparable<Range> {
	/** The range's minimum extent. */
	public int min;
	/** The range's maximum extent (inclusive). */
	public int max;
	/**
	 * Creates a range whose extent is from min to max.
	 * @param min the minimum extent.
	 * @param max the maximum extent (inclusive).
	 * @throws IllegalArgumentException if max is less than min.
	 */
	public Range(int min, int max) {
		if (max < min) {
			throw new IllegalArgumentException("Range max (" + max
					+ ") cannot be less than min (" + min + ").");
		}
		this.min = min;
		this.max = max;
	}

	@Override
	public int compareTo(Range other) {
		if (min == other.min) {
			return 0;
		}
		else if (min > other.min) {
			return 1;
		}
		return -1;
	}

	@Override
    public boolean equals(Object obj) {
		if (obj.getClass() != Range.class) {
			return false;
		}
		Range other = (Range)obj;
		return other.min == min && other.max == max;
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	@Override
    public String toString() {
		return "("+min+","+max+")";
	}
	/**
	 * Returns true if the value is within the ranges extent.
	 * @param value the value to check.
	 */
	public boolean contains(int value) {
		return value >= min && value <= max;
	}
	/**
	 * Returns the range's size.
	 */
	public long size() {
		return (long)max - (long)min + 1;
	}
}
