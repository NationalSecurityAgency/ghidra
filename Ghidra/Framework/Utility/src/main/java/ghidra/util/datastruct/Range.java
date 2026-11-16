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

import java.util.Iterator;
import java.util.stream.LongStream;

import ghidra.util.exception.AssertException;

/**
 * A class for holding a minimum and maximum signed long values that define a range.
 */
public class Range implements Comparable<Range>, Iterable<Long> {
	/** The range's minimum extent. */
	public long min;
	/** The range's maximum extent (inclusive). */
	public long max;

	/**
	 * Creates a range whose extent is from min to max.
	 * @param min the minimum extent.
	 * @param max the maximum extent (inclusive).
	 * @throws IllegalArgumentException if max is less than min.
	 */
	public Range(long min, long max) {
		if (max < min) {
			throw new IllegalArgumentException(
				"Range max (" + max + ") cannot be less than min (" + min + ").");
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
		Range other = (Range) obj;
		return other.min == min && other.max == max;
	}

	@Override
	public int hashCode() {
		return toString().hashCode();
	}

	@Override
	public String toString() {
		return "(" + min + "," + max + ")";
	}

	/**
	 * Returns true if the value is within the ranges extent.
	 * @param value the value to check.
	 * @return true if the value is within the ranges extent.
	 */
	public boolean contains(long value) {
		return value >= min && value <= max;
	}

	/**
	 * Returns the range's size.
	 * @return the size
	 */
	public long size() {
		return max - min + 1;
	}

	@Override
	public Iterator<Long> iterator() {
		return LongStream.range(min, max + 1).iterator();
	}

	/**
	 * {@return the max value in this range}
	 */
	public long getMax() {
		return max;
	}

	/**
	 * {@return the min value in this range}
	 */
	public long getMin() {
		return min;
	}

	/**
	 * Returns the min value as in int value. This should only be used when you know that only
	 * int values are possible. If the min value is not within the range of an int value,
	 * an exception will be thrown.
	 * @throws AssertException if the min value in not within the range of an int value.
	 * @return the min value as an int value
	 */
	public int getMinAsInt() {
		if (min > Integer.MAX_VALUE || min < Integer.MIN_VALUE) {
			throw new AssertException("Expected min value to be in the integer range");
		}
		return (int) max;
	}

	/**
	 * Returns the max value as in int value. This should only be used when you know that only
	 * int values are possible. If the max value is not within the range of an int value,
	 * an exception will be thrown.
	 * @throws AssertException if the max value in not within the range of an int value.
	 * @return the max value as an int value
	 */
	public int getMaxAsInt() {
		if (max > Integer.MAX_VALUE || max < Integer.MIN_VALUE) {
			throw new AssertException("Expected max value to be in the integer range");
		}
		return (int) max;
	}

}
