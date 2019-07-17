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
 * Associates an integer value with a numeric range.
 */
public class ObjectValueRange<T> implements Comparable<ObjectValueRange<T>> {
	private long start;
	private long end;
	private T value;
	
	/**
	 * Constructor for numeric range with an associated value.
	 * @param start beginning of the range
	 * @param end end of the range
	 * @param value the value to associate with the range.
	 */
	public ObjectValueRange(long start, long end, T value) {
		this.start = start;
		this.end = end;
		this.value = value;
	}
	/**
	 * Returns the beginning of the range.
	 */
	public long getStart() {
		return start;
	}
	/**
	 * Returns the end of the range.
	 */
	public long getEnd() {
		return end;
	}
	/**
	 * Returns the value associated with the range.
	 */
	public T getValue() {
		return value;
	}
	/**
	 * Determines whether or not the indicated index is in the range.
	 * @param index the index to check
	 * @return true if the index is in this range.
	 */
	public boolean contains(long index) {
		return index >= start && index <= end;
	}
	
	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	public int compareTo(ObjectValueRange<T> otherRange) {
		if (start < otherRange.start) {
			return -1;
		}
		if (start > otherRange.start) {
			return 1;
		}
		return 0;
	}


}
