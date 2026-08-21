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
package ghidra.util.bytesearch;

import java.util.Objects;

/**
 * Represents a match of a pattern at a given offset in a byte sequence.
 * 
 * @param <T> The specific implementation of the BytePattern that was used to create this match
 * 
 */
public class Match<T> {
	private T pattern;		// Pattern that matched
	private long start;		// position in the input byte sequence where this pattern matched
	private int length;

	/**
	 * Construct a Match of a BytePattern that matched at a position in the input byte sequence.
	 * @param pattern the byte pattern that matched
	 * @param start the location in the input byte sequence where the pattern match begins
	 * @param length the length of the matching sequence
	 */
	public Match(T pattern, long start, int length) {
		this.pattern = pattern;
		this.start = start;
		this.length = length;
	}

	/**
	 * @return length in bytes of the matched pattern
	 */
	public int getLength() {
		return length;
	}

	/** 
	 * @return offset of match in sequence of bytes
	 */
	public long getStart() {
		return start;
	}

	/**
	 * @return the sequence that was matched
	 */
	public T getPattern() {
		return pattern;
	}

	@Override
	public String toString() {
		return pattern.toString() + " @ " + start;
	}

	@Override
	public int hashCode() {
		return Objects.hash(pattern, start, length);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		Match<?> other = (Match<?>) obj;
		return Objects.equals(pattern, other.pattern) && start == other.start &&
			length == other.length;
	}

}
