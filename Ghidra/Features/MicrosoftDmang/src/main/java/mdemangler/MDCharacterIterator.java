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
package mdemangler;

/**
 * A class for bidirectional iteration over a string.
 * 
 * Iterators maintain a current character index, whose valid range is from
 * 0 to string.length()-1.
 * 
 * The current index can be retrieved by calling getIndex() and set directly
 * by calling setIndex().
 * 
 * The methods previous() and next() are used for iteration. They return DONE if
 * they would move outside the range from 0 to string.length()-1.
 */
public class MDCharacterIterator {
	/**
	 * Constant that is returned when the iterator has reached either the end
	 * or the beginning of the text. The value is '\\uFFFF', the "not a
	 * character" value which should not occur in any valid Unicode string.
	 */
	public static final char DONE = '\uFFFF';

	private String string;
	private int index;

	/**
	 * Constructs a new character iterator using str.
	 * @param str the string to iterate
	 */
	public MDCharacterIterator(String str) {
		this.string = str;
	}

	/**
	 * Returns the underlying string.
	 * @return the underlying string
	 */
	public String getString() {
		return string;
	}

	/**
	 * Returns the current index.
	 * @return the current index.
	 */
	public int getIndex() {
		return index;
	}

	/**
	 * Returns the length of the iterator.
	 * @return the length of the iterator
	 */
	public int getLength() {
		return string.length();
	}

	/**
	 * Sets the position to the specified position in the text.
	 * @param index the position within the text.  
	 * @return the character at the specified position
	 * @throws IllegalArgumentException if index is not in range from 0 to string.length()-1 
	 */
	public void setIndex(int index) {
		if (index < 0 || index > string.length() - 1) {
			throw new IllegalArgumentException();
		}
		this.index = index;
	}

	/**
	 * Returns true if there are more characters to read
	 * @return true if there are more characters to read
	 */
	public boolean hasNext() {
		return index < string.length() - 1;
	}

	/**
	 * Returns the next character without incrementing the current index. 
	 * @return the next character without incrementing the current index
	 */
	public char peek() {
		try {
			return string.charAt(index);
		}
		catch (IndexOutOfBoundsException e) {
			return DONE;
		}
	}

	/**
	 * Peeks at the character current index + lookAhead.
	 * Returns DONE if the computed position is out of range.
	 * @param lookAhead number of characters to look ahead
	 * @return the character at index+lookAhead
	 */
	public char peek(int lookAhead) {
		try {
			return string.charAt(index + lookAhead);
		}
		catch (IndexOutOfBoundsException e) {
			return DONE;
		}
	}

	/**
	 * Increments the current index by one and returns the character
	 * at the new index.  If the resulting index is greater or equal
	 * to the end index, the current index is reset to the end index and
	 * a value of DONE is returned.
	 * @return the character at the new position or DONE
	 */
	public char next() {
		try {
			return string.charAt(++index);
		}
		catch (IndexOutOfBoundsException e) {
			index = string.length();
			return DONE;
		}
	}

	/**
	 * Returns the character at the current index and then increments the index by one.  
	 * If the resulting index is greater or equal
	 * to the end index, the current index is reset to the end index and
	 * a value of DONE is returned.
	 * @return the character at the new position or DONE
	 */
	public char getAndIncrement() {
		try {
			return string.charAt(index++);
		}
		catch (IndexOutOfBoundsException e) {
			index = string.length();
			return DONE;
		}
	}

	/**
	 * Increments the index by one.  
	 * Does no testing for whether the index surpasses the length of the string.
	 */
	public void increment() {
		index++;
	}

	/**
	 * Increments the index by the amount of count.  
	 * Does no testing for whether the index surpasses the length of the string.
	 */
	public void increment(int count) {
		index += count;
	}

	/**
	 * Decrements the current index by one and returns the character
	 * at the new index. If the current index is 0, the index
	 * remains at 0 and a value of DONE is returned.
	 * @return the character at the new position or DONE
	 */
	public char previous() {
		try {
			return string.charAt(--index);
		}
		catch (IndexOutOfBoundsException e) {
			index = 0;
			return DONE;
		}
	}

	/**
	 * Returns true if substring is found at the current index.
	 * @return true if substring is found at the current index
	 */
	public boolean positionStartsWith(String substring) {
		return string.regionMatches(index, substring, 0, substring.length());
	}
}
