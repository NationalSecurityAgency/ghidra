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
package ghidra.app.util.demangler;

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
public class CharacterIterator {
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
	public CharacterIterator(String str) {
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
	 */
	public void setIndex(int index) {
		if (index < 0 || index > string.length() - 1) {
			throw new IllegalArgumentException();
		}
		this.index = index;
	}

	/**
	 * Returns true if there are more characters to read.
	 * @return true if there are more characters to read
	 */
	public boolean hasNext() {
		return index < string.length();
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
	 * Returns the next ascii string of the specified length starting
	 * at the current index.
	 * @param len the length of the string to read
	 * @return the next ascii string
	 */
	public String nextString(int len) {
		String s = string.substring(index, index + len);
		index = index + len;
		return s;
	}

	/**
	 * Returns the next integer. The radix must be 10 (decimal).
	 * For example, given "...12fred..". If current index is pointing
	 * to the '1', then this value will return 12.
	 * @return the next base-10 integer.
	 */
	public int nextInteger() {
		int origIndex = index;
		while (Character.isDigit(peek())) {
			getAndIncrement();
		}
		if (origIndex == index) {
			return string.charAt(index) - '0';
		}
		String s = string.substring(origIndex, index);
		try {
			return Integer.parseInt(s);
		}
		catch (NumberFormatException e) {
			index = origIndex;
			throw e;
		}
	}

	/**
	 * Looks for the next occurrence of 'c' starting
	 * at the current index. Returns the character
	 * position in the underlying string or -1 if 'c'
	 * is not found.
	 */
	public int find(char c) {
		for (int i = index; i < string.length(); ++i) {
			if (string.charAt(i) == c) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public String toString() {
		return "currnt = " + peek() + "; next = " + peek(1);
	}
}
