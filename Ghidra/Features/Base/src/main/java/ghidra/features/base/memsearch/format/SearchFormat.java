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
package ghidra.features.base.memsearch.format;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.ByteMatcher;

/**
 * SearchFormats are responsible for parsing user input data into a {@link ByteMatcher} that
 * can be used for searching memory. It also can convert search matches back into string data and 
 * can convert string data from other formats into string data for this format.
 */

public abstract class SearchFormat {
	//@formatter:off
	public static SearchFormat HEX = new HexSearchFormat();
	public static SearchFormat BINARY = new BinarySearchFormat();
	public static SearchFormat DECIMAL = new DecimalSearchFormat();
	
	public static SearchFormat STRING = new StringSearchFormat();
	public static SearchFormat REG_EX = new RegExSearchFormat();
	
	public static SearchFormat FLOAT = new FloatSearchFormat("Float", "Floating Point", 4);
	public static SearchFormat DOUBLE = new FloatSearchFormat("Double", "Floating Point (8)", 8);
	//@formatter:on

	public static SearchFormat[] ALL =
		{ HEX, BINARY, DECIMAL, STRING, REG_EX, FLOAT, DOUBLE };

	// SearchFormats fall into one of 4 types
	public enum SearchFormatType {
		BYTE, INTEGER, FLOATING_POINT, STRING_TYPE
	}

	private final String name;

	protected SearchFormat(String name) {
		this.name = name;
	}

	/**
	 * Parse the given input and settings into a {@link ByteMatcher}
	 * @param input the user input string
	 * @param settings the current search/parse settings
	 * @return a ByteMatcher that can be used for searching bytes (or an error version of a matcher)
	 */
	public abstract ByteMatcher parse(String input, SearchSettings settings);

	/**
	 * Returns a tool tip describing this search format
	 * @return a tool tip describing this search format
	 */
	public abstract String getToolTip();

	/**
	 * Returns the name of the search format.
	 * @return the name of the search format
	 */
	public String getName() {
		return name;
	}

	@Override
	public String toString() {
		return getName();
	}

	/**
	 * Reverse parses the bytes back into input value strings. Note that this is only used by
	 * numerical and string type formats. Byte oriented formats just return an empty string.
	 * @param bytes the to convert back into input value strings
	 * @param settings The search settings used to parse the input into bytes
	 * @return the string of the reversed parsed byte values
	 */
	public String getValueString(byte[] bytes, SearchSettings settings) {
		return "";
	}

	/**
	 * Returns a new search input string, doing its best to convert an input string that
	 * was parsed by a previous {@link SearchFormat}. When it makes sense to do so, it will
	 * re-interpret the parsed bytes from the old format and reconstruct the input from those
	 * bytes. This allows the user to do conversions, for example, from numbers to hex or binary and 
	 * vise-versa. If the byte conversion doesn't make sense based on the old and new formats, it
	 * will use the original input if that input can be parsed by the new input. Finally, if all
	 * else fails, the new input will be the empty string.
	 * 
	 * @param text the old input that is parsable by the old format
	 * @param oldSettings the search settings used to parse the old text
	 * @param newSettings the search settings to used for the new text
	 * @return the "best" text to change the user search input to
	 */
	public abstract String convertText(String text, SearchSettings oldSettings,
			SearchSettings newSettings);

	/**
	 * Returns the {@link SearchFormatType} for this format. This is used to help with the
	 * {@link #convertText(String, SearchSettings, SearchSettings)} method.
	 * @return the type for this format
	 */
	public abstract SearchFormatType getFormatType();

	/**
	 * Compares bytes from search results based on how this format interprets the bytes.
	 * By default, formats just compare the bytes one by one as if they were unsigned values.
	 * SearchFormats whose bytes represent numerical values will override this method and
	 * compare the bytes after interpreting them as numerical values.
	 * 
	 * @param bytes1 the first array of bytes to compare
	 * @param bytes2 the second array of bytes to compare
	 * @param settings the search settings used to generate the bytes.
	 * 
	 * @return  a negative integer, zero, or a positive integer as the first byte array 
	 * is less than, equal to, or greater than the second byte array
	 * 
	 */
	public int compareValues(byte[] bytes1, byte[] bytes2, SearchSettings settings) {
		return compareBytesUnsigned(bytes1, bytes2);
	}

	protected void reverse(byte[] bytes) {
		for (int i = 0; i < bytes.length / 2; i++) {
			int swapIndex = bytes.length - 1 - i;
			byte tmp = bytes[i];
			bytes[i] = bytes[swapIndex];
			bytes[swapIndex] = tmp;
		}
	}

	private int compareBytesUnsigned(byte[] oldBytes, byte[] newBytes) {
		for (int i = 0; i < oldBytes.length; i++) {
			int value1 = oldBytes[i] & 0xff;
			int value2 = newBytes[i] & 0xff;
			if (value1 != value2) {
				return value1 - value2;
			}
		}
		return 0;
	}

	protected boolean isValidText(String text, SearchSettings settings) {
		ByteMatcher byteMatcher = parse(text, settings);
		return byteMatcher.isValidSearch();
	}

}
