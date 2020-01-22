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
package ghidra.program.model.data;

import ghidra.util.StringFormat;
import ghidra.util.StringUtilities;

/**
 * Helper class used to build up a formatted (for human consumption) string representation returned
 * by Unicode and String data types.
 * <p>
 * Call {@link #toString()} to retrieve the formatted string.
 * <p>
 * Example (quotes are part of result): {@code "Test\tstring",01,02,"Second\npart",00}
 *
 */
public class StringRenderBuilder {
	public static final char DOUBLE_QUOTE = '"';
	public static final char SINGLE_QUOTE = '\'';
	private static final int MAX_ASCII = 0x80;

	private StringBuilder sb = new StringBuilder();
	private boolean byteMode = true;
	private final char quoteChar;
	private final int charSize;

	public StringRenderBuilder(int charSize) {
		this(charSize, DOUBLE_QUOTE);
	}

	public StringRenderBuilder(int charSize, char quoteChar) {
		this.charSize = charSize;
		this.quoteChar = quoteChar;
	}

	/**
	 * Returns true if the current formatted string starts with a quoted text section,
	 * instead of a byte value section.  Useful to indicate if
	 * the string could have a prefix applied to it (ie. u8"text")
	 * <p>
	 * 
	 * @return boolean true if this string will start with a quoted text section
	 */
	public boolean startsWithQuotedText() {
		return sb.length() > 0 && sb.charAt(0) == quoteChar;
	}

	/**
	 * Append the characters in the specified string. The added characters will
	 * be shown in a quoted text region.
	 *
	 * @param str String to add
	 */
	public void addString(String str) {
		ensureTextMode();
		sb.append(str);
	}

	/**
	 * Append the specified char after an escaping backslash "\", ie
	 * {@literal "x" -> "\x";}
	 *
	 * @param ch
	 */
	public void addEscapedChar(char ch) {
		ensureTextMode();
		sb.append("\\").append(ch);
	}

	/**
	 * Add a single character.  It will be shown in a quoted text region.
	 *
	 * @param codePoint Character to add
	 */
	public void addCodePointChar(int codePoint) {
		ensureTextMode();
		if (codePoint == quoteChar) {
			sb.append("\\");
		}
		sb.appendCodePoint(codePoint);
	}

	/**
	 * Add a single character that needs to be shown as a numeric hex value.
	 *
	 * @param codePoint Character to add
	 */
	public void addCodePointValue(int codePoint) {
		ensureByteMode();
		String valStr = Integer.toHexString(codePoint).toUpperCase();
		valStr = (valStr.length() < charSize * 2)
				? StringFormat.padIt(valStr, charSize * 2, (char) 0, true)
				: valStr;
		sb.append(valStr);
	}

	/**
	 * Add byte values, shown as numeric hex values.
	 * <p>
	 * {@literal { 0, 1, 2 } -> 00,01,02}
	 *
	 * @param bytes to convert to hex and append.  If null, append "???"
	 */
	public void addByteSeq(byte[] bytes) {
		if (bytes == null) {
			ensureByteMode();
			sb.append("???");
			return;
		}
		for (int i = 0; i < bytes.length; i++) {
			ensureByteMode();
			String valStr = Integer.toHexString(bytes[i] & 0xff).toUpperCase();
			if (valStr.length() < 2) {
				sb.append("0");
			}
			sb.append(valStr).append("h");
		}
	}

	/**
	 * Add an unicode codepoint as its escaped hex value, with a escape character
	 * prefix of 'x', 'u' or 'U' depending on the magnitude of the codePoint value.
	 * <p>
	 * {@literal codePoint 15 -> '\' 'x' "0F"}<br>
	 * {@literal codePoint 65535 -> '\' 'u' "FFFF"}<br>
	 * {@literal codePoint 65536 -> '\' 'U' "10000"}<br>
	 *
	 * @param codePoint int value
	 */
	public void addEscapedCodePoint(int codePoint) {
		ensureTextMode();
		char escapeChar =
			(codePoint < MAX_ASCII) ? 'x' : Character.isBmpCodePoint(codePoint) ? 'u' : 'U';
		int cpDigits = (codePoint < MAX_ASCII) ? 2 : Character.isBmpCodePoint(codePoint) ? 4 : 8;
		String s = Integer.toHexString(codePoint).toUpperCase();
		sb.append("\\").append(escapeChar);
		sb.append(StringUtilities.pad(s, '0', cpDigits));
	}

	/**
	 * Example (quotes are part of result): {@code "Test\tstring",01,02,"Second\npart",00}
	 * <p>
	 * @return Formatted string
	 */
	@Override
	public String toString() {
		String str = sb.toString();
		if (!byteMode) {
			// close the quoted text mode in the local string
			str = str + quoteChar;
		}
		return str;
	}

	private void ensureTextMode() {
		if (sb.length() == 0) {
			sb.append(quoteChar);
		}
		else if (byteMode) {
			sb.append(',');
			sb.append(quoteChar);
		}
		byteMode = false;
	}

	private void ensureByteMode() {
		if (!byteMode) {
			sb.append(quoteChar);
		}
		if (sb.length() > 0) {
			sb.append(',');
		}
		byteMode = true;
	}

}
