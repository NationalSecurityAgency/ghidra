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
package ghidra.util;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;

import generic.json.Json;

/**
 * Class with static methods that deal with string manipulation.
 */
public class StringUtilities {

	/**
	 * Create the bi-directional mapping between control characters and escape sequences.
	 */
	private static Map<Character, String> controlToEscapeStringMap = new HashMap<>();
	private static Map<String, Character> escapeStringToControlMap = new HashMap<>();
	static {
		controlToEscapeStringMap.put('\t', "\\t");
		controlToEscapeStringMap.put('\b', "\\b");
		controlToEscapeStringMap.put('\r', "\\r");
		controlToEscapeStringMap.put('\n', "\\n");
		controlToEscapeStringMap.put('\f', "\\f");
		controlToEscapeStringMap.put('\\', "\\\\");
		controlToEscapeStringMap.put((char) 0xb, "\\v");
		controlToEscapeStringMap.put((char) 0x7, "\\a");

		escapeStringToControlMap.put("\\t", '\t');
		escapeStringToControlMap.put("\\b", '\b');
		escapeStringToControlMap.put("\\r", '\r');
		escapeStringToControlMap.put("\\n", '\n');
		escapeStringToControlMap.put("\\f", '\f');
		escapeStringToControlMap.put("\\\\", '\\');
		escapeStringToControlMap.put("\\v", (char) 0xb);
		escapeStringToControlMap.put("\\a", (char) 0x7);

		// this one is special to allow users to enter nulls in search strings - don't
		// want the reverse
		escapeStringToControlMap.put("\\0", '\0');
	}

	private static final String ELLIPSES = "...";

	public static final Pattern DOUBLE_QUOTED_STRING_PATTERN =
		Pattern.compile("^\"((?:[^\\\\\"]|\\\\.)*)\"$");

	/**
	 * The platform specific string that is the line separator.
	 */
	public final static String LINE_SEPARATOR = System.getProperty("line.separator");

	public static final int UNICODE_REPLACEMENT = 0xFFFD;

	/**
	 * Unicode Byte Order Marks (BOM) characters are special characters in the Unicode character
	 * space that signal endian-ness of the text.
	 * <p>
	 * The value for the BigEndian version (0xFEFF) works for both 16 and 32 bit character values.
	 * <p>
	 * There are separate values for Little Endian Byte Order Marks for 16 and 32 bit characters
	 * because the 32 bit value is shifted left by 16 bits.
	 */
	public static final int UNICODE_BE_BYTE_ORDER_MARK = 0xFEFF;
	public static final int UNICODE_LE16_BYTE_ORDER_MARK = 0x0____FFFE;
	public static final int UNICODE_LE32_BYTE_ORDER_MARK = 0xFFFE_0000;

	// This is Java's default rendered size of a tab (in spaces) 
	public static final int DEFAULT_TAB_SIZE = 8;

	private StringUtilities() {
		// utility class; can't create
	}

	/**
	 * Returns true if the given character is a special character. For example a '\n' or '\\'. A
	 * value of 0 is not considered special for this purpose as it is handled separately because it
	 * has more varied use cases.
	 *
	 * @param c the character
	 * @return true if the given character is a special character
	 */
	public static boolean isControlCharacterOrBackslash(char c) {
		return controlToEscapeStringMap.containsKey(c);
	}

	/**
	 * Returns true if the given codePoint (ie. full unicode 32bit character) is a special
	 * character. For example a '\n' or '\\'. A value of 0 is not considered special for this
	 * purpose as it is handled separately because it has more varied use cases.
	 *
	 * @param codePoint the codePoint (ie. character), see {@link String#codePointAt(int)}
	 * @return true if the given character is a special character
	 */
	public static boolean isControlCharacterOrBackslash(int codePoint) {
		return (0 <= codePoint && codePoint < Character.MIN_SUPPLEMENTARY_CODE_POINT) &&
			isControlCharacterOrBackslash((char) codePoint);
	}

	/**
	 * Determines if a string is enclosed in double quotes (ASCII 34 (0x22))
	 * 
	 * @param str String to test for double-quote enclosure
	 * @return True if the first and last characters are the double-quote character, false otherwise
	 */
	public static boolean isDoubleQuoted(String str) {
		Matcher m = DOUBLE_QUOTED_STRING_PATTERN.matcher(str);
		return m.matches();
	}

	/**
	 * If the given string is enclosed in double quotes, extract the inner text. Otherwise, return
	 * the given string unmodified.
	 * 
	 * @param str String to match and extract from
	 * @return The inner text of a doubly-quoted string, or the original string if not
	 *         double-quoted.
	 */
	public static String extractFromDoubleQuotes(String str) {
		Matcher m = DOUBLE_QUOTED_STRING_PATTERN.matcher(str);
		if (m.matches()) {
			return m.group(1);
		}
		return str;
	}

	/**
	 * Returns true if the character is in displayable character range
	 * 
	 * @param c the character
	 * @return true if the character is in displayable character range
	 */
	public static boolean isDisplayable(int c) {
		return c >= 0x20 && c < 0x7F;
	}

	/**
	 * Returns true if all the given sequences are either null or only whitespace
	 *
	 * @param sequences the sequences to check
	 * @return true if all the given sequences are either null or only whitespace.
	 * @see StringUtils#isNoneBlank(CharSequence...)
	 * @see StringUtils#isNoneEmpty(CharSequence...)
	 * @see StringUtils#isAnyBlank(CharSequence...)
	 * @see StringUtils#isAnyEmpty(CharSequence...)
	 */
	public static boolean isAllBlank(CharSequence... sequences) {
		if (sequences == null) {
			return true;
		}

		for (CharSequence s : sequences) {
			if (!StringUtils.isBlank(s)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Converts the character into a string. If the character is special, it will actually render
	 * the character. For example, given '\n' the output would be "\\n".
	 * 
	 * @param c the character to convert into a string
	 * @return the converted character
	 */
	public static String characterToString(char c) {
		String escaped = controlToEscapeStringMap.get(c);
		if (escaped == null) {
			escaped = Character.toString(c);
		}
		return escaped;
	}

	/**
	 * Returns a count of how many times the 'occur' char appears in the strings.
	 * 
	 * @param string the string to look inside
	 * @param occur the character to look for/
	 * @return a count of how many times the 'occur' char appears in the strings
	 */
	public static int countOccurrences(String string, char occur) {
		int count = 0;
		int length = string.length();
		for (int i = 0; i < length; ++i) {
			if (string.charAt(i) == occur) {
				++count;
			}
		}
		return count;
	}

	public static boolean equals(String s1, String s2, boolean caseSensitive) {
		if (s1 == null) {
			return s2 == null;
		}
		if (caseSensitive) {
			return s1.equals(s2);
		}
		return s1.equalsIgnoreCase(s2);
	}

	public static boolean endsWithWhiteSpace(String string) {
		return Character.isWhitespace(string.charAt(string.length() - 1));
	}

	/**
	 * Generate a quoted string from US-ASCII character bytes assuming 1-byte chars.
	 * <p>
	 * Special characters and non-printable characters will be escaped using C character escape
	 * conventions (e.g., \t, \n, \\uHHHH, etc.). If a character size other than 1-byte is required
	 * the alternate form of this method should be used.
	 * <p>
	 * The result string will be single quoted (ie. "'") if the input byte array is 1 byte long,
	 * otherwise the result will be double-quoted ('"').
	 *
	 * @param bytes character string bytes
	 * @return escaped string for display use
	 */
	public static String toQuotedString(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		for (byte b : bytes) {
			appendCharConvertedToEscapeSequence((char) (b & 0xff), 1, builder);
		}
		String str = builder.toString();
		if (bytes.length == 1) {
			str = str.replace("'", "\\'");
			return "'" + str + "'";
		}
		str = str.replace("\"", "\\\"");
		return "\"" + str + "\"";
	}

	/**
	 * Generate a quoted string from US-ASCII characters, where each character is charSize bytes.
	 * <p>
	 * Special characters and non-printable characters will be escaped using C character escape
	 * conventions (e.g., \t, \n, \\uHHHH, etc.).
	 * <p>
	 * The result string will be single quoted (ie. "'") if the input byte array is 1 character long
	 * (ie. charSize), otherwise the result will be double-quoted ('"').
	 *
	 * @param bytes array of bytes
	 * @param charSize number of bytes per character (1, 2, 4).
	 * @return escaped string for display use
	 */
	public static String toQuotedString(byte[] bytes, int charSize) {
		if (charSize <= 1) {
			return toQuotedString(bytes);
		}
		else if (charSize > 4) {
			throw new IllegalArgumentException("unsupported charSize: " + charSize);
		}
		int shortage = bytes.length % charSize;
		if (shortage != 0) {
			byte[] paddedBytes = new byte[bytes.length + shortage];
			System.arraycopy(bytes, 0, paddedBytes, 0, bytes.length);
			bytes = paddedBytes;
		}
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < bytes.length; i += charSize) {
			int val = 0;
			for (int n = 0; n < charSize; n++) {
				val = (val << 8) + (bytes[i + n] & 0xff);
			}
			appendCharConvertedToEscapeSequence(val, charSize, builder);
		}
		String str = builder.toString();
		if (bytes.length <= charSize) {
			str = str.replace("'", "\\'");
			return "'" + str + "'";
		}
		str = str.replace("\"", "\\\"");
		return "\"" + str + "\"";
	}

	private static void appendCharConvertedToEscapeSequence(int c, int charSize,
			StringBuilder builder) {
		if (controlToEscapeStringMap.containsKey((char) c)) {
			builder.append(controlToEscapeStringMap.get((char) c));
		}
		else if (c >= 0x20 && c <= 0x7f) {
			builder.append((char) c);
		}
		else if (charSize <= 1) {
			builder.append("\\x" + pad(Integer.toHexString(c), '0', 2));
		}
		else if (charSize == 2) {
			builder.append("\\u" + pad(Integer.toHexString(c), '0', 4));
		}
		else if (charSize <= 4) {
			builder.append("\\U" + pad(Integer.toHexString(c), '0', 8));
		}
		else {
			// TODO: unsupported
		}
	}

	/**
	 * Returns true if the given string starts with <code>prefix</code> ignoring case.
	 * <p>
	 * Note: This method is equivalent to calling:
	 * 
	 * <pre>
	 * string.regionMatches(true, 0, prefix, 0, prefix.length());
	 * </pre>
	 *
	 * @param string the string which may contain the prefix
	 * @param prefix the prefix to test against
	 * @return true if the given string starts with <code>prefix</code> ignoring case.
	 */
	public static boolean startsWithIgnoreCase(String string, String prefix) {
		if ((string == null) || (prefix == null)) {
			return false;
		}
		return string.regionMatches(true, 0, prefix, 0, prefix.length());
	}

	/**
	 * Returns true if the given string ends with <code>postfix</code>, ignoring case.
	 * <p>
	 * Note: This method is equivalent to calling:
	 * 
	 * <pre>
	 * int startIndex = string.length() - postfix.length();
	 * string.regionMatches(true, startOffset, postfix, 0, postfix.length());
	 * </pre>
	 *
	 * @param string the string which may end with <code>postfix</code>
	 * @param postfix the string for which to test existence
	 * @return true if the given string ends with <code>postfix</code>, ignoring case.
	 */
	public static boolean endsWithIgnoreCase(String string, String postfix) {
		if ((string == null) || (postfix == null)) {
			return false;
		}
		int startIndex = string.length() - postfix.length();
		return string.regionMatches(true, startIndex, postfix, 0, postfix.length());
	}

	/**
	 * Returns true if all the given <code>searches</code> are contained in the given string.
	 *
	 * @param toSearch the string to search
	 * @param searches the strings to find
	 * @return true if all the given <code>searches</code> are contained in the given string.
	 */
	public static boolean containsAll(CharSequence toSearch, CharSequence... searches) {
		if (StringUtils.isEmpty(toSearch) || ArrayUtils.isEmpty(searches)) {
			return false;
		}

		for (CharSequence search : searches) {
			if (!StringUtils.contains(toSearch, search)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if all the given <code>searches</code> are contained in the given string,
	 * ignoring case.
	 *
	 * @param toSearch the string to search
	 * @param searches the strings to find
	 * @return true if all the given <code>searches</code> are contained in the given string.
	 */
	public static boolean containsAllIgnoreCase(CharSequence toSearch, CharSequence... searches) {
		if (StringUtils.isEmpty(toSearch)) {
			return false;
		}

		for (CharSequence search : searches) {
			if (!StringUtils.containsIgnoreCase(toSearch, search)) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Returns true if any of the given <code>searches</code> are contained in the given string,
	 * ignoring case.
	 *
	 * @param toSearch the string to search
	 * @param searches the strings to find
	 * @return true if any of the given <code>searches</code> are contained in the given string.
	 */
	public static boolean containsAnyIgnoreCase(CharSequence toSearch, CharSequence... searches) {
		if (StringUtils.isEmpty(toSearch)) {
			return false;
		}

		for (CharSequence search : searches) {
			if (StringUtils.containsIgnoreCase(toSearch, search)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the index of the first whole word occurrence of the search word within the given
	 * text. A whole word is defined as the character before and after the occurrence must not be a
	 * JavaIdentifierPart.
	 * 
	 * @param text the text to be searched.
	 * @param searchWord the word to search for.
	 * @return the index of the first whole word occurrence of the search word within the given
	 *         text, or -1 if not found.
	 */
	public static int indexOfWord(String text, String searchWord) {
		int index = 0;
		while (index < text.length()) {
			index = text.indexOf(searchWord, index);
			if (index < 0) {
				return -1;
			}
			if (isWholeWord(text, index, searchWord.length())) {
				return index;
			}
			index += searchWord.length();
		}
		return -1;
	}

	/**
	 * Returns true if the substring within the text string starting at startIndex and having the
	 * given length is a whole word. A whole word is defined as the character before and after the
	 * occurrence must not be a JavaIdentifierPart.
	 * 
	 * @param text the text containing the potential word.
	 * @param startIndex the start index of the potential word within the text.
	 * @param length the length of the potential word
	 * @return true if the substring within the text string starting at startIndex and having the
	 *         given length is a whole word.
	 */
	public static boolean isWholeWord(String text, int startIndex, int length) {
		if (startIndex > 0) {
			if (Character.isJavaIdentifierPart(text.charAt(startIndex - 1))) {
				return false;
			}
		}
		int endIndex = startIndex + length;
		if (endIndex < text.length()) {
			if (Character.isJavaIdentifierPart(text.charAt(endIndex))) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Convert tabs in the given string to spaces using a default tab width of 8 spaces.
	 *
	 * @param str string containing tabs
	 * @return string that has spaces for tabs
	 */
	public static String convertTabsToSpaces(String str) {
		return convertTabsToSpaces(str, DEFAULT_TAB_SIZE);
	}

	/**
	 * Convert tabs in the given string to spaces.
	 *
	 * @param str string containing tabs
	 * @param tabSize length of the tab
	 * @return string that has spaces for tabs
	 */
	public static String convertTabsToSpaces(String str, int tabSize) {
		if (str == null) {
			return null;
		}

		StringBuffer buffer = new StringBuffer();

		int linepos = 0;

		for (int i = 0; i < str.length(); i++) {
			char c = str.charAt(i);
			if (c == '\t') {
				int nSpaces = tabSize - (linepos % tabSize);
				String pad = pad("", ' ', nSpaces);
				buffer.append(pad);
				linepos += nSpaces;
			}
			else {
				buffer.append(c);
				linepos++;
				if (c == '\n') {
					linepos = 0;
				}
			}
		}

		return buffer.toString();
	}

	/**
	 * Parses a string containing multiple lines into an array where each element in the array
	 * contains only a single line. The "\n" character is used as the delimiter for lines.
	 * <p>
	 * This methods creates an empty string entry in the result array for initial and trailing
	 * separator chars, as well as for consecutive separators.
	 *
	 * @param str the string to parse
	 * @return an array of lines; an empty array if the given value is null or empty
	 * @see StringUtils#splitPreserveAllTokens(String, char)
	 */
	public static String[] toLines(String str) {
		return toLines(str, true);
	}

	/**
	 * Parses a string containing multiple lines into an array where each element in the array
	 * contains only a single line. The "\n" character is used as the delimiter for lines.
	 *
	 * @param s the string to parse
	 * @param preserveTokens true signals to treat consecutive newlines as multiple lines; false
	 *            signals to treat consecutive newlines as a single line break
	 * @return an array of lines; an empty array if the given value is null or empty
	 */
	public static String[] toLines(String s, boolean preserveTokens) {
		String[] lines = null;
		if (preserveTokens) {
			lines = StringUtils.splitPreserveAllTokens(s, '\n');
		}
		else {
			lines = StringUtils.split(s, '\n');
		}

		if (lines == null) {
			return new String[0];
		}
		return lines;
	}

	/**
	 * Enforces the given length upon the given string by trimming and then padding as necessary.
	 *
	 * @param s the String to fix
	 * @param pad the pad character to use if padding is required
	 * @param size the desired size of the string
	 * @return the fixed string
	 */
	public static String toFixedSize(String s, char pad, int size) {
		String trimmed = trim(s, size + ELLIPSES.length());
		String padded = pad(trimmed, pad, -size);
		return padded;
	}

	/**
	 * Pads the source string to the specified length, using the filler string as the pad. If length
	 * is negative, left justifies the string, appending the filler; if length is positive, right
	 * justifies the source string.
	 *
	 * @param source the original string to pad.
	 * @param filler the type of characters with which to pad
	 * @param length the length of padding to add (0 results in no changes)
	 * @return the padded string
	 */
	public static String pad(String source, char filler, int length) {

		if (length == 0) {
			return source;
		}

		boolean rightJustify = true;
		if (length < 0) {
			rightJustify = false;
			length *= -1;
		}

		int n = length - source.length();
		StringBuilder buffer = new StringBuilder();
		for (int i = 0; i < n; i++) {
			buffer.append(filler);
		}

		if (rightJustify) {
			buffer.append(source);
		}
		else {
			buffer.insert(0, source);
		}

		return buffer.toString();
	}

	/**
	 * Splits the given string into lines using <code>\n</code> and then pads each string with the
	 * given pad string. Finally, the updated lines are formed into a single string.
	 * <p>
	 * This is useful for constructing complicated <code>toString()</code> representations.
	 *
	 * @param s the input string
	 * @param indent the indent string; this will be appended as needed
	 * @return the output string
	 */
	public static String indentLines(String s, String indent) {
		String[] lines = toLines(s, false);
		StringBuilder buffy = new StringBuilder();
		for (String line : lines) {
			buffy.append(indent).append(line).append('\n');
		}

		if (buffy.length() > 0) {
			// trim off last newline so as not to add something that was not part of the
			// original string
			buffy.deleteCharAt(buffy.length() - 1);
		}

		return buffy.toString();
	}

	/**
	 * Finds the word at the given index in the given string. For example, the string "The tree is
	 * green" and the index of 5, the result would be "tree".
	 *
	 * @param s the string to search
	 * @param index the index into the string to "seed" the word.
	 * @return String the word contained at the given index.
	 */
	public static String findWord(String s, int index) {
		return findWord(s, index, null);
	}

	/**
	 * Finds the word at the given index in the given string; if the word contains the given
	 * charToAllow, then allow it in the string. For example, the string "The tree* is green" and
	 * the index of 5, charToAllow is '*', then the result would be "tree*".
	 * <p>
	 * If the search yields only whitespace, then the empty string will be returned.
	 *
	 * @param s the string to search
	 * @param index the index into the string to "seed" the word.
	 * @param charsToAllow chars that normally would be considered invalid, e.g., '*' so that the
	 *            word can be returned with the charToAllow
	 * @return String the word contained at the given index.
	 */
	public static String findWord(String s, int index, char[] charsToAllow) {

		WordLocation location = findWordLocation(s, index, charsToAllow);
		return location.getWord();
	}

	public static WordLocation findWordLocation(String s, int index, char[] charsToAllow) {

		int len = s.length();
		if (index < 0 || index >= len) {
			return WordLocation.empty(s);
		}

		char currChar = s.charAt(index);
		if (!isWordChar(currChar, charsToAllow)) {
			String substring = s.substring(index, index + 1);
			WordLocation wordLocation = new WordLocation(s, substring.trim(), index);
			return wordLocation;
		}

		int start = index;
		int end = index;
		for (; start >= 0; --start) {
			char c = s.charAt(start);
			if (!isWordChar(c, charsToAllow)) {
				break;
			}
		}

		for (; end < s.length(); ++end) {
			char c = s.charAt(end);
			if (!isWordChar(c, charsToAllow)) {
				break;
			}
		}

		int wordIndex = start + 1;
		String substring = s.substring(wordIndex, end);
		WordLocation wordLocation = new WordLocation(s, substring.trim(), wordIndex);
		return wordLocation;
	}

	/**
	 * Loosely defined as a character that we would expected to be an normal ascii content meant for
	 * consumption by a human. Also, provided allows chars will pass the test.
	 *
	 * @param c the char to check
	 * @param charsToAllow characters that will cause this method to return true
	 * @return true if it is a 'word char'
	 */
	public static boolean isWordChar(char c, char[] charsToAllow) {
		if (charsToAllow != null) {
			for (char element : charsToAllow) {
				if (c == element) {
					return true;
				}
			}
		}

		// the code, before refactoring, was using the 'c language' check for 'wordness'  Keep
		// that for now, change it if you like
		return isValidCLanguageChar(c);
	}

	/**
	 * Finds the starting position of the last word in the given string.
	 *
	 * @param s the string to search
	 * @return int the starting position of the last word, -1 if not found
	 */
	public static int findLastWordPosition(String s) {
		int len = s.length();
		int pos = -1;
		for (int i = len - 1; i >= 0; --i) {
			char c = s.charAt(i);
			if (!Character.isLetterOrDigit(c)) {
				pos = i + 1;
				break;
			}
		}
		// did string end of a char that is not a letter or digit?
		if (pos >= len) {
			pos = -1;
		}
		return pos;
	}

	/**
	 * Takes a path-like string and retrieves the last non-empty item. Examples:
	 * <ul>
	 * <li>StringUtilities.getLastWord("/This/is/my/last/word/", "/") returns word</li>
	 * <li>StringUtilities.getLastWord("/This/is/my/last/word/", "/") returns word</li>
	 * <li>StringUtilities.getLastWord("This.is.my.last.word", ".") returns word</li>
	 * <li>StringUtilities.getLastWord("/This/is/my/last/word/MyFile.java", ".") returns java</li>
	 * <li>StringUtilities.getLastWord("/This/is/my/last/word/MyFile.java", "/") returns
	 * MyFile.java</li>
	 * </ul>
	 *
	 * @param s the string from which to get the last word
	 * @param separator the separator of words
	 * @return the last word
	 */
	public static String getLastWord(String s, String separator) {

		if (s == null) {
			return null;
		}

		String escaped = Pattern.quote(separator);
		String[] parts = s.split(escaped);
		String last = parts[parts.length - 1];
		return last;
	}

	/**
	 * Converts an integer into a string. For example, given an integer 0x41424344, the returned
	 * string would be "ABCD".
	 * 
	 * @param value the integer value
	 * @return the converted string
	 */
	public static String toString(int value) {
		byte[] bytes = new byte[4];
		int byteIndex = bytes.length - 1;
		while (value != 0) {
			bytes[byteIndex] = (byte) value;
			value = value >> 8;
			--byteIndex;
		}
		return new String(bytes);
	}

	/**
	 * Creates a JSON string for the given object using all of its fields. To control the fields
	 * that are in the result string, see {@link Json}.
	 * 
	 * <P>
	 * This is here as a marker to point users to the real {@link Json} String utility.
	 * 
	 * @param o the object for which to create a string
	 * @return the string
	 */
	public static String toStingJson(Object o) {
		return Json.toString(o);
	}

	public static String toStringWithIndent(Object o) {
		if (o == null) {
			return "null";
		}

		String asString = o.toString();
		String indented = indentLines(asString, "\t");
		return indented;
	}

	/**
	 * Merge two strings into one. If one string contains the other, then the largest is returned.
	 * If both strings are null then null is returned. If both strings are empty, the empty string
	 * is returned. If the original two strings differ, this adds the second string to the first
	 * separated by a newline.
	 * 
	 * @param string1 the first string
	 * @param string2 the second string
	 * @return the merged string
	 */
	public static String mergeStrings(String string1, String string2) {
		if (string1 == null && string2 == null) {
			return null; // Both strings are null;
		}
		boolean hasString1 = (string1 != null && !string1.equals(""));
		boolean hasString2 = (string2 != null && !string2.equals(""));

		if (hasString1) {
			if (hasString2) {
				int length1 = string1.length();
				int length2 = string2.length();
				boolean string1contains2 = (length2 <= length1) && string1.contains(string2);
				if (string1contains2) {
					return string1;
				}
				boolean string2contains1 = (length1 <= length2) && string2.contains(string1);
				if (string2contains1) {
					return string2;
				}
				// Different strings are defined, so merge them.
				return string1 + "\n" + string2;
			}
			return string1; // Only have string1.
		}
		if (hasString2) {
			return string2; // Only have string2.
		}
		return ""; // No strings but at least one empty string, so return empty string.
	}

	/**
	 * Limits the given string to the given <code>max</code> number of characters. If the string is
	 * larger than the given length, then it will be trimmed to fit that length <b>after adding
	 * ellipses</b>
	 *
	 * <p>
	 * The given <code>max</code> value must be at least 4. This is to ensure that, at a minimum, we
	 * can display the {@value #ELLIPSES} plus one character.
	 *
	 * @param original The string to be limited
	 * @param max The maximum number of characters to display (including ellipses, if trimmed).
	 * @return the trimmed string
	 * @throws IllegalArgumentException If the given <code>max</code> value is less than 5.
	 */
	public static String trim(String original, int max) {
		int minimum = ELLIPSES.length() + 1; // +1 for at least one char
		if (max < minimum) {
			throw new IllegalArgumentException("Max cannot be less than " + minimum);
		}

		if (original.length() > max) {
			return original.substring(0, max - 3) + ELLIPSES;
		}
		return original;
	}

	public static String trimTrailingNulls(String s) {
		int i = s.length() - 1;
		while (i >= 0 && s.charAt(i) == 0) {
			i--;
		}
		return s.substring(0, i + 1);
	}

	/**
	 * Trims the given string the <code>max</code> number of characters. Ellipses will be added to
	 * signal that content was removed. Thus, the actual number of removed characters will be
	 * <code>(s.length() - max) + {@value StringUtilities#ELLIPSES}</code> length.
	 *
	 * <p>
	 * If the string fits within the max, then the string will be returned.
	 *
	 * <p>
	 * The given <code>max</code> value must be at least 5. This is to ensure that, at a minimum, we
	 * can display the {@value #ELLIPSES} plus one character from the front and back of the string.
	 *
	 * @param s the string to trim
	 * @param max the max number of characters to allow.
	 * @return the trimmed string
	 */
	public static String trimMiddle(String s, int max) {

		int len = s.length();
		if (len <= max) {
			return s;
		}

		int minimum = ELLIPSES.length() + 2; // +2 for one char on each side
		if (max < minimum) {
			throw new IllegalArgumentException("Max cannot be less than " + minimum);
		}

		int toRemove = (len - max) + ELLIPSES.length();
		int toKeep = len - toRemove;
		int lhsSize = toKeep / 2;
		int rhsSize = lhsSize;

		if (toKeep % 2 != 0) {
			rhsSize++; // compensate for roundoff on odd size
		}

		StringBuilder buffy = new StringBuilder();
		buffy.append(s.substring(0, lhsSize));
		buffy.append(ELLIPSES);
		buffy.append(s.substring(len - rhsSize, len));

		return buffy.toString();
	}

	/**
	 * This method looks for all occurrences of successive asterisks (i.e., "**") and replace with a
	 * single asterisk, which is an equivalent usage in Ghidra. This is necessary due to some symbol
	 * names which cause the pattern matching process to become unusable. An example string that
	 * causes this problem is
	 * "s_CLSID\{ADB880A6-D8FF-11CF-9377-00AA003B7A11}\InprocServer3_01001400".
	 *
	 * @param value The string to be checked.
	 * @return The updated string.
	 */
	public static String fixMultipleAsterisks(String value) {
		if (value.indexOf("**") < 0) {
			return value;
		}

		// check for multiple asterisks in the string that are not preceded by
		// an escape character
		// "\\*{2,}" says to match any '*' character that occurs 2 or more times
		return value.replaceAll("\\*{2,}", "*");
	}

	/**
	 * Returns true if the character is OK to be contained inside C language string. That is, the
	 * string should not be tokenized on this char.
	 *
	 * @param c the char
	 * @return boolean true if it is allows in a C string
	 */
	public static boolean isValidCLanguageChar(char c) {
		return Character.isLetterOrDigit(c) || c == '_'; // underscore
	}

	/**
	 * Returns true if the given character is within the ascii range.
	 *
	 * @param c the char to check
	 * @return true if the given character is within the ascii range.
	 */
	public static boolean isAsciiChar(char c) {
		return (0x20 <= c) && (c <= 0x7f);
	}

	/**
	 * Returns true if the given code point is within the ascii range.
	 *
	 * @param codePoint the codePoint to check
	 * @return true if the given character is within the ascii range.
	 */
	public static boolean isAsciiChar(int codePoint) {
		return (0x20 <= codePoint) && (codePoint <= 0x7f);
	}

	/**
	 * Replaces escaped characters in a string to corresponding control characters. For example a
	 * string containing a backslash character followed by a 'n' character would be replaced with a
	 * single line feed (0x0a) character. One use for this is to to allow users to type strings in a
	 * text field and include control characters such as line feeds and tabs.
	 *
	 * The string that contains 'a','b','c', '\', 'n', 'd', '\', 'u', '0', '0', '0', '1', 'e' would
	 * become 'a','b','c',0x0a,'d', 0x01, e"
	 *
	 * @param str The string to convert escape sequences to control characters.
	 * @return a new string with escape sequences converted to control characters.
	 * @see #convertEscapeSequences(String string)
	 */
	public static String convertEscapeSequences(String str) {
		StringBuilder builder = new StringBuilder();

		int inputLength = str.length();
		int index = 0;
		while (index < inputLength) {
			String subOfInput = (index + 2 <= inputLength) ? str.substring(index, index + 2)
					: str.substring(index, inputLength);
			Character escapeChar = escapeStringToControlMap.get(subOfInput);
			if (escapeChar != null) {
				builder.append(escapeChar);
				index += 2;
			}
			else if (handleEscapeSequence(str, "\\x", 2, index, builder)) {
				index += 4;
			}
			else if (handleEscapeSequence(str, "\\u", 4, index, builder)) {
				index += 6;
			}
			else if (handleEscapeSequence(str, "\\U", 8, index, builder)) {
				index += 10;
			}
			else {
				builder.append(str.charAt(index));
				index++;
			}
		}
		return builder.toString();
	}

	/**
	 * Attempt to handle character escape sequence. Note that only a single Java character will be
	 * produced which limits the range of valid character value.
	 *
	 * @param string string containing escape sequences
	 * @param escapeSequence escape sequence (e.g., "\\u")
	 * @param hexLength number of hex digits expected (1 to 8)
	 * @param index current position within string
	 * @param builder the builder into which the results will be added
	 *
	 * @return true if escape sequence processed and added a single character to the builder.
	 */
	private static boolean handleEscapeSequence(String string, String escapeSequence, int hexLength,
			int index, StringBuilder builder) {
		int inputLength = string.length();
		int hexStart = index + escapeSequence.length();
		int hexEnd = hexStart + hexLength;
		if (hexEnd <= inputLength && escapeSequence.equals(string.substring(index, hexStart))) {
			String hexStr = string.substring(hexStart, hexEnd);
			int hexMask = -1 >>> (4 * (8 - hexLength));
			try {
				int val = Integer.parseInt(hexStr, 16) & hexMask;
				if (val >= 0 && val <= Character.MAX_VALUE) {
					builder.append((char) val);
					return true;
				}
			}
			catch (NumberFormatException e) {
				// ignore
			}
		}
		return false;
	}

	/**
	 * Replaces known control characters in a string to corresponding escape sequences. For example
	 * a string containing a line feed character would be converted to backslash character followed
	 * by an 'n' character. One use for this is to display strings in a manner to easily see the
	 * embedded control characters.
	 *
	 * The string that contains 'a','b','c',0x0a,'d', 0x01, 'e' would become 'a','b','c', '\', 'n',
	 * 'd', 0x01, 'e'
	 *
	 * @param str The string to convert control characters to escape sequences
	 * @return a new string with all the control characters converted to escape sequences.
	 */
	public static String convertControlCharsToEscapeSequences(String str) {
		StringBuilder builder = new StringBuilder();
		int strLength = str.length();
		int charCount = 1;
		for (int i = 0; i < strLength; i += charCount) {
			int codePoint = str.codePointAt(i);
			charCount = Character.charCount(codePoint);
			if (charCount == 1 && controlToEscapeStringMap.containsKey((char) codePoint)) {
				builder.append(controlToEscapeStringMap.get((char) codePoint));
			}
			else {
				builder.appendCodePoint(codePoint);
			}
		}
		return builder.toString();
	}

	/**
	 * Maps known control characters to corresponding escape sequences. For example a line feed
	 * character would be converted to backslash '\\' character followed by an 'n' character. One
	 * use for this is to display strings in a manner to easily see the embedded control characters.
	 *
	 * @param codePoint The character to convert to escape sequence string
	 * @return a new string with equivalent to escape sequence, or original character (as a string)
	 *         if not in the control character mapping.
	 */
	public static String convertCodePointToEscapeSequence(int codePoint) {
		int charCount = Character.charCount(codePoint);
		String escaped;
		if (charCount == 1 && (escaped = controlToEscapeStringMap.get((char) codePoint)) != null) {
			return escaped;
		}
		return new String(new int[] { codePoint }, 0, 1);
	}

	/**
	 * About the worst way to wrap lines ever
	 */
	public static class LineWrapper {
		enum Mode {
			INIT, WORD, SPACE;
		}

		private final int width;
		private StringBuffer result = new StringBuffer();
		private int len = 0;

		public LineWrapper(int width) {
			this.width = width;
		}

		public LineWrapper append(CharSequence cs) {
			Mode mode = Mode.INIT;
			int b = 0;
			for (int f = 0; f < cs.length(); f++) {
				char c = cs.charAt(f);
				if (c == '\n') {
					if (mode == Mode.SPACE) {
						appendSpace(cs.subSequence(b, f));
					}
					else if (mode == Mode.WORD) {
						appendWord(cs.subSequence(b, f));
					}
					mode = Mode.INIT;
					appendLinesep();
					b = f + 1;
				}
				else if (Character.isWhitespace(c)) {
					if (mode == Mode.WORD) {
						appendWord(cs.subSequence(b, f));
						b = f;
					}
					mode = Mode.SPACE;
				}
				else {
					if (mode == Mode.SPACE) {
						appendSpace(cs.subSequence(b, f));
						b = f;
					}
					mode = Mode.WORD;
				}
			}
			if (mode == Mode.WORD) {
				appendWord(cs.subSequence(b, cs.length()));
			}
			else if (mode == Mode.SPACE) {
				appendSpace(cs.subSequence(b, cs.length()));
			}
			return this;
		}

		private void appendWord(CharSequence word) {
			len += word.length();
			result.append(word);
		}

		private void appendSpace(CharSequence space) {
			if (len > width) {
				appendLinesep();
				len += space.length() - 1;
				result.append(space.subSequence(1, space.length()));
			}
			else {
				len += space.length();
				result.append(space);
			}
		}

		private void appendLinesep() {
			result.append("\n");
			len = 0;
		}

		public String finish() {
			return result.toString();
		}
	}

	/**
	 * Wrap the given string at whitespace to best fit within the given line width
	 * 
	 * <p>
	 * If it is not possible to fit a word in the given width, it will be put on a line by itself,
	 * and that line will be allowed to exceed the given width.
	 * 
	 * @param str the string to wrap
	 * @param width the max width of each line, unless a single word exceeds it
	 * @return
	 */
	public static String wrapToWidth(String str, int width) {
		return new LineWrapper(width).append(str).finish();
	}
}
