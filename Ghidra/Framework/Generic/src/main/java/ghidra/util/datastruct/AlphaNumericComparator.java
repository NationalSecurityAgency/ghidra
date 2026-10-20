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

import java.util.Comparator;

/**
 * A comparator to perform a natural sort for text and numbers.  Numbers in the text will compared
 * based on their parsed value, not their ASCII value. 
 */
public class AlphaNumericComparator implements Comparator<String> {

	private boolean caseSensitive;

	public AlphaNumericComparator() {
		this.caseSensitive = true;
	}

	public AlphaNumericComparator(boolean caseSensitive) {
		this.caseSensitive = caseSensitive;
	}

	@Override
	public int compare(String s1, String s2) {
		if (s1 == null || s2 == null) {
			return s1 == s2 ? 0 : (s1 == null ? -1 : 1);
		}

		int i = 0;
		int j = 0;
		int len1 = s1.length();
		int len2 = s2.length();

		// Core Pass: Compare semantic characters and mathematical numbers
		while (i < len1 && j < len2) {

			char c1 = s1.charAt(i);
			char c2 = s2.charAt(j);

			// Skip spaces dynamically					
			if (c1 == ' ') {
				i++;
				continue;
			}
			if (c2 == ' ') {
				j++;
				continue;
			}

			boolean isDigit1 = Character.isDigit(c1);
			boolean isDigit2 = Character.isDigit(c2);
			if (isDigit1 && isDigit2) {
				// Parse full numbers from the current position
				long val1 = parseNumber(s1, i);
				long val2 = parseNumber(s2, j);
				if (val1 != val2) {
					return Long.compare(val1, val2);
				}

				// Skip ahead past the digit sequences we just parsed
				i = skipDigits(s1, i);
				j = skipDigits(s2, j);
			}
			else {
				// Compare standard characters alphabetically
				int result = compare(c1, c2);
				if (result != 0) {
					return result;
				}

				i++;
				j++;
			}
		}

		// Clean up any remaining trailing spaces
		i = skipSpaces(s1, i);
		j = skipSpaces(s2, j);

		// Tie-breaker 1: Shorter structure wins (e.g., "file4" before "file 4")
		boolean ended1 = (i == len1);
		boolean ended2 = (j == len2);
		if (ended1 != ended2) {
			return ended1 ? -1 : 1;
		}

		// Both strings have the same length. If they have numbers, the numbers have been
		// parsed to be the same numeric value, but they may have leading zeros.
		// Prefer fewer leading zeros (e.g., "file4" before "file04").
		// A non-zero value means that both strings have digits that were compared.
		int lengthCompare = compareDigitLengths(s1, s2);
		if (lengthCompare != 0) {
			return lengthCompare;
		}

		// Default to a string compare
		return s1.compareTo(s2);
	}

	private int compare(char c1, char c2) {
		if (c1 == c2) {
			return 0;
		}

		if (!caseSensitive) {
			c1 = Character.toLowerCase(c1);
			c2 = Character.toLowerCase(c2);
		}

		return Character.compare(c1, c2);
	}

	private long parseNumber(String s, int i) {
		long value = 0;
		while (i < s.length()) {
			char c = s.charAt(i);
			if (!Character.isDigit(c)) {
				return value;
			}

			int intValue = (c - '0');
			value = value * 10 + intValue;
			i++;
		}
		return value;
	}

	private int skipDigits(String s, int i) {
		int len = s.length();
		while (i < len && Character.isDigit(s.charAt(i))) {
			i++;
		}
		return i;
	}

	private int skipSpaces(String s, int i) {
		int len = s.length();
		while (i < len && s.charAt(i) == ' ') {
			i++;
		}
		return i;
	}

	private int compareDigitLengths(String s1, String s2) {
		int len1 = s1.length();
		int len2 = s2.length();
		int i = 0;
		int j = 0;
		while (i < len1 && j < len2) {
			i = skipSpaces(s1, i);
			j = skipSpaces(s2, j);
			if (i >= len1 || j >= len2) {
				break;
			}

			if (Character.isDigit(s1.charAt(i)) && Character.isDigit(s2.charAt(j))) {
				int skip1 = skipDigits(s1, i) - i;
				int skip2 = skipDigits(s2, j) - j;
				if (skip1 != skip2) {
					return Integer.compare(skip1, skip2);
				}
				i += skip1;
				j += skip2;
			}
			else {
				i++;
				j++;
			}
		}
		return 0;
	}
}
