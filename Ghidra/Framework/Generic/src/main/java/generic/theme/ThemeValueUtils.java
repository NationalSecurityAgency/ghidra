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
package generic.theme;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

public class ThemeValueUtils {
	/**
	 * Parses the given source string into a list of strings, one for each group. The startChar
	 * and endChar defined the group characters. So, for example, "(ab (cd))(ef)((gh))" would 
	 * result in a list with the following values: "ab (cd)", "ef", and "(gh)"
	 * @param source the source string to parse into groups
	 * @param startChar the character that defines the start of a group
	 * @param endChar the character that defines then end of a group
	 * @return a List of strings, one for each consecutive group contained in the string
	 * @throws ParseException if the groupings are not balanced or missing altogether
	 */
	public static List<String> parseGroupings(String source, char startChar, char endChar)
			throws ParseException {
		List<String> results = new ArrayList<>();
		int index = 0;

		while (index < source.length()) {
			int groupStart = findNextNonWhiteSpaceChar(source, index);
			if (groupStart < 0) {
				break;
			}
			if (source.charAt(groupStart) != startChar) {
				throw new ParseException("Error parsing groupings for " + source, index);
			}
			int groupEnd = findMatchingEnd(source, groupStart + 1, startChar, endChar);
			if (groupEnd < 0) {
				throw new ParseException("Error parsing groupings for " + source, index);
			}
			results.add(source.substring(groupStart + 1, groupEnd));
			index = groupEnd + 1;
		}
		return results;
	}

	private static int findMatchingEnd(String source, int index, char startChar, char endChar) {
		int level = 0;
		while (index < source.length()) {
			char c = source.charAt(index);
			if (c == startChar) {
				level++;
			}
			else if (c == endChar) {
				if (level == 0) {
					return index;
				}
				level--;
			}
			index++;
		}
		return -1;
	}

	private static int findNextNonWhiteSpaceChar(String source, int index) {
		while (index < source.length()) {
			if (!Character.isWhitespace(source.charAt(index))) {
				return index;
			}
			index++;
		}
		return -1;
	}

}
