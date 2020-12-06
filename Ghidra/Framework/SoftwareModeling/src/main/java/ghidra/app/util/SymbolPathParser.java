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
package ghidra.app.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import ghidra.program.model.symbol.Namespace;

/**
 * A parser for breaking down namespaces in the presence of complicating factors such
 *  as templates.
 * <P>
 * For example, if a SymbolPath is constructed with "foo&lt;int, blah::hah&gt;::bar::baz",
 * then "baz" is the name of a symbol in the "bar" namespace, which is in the
 * "foo&lt;int, blah::hah&gt;" namespace.
 */
public class SymbolPathParser {

	/**
	 * Parses a String pathname into its constituent namespace and name components.
	 * The list does not contain the global namespace, which is implied, but then
	 * has each more deeply nested namespace contained in order in the list, followed
	 * by the trailing name.
	 * @param name The input String to be parsed.
	 * @return {@literal List<String>} containing the sequence of namespaces and trailing name.
	 */
	public static List<String> parse(String name) {
		return parse(name, true);
	}

	/**
	 * Parses a String pathname into its constituent namespace and name components.
	 * The list does not contain the global namespace, which is implied, but then
	 * has each more deeply nested namespace contained in order in the list, followed
	 * by the trailing name.
	 * @param name The input String to be parsed.
	 * @param ignoreLeaderParens true signals to ignore any string that starts with a '(' char.  
	 *        This is useful to work around some problem characters.
	 * @return {@literal List<String>} containing the sequence of namespaces and trailing name.
	 */
	public static List<String> parse(String name, boolean ignoreLeaderParens) {
		if (StringUtils.isBlank(name)) {
			throw new IllegalArgumentException(
				"Symbol list must contain at least one symbol name!");
		}

		if (skipParsing(name, ignoreLeaderParens)) {
			List<String> list = new ArrayList<>();
			list.add(name);
			return list;
		}
		return naiveParse(name);
	}

	private static boolean skipParsing(String name, boolean ignoreLeaderParens) {

		//	if (name.indexOf(Namespace.DELIMITER) == -1) {
		// following is temporary kludge due to struct (blah).  TODO: figure/fix
		// This particular test for starting with the open parenthesis is to work around a type
		// seen in "Rust."
		if (ignoreLeaderParens && name.startsWith("(")) {
			return true;
		}

		return !name.contains(Namespace.DELIMITER);
	}

	/**
	 * Naive parsing that assumes evenly matched angle brackets (templates) with no operator
	 * overloading that contains these and no other rule breakers.
	 * @param name The input String to be parsed.
	 * @return List<String> containing the sequence of namespaces and trailing name.
	 */
	private static List<String> naiveParse(String name) {
		// Only break on namespace delimiters that are found at templateLevel == 0.
		List<String> list = new ArrayList<>();
		int templateLevel = 0;
		int parenthesesLevel = 0;
		int startIndex = 0;
		for (int i = 0; i < name.length(); ++i) {
			if ((name.charAt(i) == ':') && (i != name.length() - 1) &&
				(name.charAt(i + 1) == ':')) {
				if ((templateLevel == 0) && (parenthesesLevel == 0)) {
					int endIndex = i; // could be 0 if i == 0.
					if (endIndex > startIndex) {
						list.add(name.substring(startIndex, endIndex));
						startIndex = i + 2;
						i++; // Only increment one, because the loop also has an increment.
					}
				}
			}
			else if (name.charAt(i) == '<') {
				++templateLevel;
			}
			else if (name.charAt(i) == '>') {
				--templateLevel;
			}
			else if (name.charAt(i) == '(') {
				++parenthesesLevel;
			}
			else if (name.charAt(i) == ')') {
				--parenthesesLevel;
			}
		}
		if ((templateLevel != 0) || (parenthesesLevel != 0)) {
			// Revert to no checking template level
			startIndex = 0;
			list = new ArrayList<>();
			for (int i = 0; i < name.length(); ++i) {
				if ((name.charAt(i) == ':') && (i != name.length() - 1) &&
					name.charAt(i + 1) == ':') {
					int endIndex = i; // could be 0 if i == 0.
					if (endIndex > startIndex) {
						list.add(name.substring(startIndex, endIndex));
						startIndex = i + 2;
						i++; // Only increment one, because the loop also has an increment.
					}
				}
			}
		}
		list.add(name.substring(startIndex, name.length()));

		return list;
	}

	// TODO: in progress.
//	/**
//	 * More complicated parsing that takes into account:
//	 * <LI> overloaded operators that use angle brackets
//	 * <LI> templated overloaded operators that use angle brackets
//	 * <LI> mismatched angle brackets (MSFT specialness)
//	 * <LI> MSFT interface namespaces (square brackets out of bounds of namespace delimiter)
//	 * @param name The input String to be parsed.
//	 * @return List<String> containing the sequence of namespaces and trailing name.
//	 */
//	private static List<String> detailedParse(String name) {
//		List<String> list = new ArrayList<>();
//		return list;
//	}

}
