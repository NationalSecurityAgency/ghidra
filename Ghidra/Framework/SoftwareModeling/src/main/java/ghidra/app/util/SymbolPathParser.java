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
 * A parser for breaking down namespaces in the presence of complicating factors such as templates.
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
			throw new IllegalArgumentException("Pathname cannot be empty!");
		}

		if (skipParsing(name, ignoreLeaderParens)) {
			List<String> list = new ArrayList<>();
			list.add(name);
			return list;
		}
		return naiveParse(name);
	}

	private static boolean skipParsing(String name, boolean ignoreLeaderParens) {

		// The check for starting with the open parenthesis is to work around a type seen in Rust
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

		List<String> list = naiveParseWithTemplates(name);
		if (!list.isEmpty()) {
			return list;
		}

		return naiveParseIgnoringTemplates(name);
	}

	private static List<String> naiveParseWithTemplates(String name) {
		List<String> list = new ArrayList<>();
		int templateLevel = 0;
		int parenLevel = 0;
		int start = 0;
		for (int i = 0; i < name.length(); ++i) {

			char c = name.charAt(i);
			if (isDelimiter(i, name)) {
				if (templateLevel == 0 && parenLevel == 0) {
					int end = i; // 0 if i == 0; leading ':' chars
					if (end > start) {
						list.add(name.substring(start, end));
						start = i + 2;
					}
				}
				i++; // increment one, since the loop has an increment
			}
			else if (c == '<') {
				++templateLevel;
			}
			else if (c == '>') {
				--templateLevel;
			}
			else if (c == '(') {
				++parenLevel;
			}
			else if (c == ')') {
				--parenLevel;
			}
		}

		boolean unbalanced = templateLevel != 0 || parenLevel != 0;
		String segment = name.substring(start, name.length());
		if (!unbalanced) {
			list.add(segment);
			return list;
		}

		if (isAngleOperator(segment)) {
			list.add(segment);
			return list;
		}

		return List.of();
	}

	private static List<String> naiveParseIgnoringTemplates(String name) {

		int start = 0;
		List<String> list = new ArrayList<>();
		for (int i = 0; i < name.length(); ++i) {
			if (isDelimiter(i, name)) {
				int end = i; // 0 if i == 0; leading ':' chars
				if (end > start) {
					list.add(name.substring(start, end));
					start = i + 2;
				}
				i++; // increment one, since the loop has an increment
			}
		}
		list.add(name.substring(start, name.length()));
		return list;
	}

	private static boolean isDelimiter(int i, String name) {
		if (i == name.length() - 1) {
			return false;
		}
		return name.charAt(i) == ':' && name.charAt(i + 1) == ':';
	}

	private static boolean isAngleOperator(String component) {
		//@formatter:off
		return switch (component) {
			case "operator<", 
			     "operator>", 
			     "operator<=", 
			     "operator>=", 
			     "operator<<", 
			     "operator>>", 
			     "operator<<=", 
			     "operator>>=", 
			     "operator<=>",
			     "operator->",
			     "operator->*" -> true;
			default -> false;
		};
		//@formatter:on
	}

}
