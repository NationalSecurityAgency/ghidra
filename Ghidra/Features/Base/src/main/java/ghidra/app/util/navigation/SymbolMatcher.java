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
package ghidra.app.util.navigation;

import static ghidra.util.UserSearchUtils.*;

import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import ghidra.app.services.QueryData;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

/**
 * Class for matching symbol names with or without namespace paths and wildcards.
 */
public class SymbolMatcher {

	private String symbolName;
	private Pattern pattern;
	private boolean caseSensitive;
	private boolean isRelativePath;
	private boolean isPossibleMemoryBlockPattern;

	public SymbolMatcher(String queryString, boolean caseSensitive) {
		// assume users entering spaces is a mistake, so just remove them.
		queryString = queryString.replaceAll("\\s", "");

		this.caseSensitive = caseSensitive;
		this.isRelativePath = !queryString.startsWith(Namespace.DELIMITER);
		this.symbolName = getSymbolName(queryString);
		this.pattern = createPattern(queryString);
		this.isPossibleMemoryBlockPattern = checkIfPossibleMemoryBlockPattern(queryString);
	}

	private boolean checkIfPossibleMemoryBlockPattern(String queryString) {
		// A legacy feature is the ability to also be able to find a label in a particular memory
		// block using the same syntax as a symbol in a namespace. So something like 
		// "block::bob" would find the symbol "bob" (regardless of its namespace) if it were
		// in a memory block named "block". (Also, this only worked if there wasn't also a 
		// symbol in a namespace named "block"). Now that wildcards are supported in the namespace
		// specifications, this feature becomes even more confusing. To avoid this, the legacy
		// memory block feature will not support wildcards and probably should be removed 
		// at some point.

		int lastIndexOf = queryString.lastIndexOf(Namespace.DELIMITER);

		// if no delimiter exists or it starts with a delimiter, then it can't match a memory block
		if (lastIndexOf < 1) {
			return false;
		}
		String qualifierPart = queryString.substring(0, lastIndexOf);

		// if the qualifier is a multi part path, then it can't match a memory block
		if (qualifierPart.indexOf(Namespace.DELIMITER) >= 0) {
			return false;
		}

		// we don't support wildcard when matching against memory block names
		return !qualifierPart.contains("*") && !qualifierPart.contains("?");
	}

	private String getSymbolName(String queryString) {
		int index = queryString.lastIndexOf(Namespace.DELIMITER);
		if (index < 0) {
			return queryString;
		}
		return queryString.substring(index + Namespace.DELIMITER.length());
	}

	private Pattern createPattern(String userInput) {
		// We only support globbing characters in the query, any other regex characters need
		// to be escaped before we feed it to Java's regex Pattern class. But we need to do it
		// before we begin our substitutions as we will be adding some of those character into
		// the query string and we don't want those to be escaped.
		String s = escapeNonGlobbingRegexCharacters(userInput);
		s = replaceNamespaceDelimiters(s);
		s = removeExcessStars(s);
		s = convertNameGlobingToRegEx(s);
		s = convertPathGlobingToRegEx(s);
		s = convertRelativePathToRegEx(s);

		return Pattern.compile(s, createRegexOptions());
	}

	private String removeExcessStars(String s) {
		// There is never a reason to have 3 or more stars in the query. To avoid errors
		// creating a regex pattern, replace runs of 3 or more starts with two stars.
		// Later, the method that handles path globbing (**) chars, will either convert 
		// ** to a path matching expression, or if not valid in its location, to a
		// single * regex pattern.

		int start = s.indexOf("***");
		while (start >= 0) {
			int end = findFirstNonStar(s, start);
			s = s.substring(0, start + 2) + s.substring(end);
			start = s.indexOf("***");
		}
		return s;
	}

	private int findFirstNonStar(String query, int index) {
		while (index < query.length() && query.charAt(index) == '*') {
			index++;
		}
		return index;
	}

	private String replaceNamespaceDelimiters(String s) {
		// To make regex processing easier, replace any namespace delimiter ("::") with
		// a single character delimiter. We chose the space character because spaces can't 
		// exist in namespace names or symbol names.

		// also we remove any starting delimiters
		if (!isRelativePath) {
			s = s.substring(Namespace.DELIMITER.length());
		}

		return s.replaceAll(Namespace.DELIMITER, " ");
	}

	private String convertPathGlobingToRegEx(String s) {
		// Path globbing uses "**" to match any number of namespace elements in the symbol path
		// Valid examples of path globbing are "a::**::b", "**::a", or "a::**". 
		//
		// In order to handle the case where it matches zero path elements ("a::**::b" should
		// match "a::b"), we need to remove either the starting delimiter or the ending delimiter.
		// Also note that we are doing this replacement after all "::" have been replaced by spaces.

		// First replace " ** " with a regex pattern that matches either: a space followed by one
		// or more characters followed by another space; or a single space. The second case
		// handles when the ** matches zero elements such as "a::**::b" matches "a::b".
		s = s.replaceAll(" \\*\\* ", "( .* | )");

		// If the string starts with "** ", replace it with the regex pattern that matches either:
		// anything followed by a space; or nothing at all.
		s = s.replaceAll("^\\*\\* ", "(.* |)");

		// If the string ends with " **", replace it with the regex pattern that matches a space
		// followed by anything.
		s = s.replaceAll(" \\*\\*$", " .*");

		// Finally, any other "**", not handled is considered a mistake and is treated as if a
		// single start was entered, which is mapped to the regex expression any number of 
		// non-space characters.
		s = s.replaceAll("\\*\\*", "[^ ]*");
		return s;
	}

	private String convertNameGlobingToRegEx(String s) {
		// Name globing here refers to using the "*" or "?" globbing characters. However,
		// we only want them to apply to a single namespace or symbol name element. In other words
		// we can't use the reg-ex ".*" because it would match across delimiters which we don't 
		// want. The alternative is to use the "match everything but" construct where we use
		// "[^ ] which means match anything but spaces which is the delimiter we are using.
		//
		// There is a wrinkle for this substitution. We are replacing only single "*" characters,
		// but we need to avoid doubles (**) as those will be handled later by the path globbing.
		// To do this we used look ahead and look behind regex to only match single stars and not
		// double stars.

		// replace single "*" with the regex pattern that matches everything but spaces
		s = s.replaceAll("(?<!\\*)\\*(?!\\*)", "[^ ]*");

		// replace "?" with regex pattern that matches a single character
		s = s.replaceAll("\\?", ".");
		return s;
	}

	private String convertRelativePathToRegEx(String s) {
		// If the query is relative, add a "match anything" regex pattern to the front of the query
		// so that it will match any number of parent namespaces containing the specified 
		// symbol/namespace path.
		if (!s.isBlank() && isRelativePath) {
			s = ".*" + s;
		}
		return s;
	}

	public String getSymbolName() {
		return symbolName;
	}

	private int createRegexOptions() {
		if (!caseSensitive) {
			return Pattern.CASE_INSENSITIVE;
		}
		return 0;
	}

	/**
	 * Returns true if the symbol name part of the query string has no wildcards and is
	 * case sensitive.
	 * @return true if the query has no wildcards and is case sensitive.
	 */
	public boolean hasFullySpecifiedName() {
		return !QueryData.hasWildCards(symbolName) && caseSensitive;
	}

	/**
	 * Returns true if there are wildcards in the symbol name.
	 * @return true if there are wildcards in the symbol name
	 */
	public boolean hasWildCardsInSymbolName() {
		return QueryData.hasWildCards(symbolName);
	}

	/**
	 * Returns true if the given symbol matches the query specification for this matcher.
	 * @param symbol the symbol to test
	 * @return true if the given symbol matches the query specification for this matcher
	 */
	public boolean matches(Symbol symbol) {
		String path = createSymbolPathWithSpaces(symbol);
		if (pattern.matcher(path).matches()) {
			return true;
		}

		// legacy feature where the query may have specified a memory block name instead of a
		// namespace path.
		return checkMemoryBlockName(symbol);
	}

	private String createSymbolPathWithSpaces(Symbol symbol) {
		String[] path = symbol.getPath();
		return Arrays.stream(path).collect(Collectors.joining(" "));
	}

	private boolean checkMemoryBlockName(Symbol symbol) {
		if (!isPossibleMemoryBlockPattern) {
			return false;
		}
		Program program = symbol.getProgram();

		MemoryBlock block = program.getMemory().getBlock(symbol.getAddress());
		if (block != null) {
			String blockNamePath = block.getName() + " " + symbol.getName();
			return pattern.matcher(blockNamePath).matches();
		}
		return false;
	}
}
