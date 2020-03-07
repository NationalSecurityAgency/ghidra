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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class converts user inputted strings and creates {@link Pattern}s from them
 * that can be used to create {@link Matcher} objects.  Some methods create patterns that
 * are meant to be used with {@link Matcher#matches()}, while others create patterns
 * meant to be used with {@link Matcher#find()}.  Please see each method javadoc for clarification.
 * <p>
 * Note: methods in the class will escape regex characters, which means that normal regex
 * queries will not work, but will be instead interpreted as literal string searches.
 */
public class UserSearchUtils {

	/**
	 * Wildcard string for matching 0 or more characters.
	 */
	public final static String STAR = "*";

	/**
	 * Characters that we handle similarly to command-line globbing expansion characters.
	 */
	private final static char[] GLOB_CHARACTERS = { '*', '?' };

	/**
	 * A pattern that will find all '\' chars that are not followed by '*', '?'
	 * or another '\'
	 */
	public final static Pattern NON_GLOB_BACKSLASH_PATTERN = Pattern.compile("\\\\(?![\\*\\?])");

	/**
	 * A pattern that will find all '*' chars that are not preceded by a '\'
	 */
	private final static Pattern STAR_PATTERN = Pattern.compile("(?<!\\\\)\\*");

	/**
	 * A pattern that will find all '?' chars that are not preceded by a '\'
	 */
	private final static Pattern QUESTION_PATTERN = Pattern.compile("(?<!\\\\)\\?");

	static final int CASE_SENSITIVE = 0;

//==================================================================================================
// Matcher.matches() Methods
//==================================================================================================

	/**
	 * <b>
	 * Note: this is the default model of how to let users search for things in Ghidra.  This
	 * is NOT a tool to allow regex searching, but instead allows users to perform searches while
	 * using familiar globbing characters such as '*' and '?'.
	 * </b>
	 * <p>
	 * This method can be used with {@link Matcher#matches()} or {@link Matcher#find()}.
	 * <p>
	 * Create a regular expression from the given input. <b>Note:</b> the regular expression
	 * created by this method is not a pure regular expression.  More specifically, many
	 * regular expression characters passed to this method will be escaped
	 * (see {@link #escapeAllRegexCharacters(String)}.
	 * <p>
	 * Also, globbing characters
	 * <b><u>will</u></b> be changed from a regular expression meaning to a
	 * command-line style glob meaning.
	 *
	 * <p>
	 * <b>Note: </b>This method <b>will</b> escape regular expression
	 * characters, such as:
	 * <ul>
	 * <li>?
	 * <li>.
	 * <li>$
	 * <li>...and many others
	 * </ul>
	 * Thus, this method is not meant to <b>accept</b> regular expressions, but
	 * rather <b>generates</b> regular expressions.
	 *
	 * @param input
	 *            string to create a regular expression from
	 * @param caseSensitive
	 *            true if the regular expression is case sensitive
	 * @return Pattern the compiled regular expression
	 * @throws java.util.regex.PatternSyntaxException
	 *             if the input could be compiled
	 */
	public static Pattern createSearchPattern(String input, boolean caseSensitive) {

		int options = 0;
		if (!caseSensitive) {
			options |= Pattern.CASE_INSENSITIVE;
		}

		Pattern p = createPattern(input, true, options);
		return p;
	}

	/**
	 * Generate a compiled representation of a regular expression, ignoring regex special
	 * characters  . The resulting pattern will match the literal text string.
	 * <p>
	 * This method can be used with {@link Matcher#matches()} or {@link Matcher#find()}.
	 * <p>
	 * This method will <b><u>not</u></b> turn globbing characters into regex characters.
	 * If you need that, then see the other methods of this class.
	 *
	 * @param text
	 *            search string
	 * @return Pattern the compiled regular expression
	 * @throws java.util.regex.PatternSyntaxException
	 *             if the input could be compiled
	 */
	public static Pattern createLiteralSearchPattern(String text) {
		Pattern p = createPattern(text, false, CASE_SENSITIVE);
		return p;
	}

	/**
	 * Creates a regular expression Pattern that will <b>match</b>
	 * all strings that <b>start with</b> the given input string.
	 * <p>
	 * This method should only be used with {@link Matcher#matches()}.
	 * <p>
	 * The returned regular expression Pattern should be used
	 * with the "matches" method on a Matcher.  (As opposed to "find").
	 *
	 * @param input
	 * 			the string that you want to your matched strings to start with.
	 * @param allowGlobbing
	 *          if true, globing characters (* and ?) will converted to regex wildcard patterns;
	 *          otherwise, they will be escaped and searched as literals.
	 * @param options
	 * 			any {@link Pattern} options desired.  For example, you can pass
	 * 			{@link Pattern#CASE_INSENSITIVE} to get case insensitivity.
	 *
	 * @return a regular expression Pattern that will <b>match</b>
	 * 		   	all strings that start with the given input string.
	 */
	public static Pattern createStartsWithPattern(String input, boolean allowGlobbing,
			int options) {

		Pattern wildCardPattern = createSingleStarPattern(input, allowGlobbing, options);
		if (wildCardPattern != null) {
			return wildCardPattern;
		}

		String converted = convertUserInputToRegex(input, allowGlobbing);
		Pattern p = Pattern.compile(converted + ".*", options);
		return p;
	}

	/**
	 * Creates a regular expression Pattern that will <b>match</b>
	 * all strings that <b>end with</b> the given input string.
	 * <p>
	 * This method should only be used with {@link Matcher#matches()}.
	 * <p>
	 * The returned regular expression Pattern should be used
	 * with the "matches" method on a Matcher.  (As opposed to "find").
	 *
	 * @param input
	 * 			the string that you want to your matched strings to end with.
	 * @param allowGlobbing
	 *          if true, globing characters (* and ?) will converted to regex wildcard patterns;
	 *          otherwise, they will be escaped and searched as literals.
	 * @param options
	 * 			any {@link Pattern} options desired.  For example, you can pass
	 * 			{@link Pattern#CASE_INSENSITIVE} to get case insensitivity.
	 *
	 * @return a regular expression Pattern that will <b>match</b>
	 * 		   	all strings that end with the given input string.
	 */
	public static Pattern createEndsWithPattern(String input, boolean allowGlobbing, int options) {

		Pattern wildCardPattern = createSingleStarPattern(input, allowGlobbing, options);
		if (wildCardPattern != null) {
			return wildCardPattern;
		}

		String converted = convertUserInputToRegex(input, allowGlobbing);
		Pattern p = Pattern.compile(".*" + converted, options);
		return p;
	}

	/**
	 * Creates a regular expression Pattern that will <b>match</b>
	 * all strings that <b>contain</b> the given input string.
	 * <p>
	 * This method should only be used with {@link Matcher#matches()}.
	 *
	 * @param input
	 * 			the string that you want to your matched strings to contain.
	 * @param allowGlobbing
	 *          if true, globing characters (* and ?) will converted to regex wildcard patterns;
	 *          otherwise, they will be escaped and searched as literals.
	 * @param options
	 * 			any {@link Pattern} options desired.  For example, you can pass
	 * 			{@link Pattern#CASE_INSENSITIVE} to get case insensitivity.
	 * @return a regular expression Pattern that will <b>match</b>
	 * all strings that contain the given input string.
	 */
	public static Pattern createContainsPattern(String input, boolean allowGlobbing, int options) {

		Pattern wildCardPattern = createSingleStarPattern(input, allowGlobbing, options);
		if (wildCardPattern != null) {
			return wildCardPattern;
		}

		String converted = convertUserInputToRegex(input, allowGlobbing);
		Pattern p = Pattern.compile(".*" + converted + ".*", options);
		return p;
	}

	/**
	 * Creates a regular expression Pattern that will match all strings that
	 * <b>match exactly</b> the given input string.
	 * <p>
	 * This method can be used with {@link Matcher#matches()} or {@link Matcher#find()}.
	 * <p>
	 *
	 * @param input
	 * 			the string that you want to your matched strings to exactly match.
	 * @param allowGlobbing
	 *          if true, globing characters (* and ?) will converted to regex wildcard patterns;
	 *          otherwise, they will be escaped and searched as literals.
	 * @param options
	 * 			any {@link Pattern} options desired.  For example, you can pass
	 * 			{@link Pattern#CASE_INSENSITIVE} to get case insensitivity.
	 *
	 * @return a regular expression Pattern that will <b>match</b>
	 * 			all strings that exactly match with the given input string.
	 */
	public static Pattern createPattern(String input, boolean allowGlobbing, int options) {

		Pattern wildCardPattern = createSingleStarPattern(input, allowGlobbing, options);
		if (wildCardPattern != null) {
			return wildCardPattern;
		}

		String converted = convertUserInputToRegex(input, allowGlobbing);
		Pattern p = Pattern.compile(converted, options);
		return p;
	}

	/**
	 * Creates a regular expression that can be used to create a Pattern that will <b>match</b>
	 * all strings that match the given input string.
	 * <p>
	 * This method can be used with {@link Matcher#matches()} or {@link Matcher#find()}.
	 * <p>
	 *
	 * @param input
	 * 			the string that you want to your matched strings to exactly match.
	 * @param allowGlobbing
	 *          if true, globing characters (* and ?) will converted to regex wildcard patterns;
	 *          otherwise, they will be escaped and searched as literals.
	 *
	 * @return a regular expression Pattern String that will <b>match</b>
	 * 			all strings that exactly match with the given input string.
	 */
	public static String createPatternString(String input, boolean allowGlobbing) {

		String wildCardPatternString = createSingleStarPatternString(input, allowGlobbing);
		if (wildCardPatternString != null) {
			return wildCardPatternString;
		}

		String converted = convertUserInputToRegex(input, allowGlobbing);
		return converted;
	}

	private static Pattern createSingleStarPattern(String input, boolean allowGlobbing,
			int options) {

		if (allowGlobbing && input.equals(STAR)) {
			return Pattern.compile(".+", options);
		}
		return null;
	}

	private static String createSingleStarPatternString(String input, boolean allowGlobbing) {

		if (allowGlobbing && input.equals(STAR)) {
			return ".+";
		}
		return null;
	}

	/**
	 * Escapes regex characters, optionally turning globbing characters into valid regex syntax.
	 */
	private static String convertUserInputToRegex(String input, boolean allowGlobbing) {

		// Note: Order is important! (due to how escape characters added and checked)
		String escaped = escapeEscapeCharacters(input);

		if (allowGlobbing) {
			escaped = escapeSomeRegexCharacters(escaped, GLOB_CHARACTERS);
			escaped = convertGlobbingCharactersToRegex(escaped);
		}
		else {
			escaped = escapeAllRegexCharacters(escaped);
		}

		return escaped;
	}

//==================================================================================================
// Escaping/Converting Methods
//==================================================================================================

	/**
	 * Will change globbing characters to work as expected in Ghidra, unless the
	 * special characters are escaped with a backslash.
	 *
	 * @param input
	 *            The string containing potential globbing characters.
	 * @return The fixed string
	 */
	private static String convertGlobbingCharactersToRegex(String input) {
		// NOTE: order is important!

		// replace all unescaped '?' chars
		Matcher questionMatcher = QUESTION_PATTERN.matcher(input);
		String questionReplaced = questionMatcher.replaceAll(".");

		// replace all unescaped '*' chars
		Matcher starMatcher = STAR_PATTERN.matcher(questionReplaced);

		// *? is a Reluctant Quantifier, matching zero or more.  '*' is the quantifier, '?' makes
		// it reluctant
		String starReplaced = starMatcher.replaceAll(".*?");
		return starReplaced;
	}

	/**
	 * Replaces all escape characters ('\') by escaping that character ('\\').
	 * <p>
	 * Note: this method will not escape characters that are escaping a globbing character
	 * (see {@link #NON_GLOB_BACKSLASH_PATTERN}.
	 *
	 * @param input
	 *            The string containing potential escape characters.
	 * @return The fixed string
	 */
	private static String escapeEscapeCharacters(String input) {
		// replace all '\' chars that are not followed by *known* special chars
		Matcher backslashMatcher = NON_GLOB_BACKSLASH_PATTERN.matcher(input);
		return backslashMatcher.replaceAll("\\\\\\\\");
	}

	/**
	 * Escapes all special regex characters so that they are treated as literal characters
	 * by the regex engine.
	 *
	 * @param input
	 *            The input string to be escaped
	 * @return A new regex string with special characters escaped.
	 */
	// note: 'package' for testing
	static String escapeAllRegexCharacters(String input) {
		return Pattern.quote(input);
	}

	/**
	 * Escapes all regex characters with the '\' character, except for those in the given
	 * exclusion array.
	 *
	 * @param input
	 *            The input string to be escaped
	 * @return A new regex string with special characters escaped.
	 */
	// note: 'package' for testing
	static String escapeSomeRegexCharacters(String input, char[] doNotEscape) {
		StringBuffer buffy = new StringBuffer();
		for (int i = 0; i < input.length(); i++) {
			char c = input.charAt(i);

			if (contains(doNotEscape, c)) {
				// a bit inefficient, but the array should always be short
				buffy.append(c);
				continue;
			}

			switch (c) {
				case '^':
					buffy.append("\\^");
					break;
				case '.':
					buffy.append("\\.");
					break;
				case '$':
					buffy.append("\\$");
					break;
				case '(':
					buffy.append("\\(");
					break;
				case ')':
					buffy.append("\\)");
					break;
				case '[':
					buffy.append("\\[");
					break;
				case ']':
					buffy.append("\\]");
					break;
				case '+':
					buffy.append("\\+");
					break;
				case '&':
					buffy.append("\\&");
					break;
				case '{':
					buffy.append("\\{");
					break;
				case '}':
					buffy.append("\\}");
					break;
				case '*':
					buffy.append("\\*");
					break;
				case '?':
					buffy.append("\\?");
					break;
				case '|':
					buffy.append("\\|");
					break;
				default:
					buffy.append(c);
					break;
			}
		}
		return buffy.toString();
	}

	private static boolean contains(char[] array, char c) {
		for (char next : array) {
			if (next == c) {
				return true;
			}
		}
		return false;
	}

}
