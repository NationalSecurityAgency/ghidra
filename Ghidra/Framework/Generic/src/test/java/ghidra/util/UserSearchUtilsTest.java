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

import static org.junit.Assert.*;

import java.util.regex.Pattern;

import org.junit.Test;

public class UserSearchUtilsTest {

	private static final int CASE_SENSITIVE = UserSearchUtils.CASE_SENSITIVE;

	@Test
	public void testCreateContainsPatternNoWildCards() {
		Pattern pattern = UserSearchUtils.createContainsPattern("bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("bobbob").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateContainsPatternNoWildCardsCaseSensitive() {
		Pattern pattern = UserSearchUtils.createContainsPattern("Bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("bobbob").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());

		assertTrue(pattern.matcher("Bob").matches());
		assertTrue(pattern.matcher("xBob").matches());
		assertTrue(pattern.matcher("Bobx").matches());
		assertTrue(pattern.matcher("BobBob").matches());
		assertTrue(pattern.matcher("xxBobxx").matches());
	}

	@Test
	public void testContainsWithPatternWithOnlyWildCardCaseInsensitive() {
		Pattern pattern = UserSearchUtils.createContainsPattern("*", true, Pattern.CASE_INSENSITIVE);

		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testContainsWithPatternWithOnlyWildCardCaseSensitive() {
		// Note: case sensitivity should not matter
		Pattern pattern = UserSearchUtils.createContainsPattern("*", true, CASE_SENSITIVE);

		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}
	@Test
	public void testCreateContainsPatternWithSingleCharhWildCard() {
		Pattern pattern = UserSearchUtils.createContainsPattern("b?b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateContainsPatternWildCard() {
		Pattern pattern = UserSearchUtils.createContainsPattern("b*b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateContainsPatternWildCardAtStart() {
		Pattern pattern = UserSearchUtils.createContainsPattern("*bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateContainsPatternWildCardAtEnd() {
		Pattern pattern = UserSearchUtils.createContainsPattern("*bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
    public void testStartsPatternNoWildCards() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
    public void testStartsPatternNoWildCardsCaseSensitive() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("boB", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());

		assertTrue(pattern.matcher("boB").matches());
		assertTrue(pattern.matcher("boBx").matches());
	}

	@Test
	public void testCreateStartsWithPatternWithOnlyWildCardCaseInsensitive() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("*", true, Pattern.CASE_INSENSITIVE);

		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}
	@Test
	public void testCreateStartsWithPatternWithOnlyWildCardCaseSensitive() {
		// Note: case sensitivity should not matter
		Pattern pattern = UserSearchUtils.createStartsWithPattern("*", true, CASE_SENSITIVE);

		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}
	
	@Test
	public void testCreateStartsWithPatternWithSingleCharhWildCard() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("b?b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateStartsWithPatternWildCard() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("b*b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("boasdfbx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateStartsWithPatternWildCardAtStart() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("*bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreateStartsWithPatternWildCardAtEnd() {
		Pattern pattern = UserSearchUtils.createStartsWithPattern("bob*", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreatePatternNoWildCards() {
		Pattern pattern = UserSearchUtils.createPattern("bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreatePatternNoWildCardsCaseSensitive() {
		Pattern pattern = UserSearchUtils.createPattern("bOb", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());

		assertTrue(pattern.matcher("bOb").matches());
	}

	@Test
	public void testCreatePatternSingleWildCard_MatchAll() {
		Pattern pattern = UserSearchUtils.createPattern("*", true, CASE_SENSITIVE);

		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreatePatternWithSingleCharhWildCard() {
		Pattern pattern = UserSearchUtils.createPattern("b?b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boxb").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreatePatternWildCard() {
		Pattern pattern = UserSearchUtils.createPattern("b*b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("boasdfbx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreatePatternWithSingleWildcard() {
		Pattern pattern = UserSearchUtils.createPattern("*", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("").matches());
		assertTrue(pattern.matcher(" ").matches());
		assertTrue(pattern.matcher("b").matches());
		assertTrue(pattern.matcher("bb").matches());
		assertTrue(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("xxbob").matches());
	}

	@Test
	public void testCreatePatternWildCardAtStart() {
		Pattern pattern = UserSearchUtils.createPattern("*bob", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
		assertFalse(pattern.matcher("bOb").matches());

		assertTrue(pattern.matcher("bob").matches());
		assertTrue(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("xxbob").matches());
	}

	@Test
	public void testCreatePatternWildCardAtEnd() {
		Pattern pattern = UserSearchUtils.createPattern("bob*", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("boob").matches());
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertTrue(pattern.matcher("bobx").matches());
		assertTrue(pattern.matcher("bobxx").matches());
		assertFalse(pattern.matcher("xxbobxx").matches());
	}

	@Test
	public void testCreatePatternWildCardAsLiteral_Star() {
		Pattern pattern = UserSearchUtils.createPattern("b*b", false, Pattern.CASE_INSENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());

		assertTrue(pattern.matcher("b*b").matches());
		assertTrue(pattern.matcher("B*b").matches());
	}

	@Test
	public void testCreatePatternWildCardAsLiteral_Question() {
		Pattern pattern = UserSearchUtils.createPattern("b?b", false, Pattern.CASE_INSENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());

		assertTrue(pattern.matcher("b?b").matches());
		assertTrue(pattern.matcher("B?b").matches());
	}

	@Test
	public void testCreatePatternWildCaseSensitive() {
		Pattern pattern = UserSearchUtils.createPattern("bO?b", true, CASE_SENSITIVE);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("bobx").matches());
		assertFalse(pattern.matcher("BOb").matches());

		assertTrue(pattern.matcher("bObb").matches());
	}

	@Test
	public void testCreateSearchPatternCaseSenstive() {
		Pattern pattern = UserSearchUtils.createSearchPattern("b?b?", true);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());
		assertFalse(pattern.matcher("boBx").matches());

		assertTrue(pattern.matcher("bobx").matches());
	}

	@Test
	public void testCreateSearchPatternCaseInsenstive() {
		Pattern pattern = UserSearchUtils.createSearchPattern("b?b?", false);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bb").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("xbob").matches());

		assertTrue(pattern.matcher("boBx").matches());
		assertTrue(pattern.matcher("bobx").matches());
	}

	@Test
	public void testCreateSearchPatternCaseInsenstive_ContainsNonGlobbingRegexChar() {
		// note: this was a bug I had to fix

		Pattern pattern = UserSearchUtils.createSearchPattern("Bob[*", false);

		assertFalse(pattern.matcher("b").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("bobb[").matches());

		assertTrue(pattern.matcher("bob[").matches());
		assertTrue(pattern.matcher("Bob[").matches());
		assertTrue(pattern.matcher("Bob[2]").matches());
	}

	@Test
	public void testCreateLiteralExactMatchPattern() {
		//
		// A literal pattern should only match case sensitive and no globbing expansion
		//

		Pattern pattern = UserSearchUtils.createLiteralSearchPattern("bob");
		assertTrue(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("bbb").matches());
		assertFalse(pattern.matcher("Bob").matches());

		pattern = UserSearchUtils.createLiteralSearchPattern("b*b");
		assertTrue(pattern.matcher("b*b").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("Bob").matches());

		pattern = UserSearchUtils.createLiteralSearchPattern("b?b");
		assertTrue(pattern.matcher("b?b").matches());
		assertFalse(pattern.matcher("bob").matches());
		assertFalse(pattern.matcher("Bob").matches());
	}

	@Test
	public void testEscapeAllRegexCharacters() {
		// RegEx Special Chars: ^.$()[]+&{}*?
		String escaped = UserSearchUtils.escapeAllRegexCharacters("start^.$()[]+&{}*?end");

		assertEquals("\\Qstart^.$()[]+&{}*?end\\E", escaped);
	}

	@Test
	public void testEscapeSomeRegexCharacters() {
		// RegEx Special Chars: ^.$()[]+&{}*?
		char[] toIgnore = { '(', ')' };
		String escaped = UserSearchUtils.escapeSomeRegexCharacters("start^.$()[]+&{}*?end", toIgnore);

		assertEquals("start\\^\\.\\$()\\[\\]\\+\\&\\{\\}\\*\\?end", escaped);

		toIgnore = new char[] { '^', '*', '?' };
		escaped = UserSearchUtils.escapeSomeRegexCharacters("start^.$()[]+&{}*?end", toIgnore);

		assertEquals("start^\\.\\$\\(\\)\\[\\]\\+\\&\\{\\}*?end", escaped);
	}
}
