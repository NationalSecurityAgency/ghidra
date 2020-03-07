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

import org.junit.Test;

public class StringUtilitiesTest {

	@Test
	public void testCountOccurrencesOfCharacter() {
		int count = StringUtilities.countOccurrences("AxBxCxDxxX", 'x');
		assertEquals(5, count);
	}

	@Test
	public void testToQuotedString() {

		// single char
		assertEquals("'\\''", StringUtilities.toQuotedString(new byte[] { '\'' }));
		assertEquals("'\"'", StringUtilities.toQuotedString(new byte[] { '"' }));
		assertEquals("'\\n'", StringUtilities.toQuotedString(new byte[] { '\n' }));
		assertEquals("'\\t'", StringUtilities.toQuotedString(new byte[] { '\t' }));
		assertEquals("'a'", StringUtilities.toQuotedString(new byte[] { 'a' }));
		assertEquals("'\\x04'", StringUtilities.toQuotedString(new byte[] { (byte) '\u0004' }));
		assertEquals("'\\u0004'", StringUtilities.toQuotedString(new byte[] { 0, 4 }, 2));
		assertEquals("'\\U00000004'", StringUtilities.toQuotedString(new byte[] { 0, 0, 0, 4 }, 4));

		// string
		assertEquals("\"'a'\"", StringUtilities.toQuotedString("'a'".getBytes()));
		assertEquals("\"\\\"a\\\"\"", StringUtilities.toQuotedString("\"a\"".getBytes()));
		assertEquals("\"a\\nb\\tc\\x04d\"",
			StringUtilities.toQuotedString("a\nb\tc\u0004d".getBytes()));
	}

	@Test
	public void testConvertControlCharsToEscapeSequenes() throws Exception {
		assertEquals("'a'", StringUtilities.convertControlCharsToEscapeSequences("'a'"));
		assertEquals("\"a\"", StringUtilities.convertControlCharsToEscapeSequences("\"a\""));
		assertEquals("a\\nb\\tc\u0004d",
			StringUtilities.convertControlCharsToEscapeSequences("a\nb\tc\u0004d"));
		assertEquals("a\\nb\\tc\ud852\udf62d",
			StringUtilities.convertControlCharsToEscapeSequences("a\nb\tc\ud852\udf62d"));
	}

	@Test
	public void testConvertEscapeSequecesToControlChars() {
		assertEquals("'a'", StringUtilities.convertEscapeSequences("'a'"));
		assertEquals("\"a\"", StringUtilities.convertEscapeSequences("\"a\""));
		assertEquals("a\nb\tc\u0004d", StringUtilities.convertEscapeSequences("a\\nb\\tc\\x04d"));
		assertEquals("a\nb\tc\u0004d", StringUtilities.convertEscapeSequences("a\\nb\\tc\\u0004d"));
		assertEquals("a\nb\tc\u0004d",
			StringUtilities.convertEscapeSequences("a\\nb\\tc\\U00000004d"));
	}

	@Test
	public void testEndsWithIgnoresCase() {
		String bob = "bob";
		String endsWithBob = "endsWithBob";

		assertTrue(StringUtilities.endsWithIgnoreCase(endsWithBob, bob));

		String endsWithBobUpperCase = "endsWithBOB";
		assertTrue(StringUtilities.endsWithIgnoreCase(endsWithBobUpperCase, bob));

		String startsWithBob = "bobWithTrailingText";
		assertFalse(StringUtilities.endsWithIgnoreCase(startsWithBob, bob));

		String justBob = "bOb";
		assertTrue(StringUtilities.endsWithIgnoreCase(justBob, bob));
	}

	@Test
	public void testIndexOfWord() {
		String word = "test";
		String sentenceWithTest = "This is a test sentence";
		String sentenceWithTestNotAsAWord = "Thisisatestsentence";

		assertEquals(10, StringUtilities.indexOfWord(sentenceWithTest, word));
		assertEquals(-1, StringUtilities.indexOfWord(sentenceWithTestNotAsAWord, word));
	}

	@Test
	public void testIsAllBlank() {

		String[] input = null;
		assertTrue(StringUtilities.isAllBlank(input));
		assertTrue(StringUtilities.isAllBlank(null, null));
		assertTrue(StringUtilities.isAllBlank(""));
		assertTrue(StringUtilities.isAllBlank("", ""));
		assertFalse(StringUtilities.isAllBlank("Hi"));
		assertFalse(StringUtilities.isAllBlank("Hi", null));
		assertFalse(StringUtilities.isAllBlank("Hi", "Hey"));
	}

	@Test
	public void testFindWord() {
		String foundWord = "word";
		String sentence = "This string has a word that we should find";
		assertEquals(foundWord, StringUtilities.findWord(sentence, 18));
		assertEquals(foundWord, StringUtilities.findWord(sentence, 19));
		assertEquals(foundWord, StringUtilities.findWord(sentence, 21));

		String embeddedFoundWord = "word1";
		String sentenceWithInvalidChars = "This string has *word1!word2 with invalid chars";
		assertEquals(embeddedFoundWord, StringUtilities.findWord(sentenceWithInvalidChars, 18));

		char[] allowedChars = new char[] { '!' };
		String foundWordWithAllowedChars = "word1!word2";
		assertEquals(foundWordWithAllowedChars,
			StringUtilities.findWord(sentenceWithInvalidChars, 18, allowedChars));
	}

	@Test
	public void testFindWord_ProgrammingWord() {
		String code = "String var_with_underbar = foo.getBar().getName(defaultValue);";
		assertEquals("String", StringUtilities.findWord(code, 3));

		assertEquals("var_with_underbar", StringUtilities.findWord(code, 7));
		assertEquals("var_with_underbar", StringUtilities.findWord(code, 12));
		assertEquals("var_with_underbar", StringUtilities.findWord(code, 23));

		assertEquals("", StringUtilities.findWord(code, 24));
		assertEquals("=", StringUtilities.findWord(code, 25));
		assertEquals("", StringUtilities.findWord(code, 26));

		assertEquals("foo", StringUtilities.findWord(code, 27));
		assertEquals(".", StringUtilities.findWord(code, 30));
		assertEquals("getBar", StringUtilities.findWord(code, 31));

		assertEquals("getName", StringUtilities.findWord(code, 40));
		assertEquals("(", StringUtilities.findWord(code, 47));
		assertEquals("defaultValue", StringUtilities.findWord(code, 50));

		assertEquals("", StringUtilities.findWord(code, code.length()));
		assertEquals(";", StringUtilities.findWord(code, code.length() - 1));
		assertEquals(")", StringUtilities.findWord(code, code.length() - 2));
	}

	@Test
	public void testFindLastWordPosition() {
		String testString = "This is a test String";
		assertEquals(15, StringUtilities.findLastWordPosition(testString));
	}

	@Test
	public void testToString() {
		assertEquals("ABCD", StringUtilities.toString(0x41424344));
	}

	@Test
	public void testTrim() {
		// test that a length smaller than max will not be altered
		int max = 15;
		String underString = "UnderMaxString";
		String result = StringUtilities.trim(underString, max);
		assertSame(underString, result);

		// test that a length equal to max will not be altered
		max = 17;
		String equalToMaxString = "AtMaxLengthString";
		result = StringUtilities.trim(equalToMaxString, max);
		assertSame(equalToMaxString, result);

		// test that a length greater than max will be trimmed (with various overages)
		max = 6;
		String overString = "OverBy1";
		result = StringUtilities.trim(overString, max);
		assertEquals(max, result.length());
		assertEquals("Ove...", result);

		max = 5;
		overString = "OverBy2";
		result = StringUtilities.trim(overString, max);
		assertEquals(max, result.length());
		assertEquals("Ov...", result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTrim_MaxTooShortForEllipses() {
		int max = 1;
		String underString = "UnderMaxString";
		StringUtilities.trim(underString, max);
	}

	@Test
	public void testTrimMiddle_UnderMax() {

		// test that a length smaller than max will not be altered
		String underString = "Under Max String";
		int max = underString.length() + 1;
		String result = StringUtilities.trimMiddle(underString, max);
		assertSame(underString, result);

		// test that a length equal to max will not be altered
		String equalToMaxString = "At Max Length String";
		max = equalToMaxString.length();
		result = StringUtilities.trimMiddle(equalToMaxString, max);
		assertSame(equalToMaxString, result);
	}

	@Test
	public void testTrimMiddle_OddLengthStrings() {
		String overString = "Over By 1";
		int max = overString.length() - 1;
		String result = StringUtilities.trimMiddle(overString, max);
		assertEquals(max, result.length());
		assertEquals("Ov...y 1", result);

		overString = "Over By 2";
		max = overString.length() - 2;
		result = StringUtilities.trimMiddle(overString, max);
		assertEquals(max, result.length());
		assertEquals("Ov... 2", result);
	}

	@Test
	public void testTrimMiddle_EvenLengthStrings() {
		String overString = "Over By 12";
		int max = overString.length() - 1;
		String result = StringUtilities.trimMiddle(overString, max);
		assertEquals("Ove... 12", result);

		max = overString.length() - 2;
		result = StringUtilities.trimMiddle(overString, max);
		assertEquals(max, result.length());
		assertEquals("Ov... 12", result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testTrimMiddle_MaxTooShortForEllipses() {
		String overString = "My String to trim";
		int max = 1;
		StringUtilities.trimMiddle(overString, max);
	}

	@Test
	public void testGetLastWord() {
		assertEquals("word", StringUtilities.getLastWord("/This/is/my/last/word", "/"));
		assertEquals("word", StringUtilities.getLastWord("This/is/my/last/word", "/"));
		assertEquals("word", StringUtilities.getLastWord("/This/is/my/last/word/", "/"));
		assertEquals("word", StringUtilities.getLastWord("This.is.my.last.word", "."));
		assertEquals("MyFile.java",
			StringUtilities.getLastWord("/This/is/my/last/word/MyFile.java", "/"));
		assertEquals("java", StringUtilities.getLastWord("/This/is/my/last/word/MyFile.java", "."));
	}

	@Test
	public void testTrimTrailingNulls() {
		assertEquals("", StringUtilities.trimTrailingNulls(""));
		assertEquals("", StringUtilities.trimTrailingNulls("\0"));
		assertEquals("", StringUtilities.trimTrailingNulls("\0\0"));
		assertEquals("x", StringUtilities.trimTrailingNulls("x\0"));
		assertEquals("x", StringUtilities.trimTrailingNulls("x\0\0"));
		assertEquals("x", StringUtilities.trimTrailingNulls("x"));
		assertEquals("\0x", StringUtilities.trimTrailingNulls("\0x\0"));
	}

	@Test
	public void testToLines() {
		String s = "This\nis\nmy\nString";
		String[] lines = StringUtilities.toLines(s);
		assertEquals(4, lines.length);

		assertEquals("This", lines[0]);
		assertEquals("is", lines[1]);
		assertEquals("my", lines[2]);
		assertEquals("String", lines[3]);
	}

	@Test
	public void testToLinesNewlineAtBeginningMiddleAndEnd() {
		String s = "\nThis\nis\nmy\nString\n";
		String[] lines = StringUtilities.toLines(s);
		assertEquals(6, lines.length);

		assertEquals("", lines[0]);
		assertEquals("This", lines[1]);
		assertEquals("is", lines[2]);
		assertEquals("my", lines[3]);
		assertEquals("String", lines[4]);
		assertEquals("", lines[5]);
	}

	@Test
	public void testToLinesPreserveTokens() {
		String s = "My\n\nString";
		String[] lines = StringUtilities.toLines(s, true);
		assertEquals(3, lines.length);

		assertEquals("My", lines[0]);
		assertEquals("", lines[1]);
		assertEquals("String", lines[2]);
	}

	@Test
	public void testToLinesDontPreserveTokens() {
		String s = "My\n\nString";
		String[] lines = StringUtilities.toLines(s, false);
		assertEquals(2, lines.length);

		assertEquals("My", lines[0]);
		assertEquals("String", lines[1]);
	}
}
