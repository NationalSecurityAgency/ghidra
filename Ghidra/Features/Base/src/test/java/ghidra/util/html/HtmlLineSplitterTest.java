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
package ghidra.util.html;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

public class HtmlLineSplitterTest {

	@Test
	public void testSplitWithMaxRetainLeadingSpacesWithSpacesAtFront() {
		String text = "              Heeey mom!  Look, no hands";
		List<String> lines = HtmlLineSplitter.split(text, 21, true);
		assertEquals(2, lines.size());
		assertEquals("              Heeey ", lines.get(0));
		assertEquals("mom!  Look, no hands", lines.get(1));
	}

	@Test
	public void testSplitWithMaxRetainLeadingSpacesWithSpacesInMiddle() {
		String text = "Heeey mom!                Look, no hands";
		List<String> lines = HtmlLineSplitter.split(text, 21, true);

		assertEquals(2, lines.size());
		assertEquals("Heeey mom!          ", lines.get(0));
		assertEquals("      Look, no hands", lines.get(1));
	}

	@Test
	public void testSplitNoMaxWithNewlines() {
		List<String> lines = HtmlLineSplitter.split("abc\ndef", 0);
		assertEquals(2, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("def", lines.get(1));
	}

	@Test
	public void testSplitNoMaxWithContiguousNewlinesInMiddle() {
		List<String> lines = HtmlLineSplitter.split("abc\n\ndef", 0);
		assertEquals(3, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("", lines.get(1));
		assertEquals("def", lines.get(2));

		lines = HtmlLineSplitter.split("abc\n\n\ndef", 0);
		assertEquals(4, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("", lines.get(1));
		assertEquals("", lines.get(2));
		assertEquals("def", lines.get(3));
	}

	@Test
	public void testSplitNoMaxWithContiguousNewlinesAtEnd() {

		List<String> lines = HtmlLineSplitter.split("abcdef\n\n", 0);
		assertEquals(3, lines.size());
		assertEquals("abcdef", lines.get(0));
		assertEquals("", lines.get(1));
		assertEquals("", lines.get(2));

		lines = HtmlLineSplitter.split("abcdef\n\n\n", 0);
		assertEquals(4, lines.size());
		assertEquals("abcdef", lines.get(0));
		assertEquals("", lines.get(1));
		assertEquals("", lines.get(2));
		assertEquals("", lines.get(3));
	}

	@Test
	public void testSplitNoMaxWithoutNewlines() {
		List<String> lines = HtmlLineSplitter.split("abcdef", 0);
		assertEquals(1, lines.size());
		assertEquals("abcdef", lines.get(0));
	}

	@Test
	public void testSplitWithMaxWithNewlines() {
		// length below max
		List<String> lines = HtmlLineSplitter.split("abc\ndef", 100);
		assertEquals(2, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("def", lines.get(1));

		// past max; newlines less than max
		lines = HtmlLineSplitter.split("abc\ndef", 5);
		assertEquals(2, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("def", lines.get(1));

		// past max; newlines larger than max (splits on newlines only; no other whitespace
		// upon which to split)
		lines = HtmlLineSplitter.split("abcdefg\nh", 5);
		assertEquals(2, lines.size());
		assertEquals("abcdefg", lines.get(0));
		assertEquals("h", lines.get(1));
	}

	@Test
	public void testSplitWithMaxWithoutNewlines() {
		// single string--no whitespace or newlines upon which to split
		List<String> lines = HtmlLineSplitter.split("abcdefghi", 3);
		assertEquals(1, lines.size());
		assertEquals("abcdefghi", lines.get(0));
	}

	@Test
	public void testSplitWithMaxWithSpaceAtEnd() {
		// The word is long enough to force a hard split on the first 'n' characters.  The
		// space at the end allows the remaining 'word' to be kept intact.
		List<String> lines = HtmlLineSplitter.split("abcdefghijklm ", 3);
		assertEquals(2, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("defghijklm", lines.get(1));
	}

	@Test
	public void testSplitWithMaxAtMaxWithSpacesAtEnd() {
		// The word is long enough to force a hard split on the first 'n' characters.  The
		// space at the end allows the remaining 'word' to be kept intact.
		List<String> lines = HtmlLineSplitter.split("abc        ", 3);
		assertEquals(1, lines.size());
		assertEquals("abc", lines.get(0));
	}

	@Test
	public void testSplitWithMaxWhitespaceAsPartOfMaxWithSpaceAtEnd() {
		// The word is long enough to force a hard split on the first 'n' characters.  The
		// space at the end allows the remaining 'word' to be kept intact.
		List<String> lines = HtmlLineSplitter.split("ab   c     ", 6);
		assertEquals(2, lines.size());
		assertEquals("ab", lines.get(0));
		assertEquals("c", lines.get(1));
	}

	@Test
	public void testSplitWithoutMaxNewlineAtBeginningAndEndOnly() {
		List<String> lines = HtmlLineSplitter.split("\nabcdefghi\n", 0);
		assertEquals(3, lines.size());
		assertEquals("", lines.get(0));
		assertEquals("abcdefghi", lines.get(1));
		assertEquals("", lines.get(2));
	}

	@Test
	public void testSplitWithMaxNewlineAtBeginningAndEndOnly() {
		// newlines at begin and end do not create lines; no whitespace--max is below
		// MAX_WORD_LENGTH, so single line only
		List<String> lines = HtmlLineSplitter.split("\nabcdefghi\n", 4);
		assertEquals(3, lines.size());
		assertEquals("", lines.get(0));
		assertEquals("abcdefghi", lines.get(1));
		assertEquals("", lines.get(2));
	}

	@Test
	public void testSplitWithMaxNewlineAtBeginningAndMiddleAndEndOnly() {
		// newlines at begin and end do not create lines; no whitespace--max is below
		// MAX_WORD_LENGTH, so single line only
		List<String> lines = HtmlLineSplitter.split("\nabcd\nefghi\n", 6);
		assertEquals(4, lines.size());
		assertEquals("", lines.get(0));
		assertEquals("abcd", lines.get(1));
		assertEquals("efghi", lines.get(2));
		assertEquals("", lines.get(3));
	}

	@Test
	public void testSplitWithMultipleTrailingNewlines() {
		// newlines at begin and end do not create lines; no whitespace--max is below
		// MAX_WORD_LENGTH, so single line only
		List<String> lines = HtmlLineSplitter.split("\naa\n\nbb\n\n\n", 100);
		assertEquals(7, lines.size());
		assertEquals("", lines.get(0));
		assertEquals("aa", lines.get(1));
		assertEquals("", lines.get(2));
		assertEquals("bb", lines.get(3));
		assertEquals("", lines.get(4));
		assertEquals("", lines.get(5));
		assertEquals("", lines.get(6));
	}

	@Test
	public void testSplitWithMultipleTrailingNewlines2() {
		// newlines at begin and end do not create lines; no whitespace--max is below
		// MAX_WORD_LENGTH, so single line only
		List<String> lines = HtmlLineSplitter.split("\naa\n\n", 100);
		assertEquals(4, lines.size());
		assertEquals("", lines.get(0));
		assertEquals("aa", lines.get(1));
		assertEquals("", lines.get(2));
		assertEquals("", lines.get(3));
	}

	@Test
	public void testSplitWithNoMaxWithMultipleNewlinesOnly() {
		// newlines at begin and end do not create lines; no whitespace--max is below
		// MAX_WORD_LENGTH, so single line only
		List<String> lines = HtmlLineSplitter.split("\n\n\n", 100);
		assertEquals(4, lines.size());
	}

	@Test
	public void testSplitWithMaxWithSpacesLessThanMax() {
		// the split routine will look backwards for a space.  So, we get one line shorter than
		// the requested max and one line longer
		List<String> lines = HtmlLineSplitter.split("abcd efghijklmnopq", 8);
		assertEquals(2, lines.size());
		assertEquals("abcd", lines.get(0));
		assertEquals("efghijklmnopq", lines.get(1));
	}

	@Test
	public void testSplitWithMaxWithSpacesGreaterThanMax() {
		// the split routine will look  forwards for a space.  It will split on this space
		List<String> lines = HtmlLineSplitter.split("abcdefg hijklmnopq", 3);
		assertEquals(2, lines.size());
		assertEquals("abcdefg", lines.get(0));
		assertEquals("hijklmnopq", lines.get(1));
	}

	@Test
	public void testSplitWithMaxWithSpacesFarAwayFromMax() {
		// the split routine will look  forwards for a space.  It will split on this space
		List<String> lines = HtmlLineSplitter.split("abcdefg hijklmnopq", 3);
		assertEquals(2, lines.size());
		assertEquals("abcdefg", lines.get(0));
		assertEquals("hijklmnopq", lines.get(1));
	}

	@Test
	public void testSplitWithMaxRetainBlankLines() {
		List<String> lines = HtmlLineSplitter.split("abcd\n\nefgh", 3);
		assertEquals("Wrong number of lines - " + lines, 3, lines.size());
		assertEquals("abcd", lines.get(0));
		assertEquals("", lines.get(1));
		assertEquals("efgh", lines.get(2));
	}

	@Test
	public void testSplitWithMaxWithoutSpacesGreaterThanMaxWordLength() {
		// assume MAX_WORD_LENGTH == 10 (I'm too lazy to dynamically generate the data)
		assertEquals("Update test for new MAX_WORD_LENGTH", 10, HtmlLineSplitter.MAX_WORD_LENGTH);

		List<String> lines = HtmlLineSplitter.split("abcdefghijklmnopqrstuvwxyz", 3);
		assertEquals(9, lines.size());
		assertEquals("abc", lines.get(0));
		assertEquals("def", lines.get(1));
		assertEquals("ghi", lines.get(2));
		assertEquals("jkl", lines.get(3));
		assertEquals("mno", lines.get(4));
		assertEquals("pqr", lines.get(5));
		assertEquals("stu", lines.get(6));
		assertEquals("vwx", lines.get(7));
		assertEquals("yz", lines.get(8));
	}

	@Test
	public void testSplitAtSpace() {
		List<String> lines = HtmlLineSplitter.split("split split", 5);
		assertEquals("Wrong number of lines - " + lines, 2, lines.size());
		assertEquals("split", lines.get(0));
		assertEquals("split", lines.get(1));
	}

	@Test
	public void testSplitAtSpace_PreserveWhitespace() {
		//
		// Interesting behavior: the second split attempts to split ' spli'.  The algorithm 
		// then looks for a space to split on, to avoid breaking a word.  It finds the first
		// space and then splits there, creating a line that is just a ' '.  It looks unusual, 
		// but it prevents splitting on a word.
		//
		List<String> lines = HtmlLineSplitter.split("split split", 5, true);
		assertEquals("Wrong number of lines - " + lines, 3, lines.size());
		assertEquals("split", lines.get(0));
		assertEquals(" ", lines.get(1));
		assertEquals("split", lines.get(2));
	}

}
