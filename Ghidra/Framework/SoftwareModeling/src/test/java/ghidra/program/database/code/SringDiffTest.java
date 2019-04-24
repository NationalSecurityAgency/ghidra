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
package ghidra.program.database.code;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

public class SringDiffTest {

	/*
	 	A line match is if the given line to match is contained in the source string and:
	 	
	 		1) a) matches in the source string with a '\n' char at the index before the match OR
	 		   b) is at the beginning *and* the match contains a newline
	 		2) is at the exact end of the source string
	 		
	 		*The empty string matches at the current position
	 	
	 	Source String:	 "abcd\nefghi\n"
	 	Line to Match:	 	
	 */

	@Test
	public void testFindLine_FromStart_EmptyLine() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(0, result);
	}

	@Test
	public void testFindLine_FromStart_NoMatch() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "coconuts";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(-1, result);
	}

	@Test
	public void testFindLine_FromMiddle_NoMatch() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "coconuts";
		int result = StringDiffer.findLine(source, 15, line);
		assertEquals(-1, result);
	}

	@Test
	public void testFindLine_FromEnd_NoMatch() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "coconuts";
		int result = StringDiffer.findLine(source, source.length(), line);
		assertEquals(-1, result);
	}

	@Test
	public void testFindLine_FromStart_MatchWithNewline_AtStart() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "this is a really\n";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(0, result);
	}

	@Test
	public void testFindLine_FromStart_MatchWithNewline_AtMiddle() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "lone line with\n";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(17, result);
	}

	@Test
	public void testFindLine_FromStart_MatchWithNewline_AtEnd_FailWithoutPrecedingNewline() {

		String source = "this is a really\nlone line with\n newlines\n";
		String line = "lines\n";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(-1, result);
	}

	@Test
	public void testFindLine_FromStart_MatchWithNewline_AtEnd_PassWithPrecedingNewline() {

		String source = "this is a really\nlone line with\n new\nlines\n";
		String line = "lines\n";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(37, result);
	}

	@Test
	public void testFindLine_FromStart_MatchWithoutNewline_AtStart() {

		String source = "this is a really\nlone line with\n newlines";
		String line = "this is a really";
		int result = StringDiffer.findLine(source, 0, line);
		assertEquals(-1, result); // match at start must contain a newline
	}

	@Test
	public void testGetDiffLines_Insert_AtFront() {

		String[] a1 = new String[] { "This", "is", "four", "friends" };
		String[] a2 = new String[] { "Inserted", "This", "is", "four", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Insert_AtEnd() {

		String[] a1 = new String[] { "This", "is", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "friends", "Inserted" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Insert_AtMiddle() {

		String[] a1 = new String[] { "This", "is", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "Inserted", "four", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_AtStart() {

		String[] a1 = new String[] { "DELETED", "This", "is", "the", "best" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_AtEnd() {

		String[] a1 = new String[] { "This", "is", "the", "best", "DELETED" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_AtMiddle() {

		String[] a1 = new String[] { "This", "is", "DELETED", "the", "best" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_MultipleDeletes() {

		String[] a1 = new String[] { "This", "is", "DELETED", "the", "best", "DELETED" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Rearrange_EqualLineLength() {

		// note: this text used to cause an infinite loop bug that tripped when two words were
		//       swapped at some point in the two strings *and* had the same length

		String[] a1 = new String[] { "This", "is", "best", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "best", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Rearrange_DifferentLineLength_LongerThanNewSpot() {

		String[] a1 = new String[] { "This", "is", "besties", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "besties", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Rearrange_DifferentLineLength_ShorterThanNewSpot() {

		String[] a1 = new String[] { "This", "is", "be", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "be", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffer.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffer.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

}
