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

import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.junit.Test;

import generic.test.AbstractGTest;

public class StringDiffTest {

	@Test
	public void testGetDiffLines_Insert_AtFront() {

		String[] a1 = new String[] { "This", "is", "four", "friends" };
		String[] a2 = new String[] { "Inserted", "This", "is", "four", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Insert_AtEnd() {

		String[] a1 = new String[] { "This", "is", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "friends", "Inserted" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Insert_AtMiddle() {

		String[] a1 = new String[] { "This", "is", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "Inserted", "four", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_AtStart() {

		String[] a1 = new String[] { "DELETED", "This", "is", "the", "best" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_AtEnd() {

		String[] a1 = new String[] { "This", "is", "the", "best", "DELETED" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_AtMiddle() {

		String[] a1 = new String[] { "This", "is", "DELETED", "the", "best" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Delete_MultipleDeletes() {

		String[] a1 = new String[] { "This", "is", "DELETED", "the", "best", "DELETED" };
		String[] a2 = new String[] { "This", "is", "the", "best" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
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

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Rearrange_DifferentLineLength_LongerThanNewSpot() {

		String[] a1 = new String[] { "This", "is", "besties", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "besties", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetDiffLines_Rearrange_DifferentLineLength_ShorterThanNewSpot() {

		String[] a1 = new String[] { "This", "is", "be", "four", "friends" };
		String[] a2 = new String[] { "This", "is", "four", "be", "friends" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetLineDiffs_Empty() {

		String v1 = "";
		String v2 = "";

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 0);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetLineDiffs_EmptyInitial() {

		String v1 = "";
		String v2 = "This is not empty";

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 0);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testGetLineDiffs_EmptyReplacement() {

		String v1 = "This is not empty";
		String v2 = "";

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 0);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testReplace() {
		String[] a1 = new String[] { "In", "the", "beginning" };
		String[] a2 = new String[] { "There", "was", "vastness" };
		String v1 = StringUtils.join(a1, '\n');
		String v2 = StringUtils.join(a2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	@Test
	public void testTheBiggness_NoOptimization() throws Exception {

		List<String> bigLines = generateLines(1200);
		List<String> bigLines2 = new ArrayList<>(bigLines);

		bigLines2.set(0, "a new line at 0");
		bigLines2.set(bigLines2.size() - 1, "a new line at length");

		String v1 = StringUtils.join(bigLines, '\n');
		String v2 = StringUtils.join(bigLines2, '\n');

		StringDiff[] diffs = StringDiffUtils.getLineDiffs(v1, v2, 1);
		assertEquals(1, diffs.length); // 1 diff--completely different, due to size restriction on Lcs
		String restoredV2 = StringDiffUtils.applyDiffs(v1, Arrays.asList(diffs));
		assertEquals(v2, restoredV2);
	}

	private List<String> generateLines(int size) {

		List<String> results = new ArrayList<>();
		for (int i = 0; i < size; i++) {
			String random = AbstractGTest.getRandomString(0, 50);
			random = random.replaceAll("\n", "");
			results.add("Line " + (i + 1) + ": " + random);
		}

		return results;
	}
}
