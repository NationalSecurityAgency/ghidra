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
package docking.widgets.fieldpanel;

import static org.junit.Assert.*;

import java.math.BigInteger;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.*;
import generic.test.AbstractGenericTest;
import ghidra.framework.options.SaveState;

/**
 * 
 */
public class FieldSelectionTest extends AbstractGenericTest {

	/**
	 * Constructor for FieldSelectionTest.
	 * @param name
	 */
	public FieldSelectionTest() {
		super();
	}

	@Before
	public void setUp() {
	}

	private FieldLocation fl(int index, int fieldNum) {
		return new FieldLocation(index, fieldNum, 0, 0);
	}

	@Test
	public void testContains() {
		FieldSelection fs = new FieldSelection();
		fs.addRange(10, 16, 15, 3);
		fs.addRange(20, 31);
		assertTrue(!fs.contains(fl(0, 0)));
		assertTrue(!fs.contains(fl(10, 0)));
		assertTrue(!fs.contains(fl(10, 15)));
		assertTrue(fs.contains(fl(10, 16)));
		assertTrue(fs.contains(fl(10, 17)));
		assertTrue(fs.contains(fl(10, Integer.MAX_VALUE)));
		assertTrue(fs.contains(fl(15, 0)));
		assertTrue(fs.contains(fl(15, 2)));
		assertTrue(!fs.contains(fl(15, 3)));
		assertTrue(!fs.contains(fl(15, 4)));

		assertTrue(!fs.contains(fl(16, 0)));

		assertTrue(fs.contains(fl(20, 0)));
		assertTrue(fs.contains(fl(20, 1)));
		assertTrue(fs.contains(fl(22, 0)));

		assertTrue(!fs.contains(fl(31, 0)));

	}

	@Test
	public void testCoalescing() {
		FieldSelection fs = new FieldSelection();
		fs.addRange(2, 3);
		fs.addRange(3, 4);
		assertEquals(1, fs.getNumRanges());

		fs.clear();
		fs.addRange(2, 2, 3, 5);
		fs.addRange(3, 5, 7, 2);
		assertEquals(1, fs.getNumRanges());

		fs.clear();
		fs.addRange(2, 2, 2, 5);
		fs.addRange(2, 0, 3, 0);
		assertEquals(1, fs.getNumRanges());
		assertEquals(new FieldRange(fl(2, 0), fl(3, 0)), fs.getFieldRange(0));

	}

	@Test
	public void testContainsEntirely() {
		FieldSelection fs = new FieldSelection();
		fs.addRange(10, 16, 15, 3);

		assertTrue(!fs.containsEntirely(BigInteger.valueOf(10)));
		assertTrue(fs.containsEntirely(BigInteger.valueOf(11)));
		assertTrue(fs.containsEntirely(BigInteger.valueOf(12)));
		assertTrue(fs.containsEntirely(BigInteger.valueOf(13)));
		assertTrue(fs.containsEntirely(BigInteger.valueOf(14)));
		assertTrue(!fs.containsEntirely(BigInteger.valueOf(15)));
	}

	public void excludesEntirely() {
		FieldSelection fs = new FieldSelection();
		fs.addRange(10, 16, 15, 3);
		fs.addRange(20, 21);

		assertTrue(fs.excludesEntirely(BigInteger.valueOf(9)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(10)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(11)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(12)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(13)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(14)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(15)));
		assertTrue(fs.excludesEntirely(BigInteger.valueOf(16)));

		assertTrue(fs.excludesEntirely(BigInteger.valueOf(19)));
		assertTrue(!fs.excludesEntirely(BigInteger.valueOf(20)));
		assertTrue(fs.excludesEntirely(BigInteger.valueOf(21)));
		assertTrue(fs.excludesEntirely(BigInteger.valueOf(22)));

	}

	@Test
	public void testIntersectForIndexes() {
		FieldSelection fs1 = new FieldSelection();
		FieldSelection fs2 = new FieldSelection();
		FieldSelection fsResult = new FieldSelection();

		// Test intersect of non overlapping ranges.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 16);
		fs1.addRange(20, 31);
		fs1.addRange(30, 41);
		fs2.addRange(4, 8);
		fs2.addRange(16, 19);
		fs2.addRange(50, 61);
		fs1.intersect(fs2);
		assertEquals(fsResult, fs1);

		// Test fs1 same as fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 16);
		fs1.addRange(20, 31);
		fs1.addRange(30, 41);
		fs2.addRange(10, 16);
		fs2.addRange(20, 31);
		fs2.addRange(30, 41);
		fsResult = new FieldSelection(fs2);
		fs1.intersect(fs2);
		assertEquals(fsResult, fs1);

		// Test fs1 contains fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 16);
		fs1.addRange(20, 31);
		fs1.addRange(30, 41);
		fs2.addRange(10, 12);
		fs2.addRange(22, 27);
		fs2.addRange(35, 41);
		fsResult = new FieldSelection(fs2);
		fs1.intersect(fs2);
		assertEquals(fsResult, fs1);

		// Test fs2 contains fs1.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs2.addRange(10, 16);
		fs2.addRange(20, 31);
		fs2.addRange(30, 41);
		fs1.addRange(10, 12);
		fs1.addRange(22, 27);
		fs1.addRange(35, 41);
		fsResult = new FieldSelection(fs1);
		fs1.intersect(fs2);
		assertEquals(fsResult, fs1);

		// Test end of fs1 overlaps start of fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 16);
		fs2.addRange(14, 20);
		fsResult.addRange(14, 16);
		fs1.intersect(fs2);
		assertEquals(fsResult, fs1);

		// Test start of fs1 overlaps end of fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs2.addRange(10, 16);
		fs1.addRange(14, 20);
		fsResult.addRange(14, 16);
		fs1.intersect(fs2);
		assertEquals(fsResult, fs1);

	}

	@Test
	public void testIntersectForFields() {
		FieldSelection fs1 = new FieldSelection();
		FieldSelection fs2 = new FieldSelection();
		FieldSelection fsResult = new FieldSelection();

		// Test intersect of non overlapping ranges.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 0, 16, 0);
		fs1.addRange(20, 3, 25, 5);
		fs1.addRange(30, 0, 41, 0);
		fs2.addRange(2, 0, 3, 0);
		fs2.addRange(4, 0, 8, 5);
		fs2.addRange(16, 2, 20, 0);
		fs2.addRange(26, 2, 30, 0);
		fs2.addRange(41, 0, 45, 3);
		fs1.intersect(fs2);
		assertEquals(fs1, fsResult);

		// Test fs1 same as fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 2, 16, 7);
		fs1.addRange(20, 0, 31, 9);
		fs1.addRange(30, 5, 41, 0);
		fs1.addRange(43, 0, 46, 0);
		fs2.addRange(10, 2, 16, 7);
		fs2.addRange(20, 0, 31, 9);
		fs2.addRange(30, 5, 41, 0);
		fs2.addRange(43, 0, 46, 0);
		fsResult = new FieldSelection(fs2);
		fs1.intersect(fs2);
		assertEquals(fs1, fsResult);

		// Test fs1 contains fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 2, 16, 7);
		fs1.addRange(20, 4, 31, 1);
		fs1.addRange(30, 3, 41, 7);
		fs2.addRange(10, 2, 15, 7);
		fs2.addRange(22, 6, 27, 2);
		fs2.addRange(35, 1, 41, 7);
		fsResult = new FieldSelection(fs2);
		fs1.intersect(fs2);
		assertEquals(fs1, fsResult);

		// Test fs2 contains fs1.
		fs2.clear();
		fs1.clear();
		fsResult.clear();
		fs2.addRange(10, 2, 16, 7);
		fs2.addRange(20, 4, 31, 1);
		fs2.addRange(30, 3, 41, 7);
		fs1.addRange(10, 2, 15, 7);
		fs1.addRange(22, 6, 27, 2);
		fs1.addRange(35, 1, 41, 7);
		fsResult = new FieldSelection(fs1);
		fs1.intersect(fs2);
		assertEquals(fs1, fsResult);

		// Test end of fs1 overlaps start of fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs1.addRange(10, 3, 16, 2);
		fs2.addRange(14, 4, 20, 1);
		fsResult.addRange(14, 4, 16, 2);
		fs1.intersect(fs2);
		assertEquals(fs1, fsResult);

		// Test start of fs1 overlaps end of fs2.
		fs1.clear();
		fs2.clear();
		fsResult.clear();
		fs2.addRange(10, 3, 16, 2);
		fs1.addRange(14, 4, 20, 1);
		fsResult.addRange(14, 4, 16, 2);
		fs1.intersect(fs2);
		assertEquals(fs1, fsResult);

	}

	@Test
	public void testFieldRangeCompareTo() {
		FieldRange baseRange = new FieldRange(fl(3, 6), fl(5, 2));
		FieldRange completelyBefore = new FieldRange(fl(0, 0), fl(2, 0));
		FieldRange completelyBeforeSingleRow = new FieldRange(fl(3, 0), fl(3, 1));
		FieldRange startBeforeEndsInside = new FieldRange(fl(3, 2), fl(3, 7));
		FieldRange startsSameEndsInside = new FieldRange(fl(3, 6), fl(3, 7));
		FieldRange startSameEndsInsideSameRow = new FieldRange(fl(3, 6), fl(5, 1));
		FieldRange sameRange = new FieldRange(fl(3, 6), fl(5, 2));
		FieldRange startsSameEndsAfterSameRow = new FieldRange(fl(3, 6), fl(5, 3));
		FieldRange startsInsideEndsAfterSameRow = new FieldRange(fl(5, 0), fl(5, 3));
		FieldRange startsAtEndEndsAfter = new FieldRange(fl(5, 2), fl(7, 2));
		FieldRange startsAtEndRowCompletelyAfter = new FieldRange(fl(5, 6), fl(7, 2));
		FieldRange startsCompletelyAfter = new FieldRange(fl(6, 6), fl(7, 2));

		assertEquals(0, baseRange.compareTo(baseRange));
		assertEquals(0, baseRange.compareTo(sameRange));

		assertEquals(1, baseRange.compareTo(completelyBefore));
		assertEquals(1, baseRange.compareTo(completelyBeforeSingleRow));
		assertEquals(1, baseRange.compareTo(startBeforeEndsInside));
		assertEquals(1, baseRange.compareTo(startsSameEndsInside));
		assertEquals(1, baseRange.compareTo(startSameEndsInsideSameRow));
		assertEquals(-1, baseRange.compareTo(startsSameEndsAfterSameRow));
		assertEquals(-1, baseRange.compareTo(startsInsideEndsAfterSameRow));
		assertEquals(-1, baseRange.compareTo(startsAtEndEndsAfter));
		assertEquals(-1, baseRange.compareTo(startsAtEndRowCompletelyAfter));
		assertEquals(-1, baseRange.compareTo(startsCompletelyAfter));

		assertEquals(-1, completelyBefore.compareTo(baseRange));
		assertEquals(-1, completelyBeforeSingleRow.compareTo(baseRange));
		assertEquals(-1, startBeforeEndsInside.compareTo(baseRange));
		assertEquals(-1, startsSameEndsInside.compareTo(baseRange));
		assertEquals(-1, startSameEndsInsideSameRow.compareTo(baseRange));
		assertEquals(1, startsSameEndsAfterSameRow.compareTo(baseRange));
		assertEquals(1, startsInsideEndsAfterSameRow.compareTo(baseRange));
		assertEquals(1, startsAtEndEndsAfter.compareTo(baseRange));
		assertEquals(1, startsAtEndRowCompletelyAfter.compareTo(baseRange));
		assertEquals(1, startsCompletelyAfter.compareTo(baseRange));

	}

	@Test
	public void testFieldRangeContains() {
		FieldRange baseRange = new FieldRange(fl(3, 6), fl(5, 2));
		assertTrue(!baseRange.contains(fl(2, 2)));
		assertTrue(!baseRange.contains(fl(3, 3)));
		assertTrue(!baseRange.contains(fl(3, 5)));
		assertTrue(baseRange.contains(fl(3, 6)));
		assertTrue(baseRange.contains(fl(3, 7)));
		assertTrue(baseRange.contains(fl(4, 4)));
		assertTrue(baseRange.contains(fl(5, 1)));
		assertTrue(!baseRange.contains(fl(5, 2)));
		assertTrue(!baseRange.contains(fl(5, 3)));
		assertTrue(!baseRange.contains(fl(5, 2)));
	}

	@Test
	public void testFieldRangeCanMerge() {

		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(2, 4), fl(2, 6))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(2, 4), fl(3, 5))));

		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(2, 4), fl(3, 6))));
		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(2, 4), fl(3, 8))));
		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(2, 4), fl(5, 2))));
		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(2, 4), fl(7, 8))));
		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(3, 2), fl(7, 8))));
		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(4, 4), fl(7, 8))));
		assertTrue(new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(5, 2), fl(7, 8))));

		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(5, 3), fl(7, 8))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(5, 4), fl(7, 8))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).canMerge(new FieldRange(fl(6, 4), fl(7, 8))));

	}

	@Test
	public void testFieldRangeMerge() {

		FieldRange range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(2, 4), fl(3, 6)));
		assertEquals(new FieldRange(fl(2, 4), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(2, 4), fl(3, 8)));
		assertEquals(new FieldRange(fl(2, 4), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(2, 4), fl(3, 6)));
		assertEquals(new FieldRange(fl(2, 4), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(2, 4), fl(5, 2)));
		assertEquals(new FieldRange(fl(2, 4), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(2, 4), fl(7, 8)));
		assertEquals(new FieldRange(fl(2, 4), fl(7, 8)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(3, 2), fl(7, 8)));
		assertEquals(new FieldRange(fl(3, 2), fl(7, 8)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(4, 4), fl(7, 8)));
		assertEquals(new FieldRange(fl(3, 6), fl(7, 8)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		range.merge(new FieldRange(fl(5, 2), fl(7, 8)));
		assertEquals(new FieldRange(fl(3, 6), fl(7, 8)), range);

	}

	@Test
	public void testFieldRangeIntersects() {
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(2, 4), fl(2, 6))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(2, 4), fl(3, 5))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(2, 4), fl(3, 6))));

		assertTrue(
			new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(2, 4), fl(3, 8))));
		assertTrue(
			new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(2, 4), fl(5, 2))));
		assertTrue(
			new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(2, 4), fl(7, 8))));
		assertTrue(
			new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(3, 2), fl(7, 8))));
		assertTrue(
			new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(4, 4), fl(7, 8))));
		assertTrue(
			new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(5, 1), fl(7, 8))));

		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(5, 2), fl(7, 8))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(5, 3), fl(7, 8))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(5, 4), fl(7, 8))));
		assertTrue(
			!new FieldRange(fl(3, 6), fl(5, 2)).intersects(new FieldRange(fl(6, 4), fl(7, 8))));

	}

	@Test
	public void testFieldRangeSubtract() {
		FieldRange range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(2, 4), fl(3, 6))));
		assertEquals(new FieldRange(fl(3, 6), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(2, 4), fl(3, 7))));
		assertEquals(new FieldRange(fl(3, 7), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(2, 4), fl(4, 0))));
		assertEquals(new FieldRange(fl(4, 0), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(3, 6), fl(4, 0))));
		assertEquals(new FieldRange(fl(4, 0), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertEquals(new FieldRange(fl(4, 0), fl(5, 2)),
			range.subtract(new FieldRange(fl(3, 7), fl(4, 0))));
		assertEquals(new FieldRange(fl(3, 6), fl(3, 7)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertEquals(new FieldRange(fl(4, 3), fl(5, 2)),
			range.subtract(new FieldRange(fl(4, 0), fl(4, 3))));
		assertEquals(new FieldRange(fl(3, 6), fl(4, 0)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(3, 6), fl(5, 2))));
		assertEquals(new FieldRange(fl(3, 6), fl(3, 6)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(3, 8), fl(5, 2))));
		assertEquals(new FieldRange(fl(3, 6), fl(3, 8)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(3, 8), fl(5, 8))));
		assertEquals(new FieldRange(fl(3, 6), fl(3, 8)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(3, 8), fl(7, 8))));
		assertEquals(new FieldRange(fl(3, 6), fl(3, 8)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(5, 2), fl(7, 8))));
		assertEquals(new FieldRange(fl(3, 6), fl(5, 2)), range);

		range = new FieldRange(fl(3, 6), fl(5, 2));
		assertNull(range.subtract(new FieldRange(fl(1, 2), fl(7, 8))));
		assertEquals(new FieldRange(fl(3, 6), fl(3, 6)), range);
	}

	@Test
	public void testSaveRestore() {
		FieldSelection fs1 = new FieldSelection();
		fs1.addRange(10, 0, 16, 0);
		fs1.addRange(20, 3, 25, 5);
		fs1.addRange(30, 0, 41, 0);

		SaveState ss = new SaveState();
		fs1.save(ss);
		FieldSelection fs2 = new FieldSelection();
		fs2.load(ss);
		assertEquals(fs1, fs2);
	}
}
