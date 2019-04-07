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
package ghidra.util.datastruct;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;

/**
 * Tests the Range class which has a signed int range.
 */
public class RangeTest extends AbstractGenericTest {
	int[][] goodPairs = { { Integer.MIN_VALUE, Integer.MAX_VALUE },
		{ Integer.MIN_VALUE, Integer.MIN_VALUE }, { Integer.MAX_VALUE, Integer.MAX_VALUE },
		{ 0, Integer.MAX_VALUE }, { Integer.MIN_VALUE, 0 }, { 0, 0 }, { Integer.MIN_VALUE, -1 },
		{ 1, Integer.MAX_VALUE }, { Integer.MIN_VALUE, 1 }, { -1, Integer.MAX_VALUE },
		{ -200, 200 }, { -3000, -1950 }, { 1746, 2334 } };

	int[][] badPairs = { { Integer.MAX_VALUE, Integer.MIN_VALUE }, { Integer.MAX_VALUE, 0 },
		{ 0, Integer.MIN_VALUE }, { -1, Integer.MIN_VALUE }, { Integer.MAX_VALUE, 1 },
		{ 1, Integer.MIN_VALUE, }, { Integer.MAX_VALUE, -1 }, { 200, -200 }, { -1950, -3000 },
		{ 2334, 1746 } };

	/**
	 * Constructor for TestRange.
	 */
	public RangeTest() {
		super();
	}

	@Test
	public void testRange() {
		Range r;
		// Valid construction
		for (int i = 0; i < goodPairs.length; i++) {
			int[] pair = goodPairs[i];
			int min = pair[0];
			int max = pair[1];
			r = new Range(min, max);
			assertEquals(min, r.min);
			assertEquals(max, r.max);
		}

		// Invalid construction
		for (int i = 0; i < badPairs.length; i++) {
			int[] pair = badPairs[i];
			int min = pair[0];
			int max = pair[1];
			try {
				r = new Range(min, max);
				Assert.fail("Didn't detect max(" + max + ") less than min(" + min + ") for Range.");
			}
			catch (IllegalArgumentException e) {
			}
		}
	}

	@Test
	public void testCompareTo() {
		Range r;
		r = new Range(Integer.MIN_VALUE, Integer.MAX_VALUE);
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) == 0);// same
		assertTrue(r.compareTo(new Range(0, 0)) < 0);// inside
		assertTrue(r.compareTo(new Range(-4567, -2222)) < 0);// inside
		assertTrue(r.compareTo(new Range(-333, 5678)) < 0);// inside
		assertTrue(r.compareTo(new Range(111, 3467)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -345)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 567)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-444, Integer.MAX_VALUE)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(0, Integer.MAX_VALUE)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(55, Integer.MAX_VALUE)) < 0);// endAtMax

		r = new Range(Integer.MIN_VALUE, Integer.MIN_VALUE);
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MIN_VALUE)) == 0);// same

		r = new Range(Integer.MAX_VALUE, Integer.MAX_VALUE);
		assertTrue(r.compareTo(new Range(Integer.MAX_VALUE, Integer.MAX_VALUE)) == 0);// same

		r = new Range(0, Integer.MAX_VALUE);
		assertTrue(r.compareTo(new Range(0, Integer.MAX_VALUE)) == 0);// same
		assertTrue(r.compareTo(new Range(1, Integer.MAX_VALUE - 1)) < 0);// inside
		assertTrue(r.compareTo(new Range(55, 999)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -1)) > 0);// before
		assertTrue(r.compareTo(new Range(-234, -123)) > 0);// before
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-2221, 333)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-1, Integer.MAX_VALUE)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(0, 0)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(0, 344)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-15, Integer.MAX_VALUE)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(1, Integer.MAX_VALUE)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(Integer.MAX_VALUE, Integer.MAX_VALUE)) < 0);// endAtMax

		r = new Range(Integer.MIN_VALUE, 0);
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) == 0);// same
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE + 1, -1)) < 0);// inside
		assertTrue(r.compareTo(new Range(-4445, -555)) < 0);// inside
		assertTrue(r.compareTo(new Range(22, 22)) < 0);// after
		assertTrue(r.compareTo(new Range(1, Integer.MAX_VALUE)) < 0);// after
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 45)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1)) == 0);// overlap max
		assertTrue(r.compareTo(new Range(-555, 99)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(0, Integer.MAX_VALUE)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) == 0);// endAtMax
		assertTrue(r.compareTo(new Range(-88, 0)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(0, 0)) < 0);// endAtMax

		r = new Range(0, 0);
		assertTrue(r.compareTo(new Range(0, 0)) == 0);// same

		r = new Range(Integer.MIN_VALUE, -1);
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -1)) == 0);// same
		assertTrue(r.compareTo(new Range(-22, 0)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE + 1, -66)) < 0);// inside
		assertTrue(r.compareTo(new Range(222, 543)) < 0);// after
		assertTrue(r.compareTo(new Range(0, Integer.MAX_VALUE)) < 0);// after
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MIN_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -99)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) == 0);// overlap max
		assertTrue(r.compareTo(new Range(-555, 99)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(-1, Integer.MAX_VALUE)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -1)) == 0);// endAtMax
		assertTrue(r.compareTo(new Range(-88, -1)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(-1, -1)) < 0);// endAtMax

		r = new Range(1, Integer.MAX_VALUE);
		assertTrue(r.compareTo(new Range(1, Integer.MAX_VALUE)) == 0);// same
		assertTrue(r.compareTo(new Range(2, Integer.MAX_VALUE - 1)) < 0);// inside
		assertTrue(r.compareTo(new Range(222, 555)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 0)) > 0);// before
		assertTrue(r.compareTo(new Range(-333, -222)) > 0);// before
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(0, 235)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-55, Integer.MAX_VALUE - 1)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(1, 1)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(1, 456)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(1, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-15, Integer.MAX_VALUE)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(23, Integer.MAX_VALUE)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(Integer.MAX_VALUE, Integer.MAX_VALUE)) < 0);// endAtMax

		r = new Range(Integer.MIN_VALUE, 1);
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1)) == 0);// same
		assertTrue(r.compareTo(new Range(-1234, 0)) < 0);// inside
		assertTrue(r.compareTo(new Range(-2000, -1000)) < 0);// inside
		assertTrue(r.compareTo(new Range(77, 77)) < 0);// after
		assertTrue(r.compareTo(new Range(2, Integer.MAX_VALUE)) < 0);// after
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 333)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 2)) == 0);// overlap max
		assertTrue(r.compareTo(new Range(-555, 99)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(1, Integer.MAX_VALUE)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1)) == 0);// endAtMax
		assertTrue(r.compareTo(new Range(-88, 1)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(1, 1)) < 0);// endAtMax

		r = new Range(-1, Integer.MAX_VALUE);
		assertTrue(r.compareTo(new Range(-1, Integer.MAX_VALUE)) == 0);// same
		assertTrue(r.compareTo(new Range(0, 500)) < 0);// inside
		assertTrue(r.compareTo(new Range(1234, 4567)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -2)) > 0);// before
		assertTrue(r.compareTo(new Range(-13, -13)) > 0);// before
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE - 1)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-99, -1)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-203, 555)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-1, -1)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-1, 55)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-1, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-15, Integer.MAX_VALUE)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(0, Integer.MAX_VALUE)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(Integer.MAX_VALUE, Integer.MAX_VALUE)) < 0);// endAtMax

		r = new Range(-200, 200);
		assertTrue(r.compareTo(new Range(-200, 200)) == 0);// same
		assertTrue(r.compareTo(new Range(-190, -180)) < 0);// inside
		assertTrue(r.compareTo(new Range(-20, 34)) < 0);// inside
		assertTrue(r.compareTo(new Range(150, 185)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) > 0);// around
		assertTrue(r.compareTo(new Range(-201, 201)) > 0);// around
		assertTrue(r.compareTo(new Range(-999, 999)) > 0);// around
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -201)) > 0);// before
		assertTrue(r.compareTo(new Range(-987, -986)) > 0);// before
		assertTrue(r.compareTo(new Range(333, 555)) < 0);// after
		assertTrue(r.compareTo(new Range(201, Integer.MAX_VALUE)) < 0);// after
		assertTrue(r.compareTo(new Range(-201, -200)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-999, 111)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-301, 55)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-200, -200)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-200, 0)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-200, 5)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-200, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-100, 400)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(200, 201)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 200)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(-88, 200)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(0, 200)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(88, 200)) < 0);// endAtMax
		assertTrue(r.compareTo(new Range(200, 200)) < 0);// endAtMax

		r = new Range(-3000, -1950);
		assertTrue(r.compareTo(new Range(-3000, -1950)) == 0);// same
		assertTrue(r.compareTo(new Range(-2500, -2000)) < 0);// inside
		assertTrue(r.compareTo(new Range(-2999, -1951)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) > 0);// around
		assertTrue(r.compareTo(new Range(-3001, -1949)) > 0);// around
		assertTrue(r.compareTo(new Range(-5555, 999)) > 0);// around
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -3001)) > 0);// before
		assertTrue(r.compareTo(new Range(-5234, -4933)) > 0);// before
		assertTrue(r.compareTo(new Range(-1700, -499)) < 0);// after
		assertTrue(r.compareTo(new Range(0, 0)) < 0);// after
		assertTrue(r.compareTo(new Range(-22, 33)) < 0);// after
		assertTrue(r.compareTo(new Range(600, 600)) < 0);// after
		assertTrue(r.compareTo(new Range(-1949, Integer.MAX_VALUE)) < 0);// after
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -3000)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-3001, -2000)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(-3000, -3000)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-3000, -2000)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-3000, 0)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-3000, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(-3000, -1949)) == 0);// overlap max
		assertTrue(r.compareTo(new Range(-2222, 0)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(-1950, Integer.MAX_VALUE)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, -1950)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(-3333, -1950)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(-1950, -1950)) < 0);// endAtMax

		r = new Range(1746, 2334);
		assertTrue(r.compareTo(new Range(1746, 2334)) == 0);// same
		assertTrue(r.compareTo(new Range(1000, 1500)) > 0);// inside
		assertTrue(r.compareTo(new Range(1747, 2333)) < 0);// inside
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, Integer.MAX_VALUE)) > 0);// around
		assertTrue(r.compareTo(new Range(1745, 2335)) > 0);// around
		assertTrue(r.compareTo(new Range(-999, 3000)) > 0);// around
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1745)) > 0);// before
		assertTrue(r.compareTo(new Range(-9999, -9999)) > 0);// before
		assertTrue(r.compareTo(new Range(0, 0)) > 0);// before
		assertTrue(r.compareTo(new Range(-15, -15)) > 0);// before
		assertTrue(r.compareTo(new Range(345, 456)) > 0);// before
		assertTrue(r.compareTo(new Range(3333, 4444)) < 0);// after
		assertTrue(r.compareTo(new Range(2335, Integer.MAX_VALUE)) < 0);// after
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 1746)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(33, 2000)) > 0);// overlap min
		assertTrue(r.compareTo(new Range(1746, 1746)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(1746, 9999)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(1746, Integer.MAX_VALUE)) == 0);// startAtMin
		assertTrue(r.compareTo(new Range(1746, 2335)) == 0);// overlap max
		assertTrue(r.compareTo(new Range(1900, 4444)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(2334, Integer.MAX_VALUE)) < 0);// overlap max
		assertTrue(r.compareTo(new Range(Integer.MIN_VALUE, 2334)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(-88, 2334)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(0, 2334)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(88, 2334)) > 0);// endAtMax
		assertTrue(r.compareTo(new Range(2334, 2334)) < 0);// endAtMax

	}

	/*
	 * Class under test for boolean equals(Object)
	 */
	@Test
	public void testEqualsObject() {
		Range r1;
		Range r2;
		for (int i = 0; i < goodPairs.length; i++) {
			int[] pair = goodPairs[i];
			int min = pair[0];
			int max = pair[1];
			r1 = new Range(min, max);
			r2 = new Range(min, max);
			assertEquals("Range equals() failed for " + r1.toString() + ".", r1, r2);
		}
	}

	/*
	 * Class under test for String toString()
	 */
	@Test
	public void testToString() {
		Range r;
		for (int i = 0; i < goodPairs.length; i++) {
			int[] pair = goodPairs[i];
			int min = pair[0];
			int max = pair[1];
			r = new Range(min, max);
			assertEquals("(" + min + "," + max + ")", r.toString());
		}
	}

	@Test
	public void testContains() {
		Range r;
		r = new Range(Integer.MIN_VALUE, Integer.MAX_VALUE);
		assertEquals(true, r.contains(Integer.MIN_VALUE));
		assertEquals(true, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(true, r.contains(-1000));
		assertEquals(true, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(true, r.contains(1));
		assertEquals(true, r.contains(1000));
		assertEquals(true, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(true, r.contains(Integer.MAX_VALUE));

		r = new Range(Integer.MIN_VALUE, Integer.MIN_VALUE);
		assertEquals(true, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-1));
		assertEquals(false, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(Integer.MAX_VALUE, Integer.MAX_VALUE);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-1));
		assertEquals(false, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(true, r.contains(Integer.MAX_VALUE));

		r = new Range(0, Integer.MAX_VALUE);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(true, r.contains(1));
		assertEquals(true, r.contains(1000));
		assertEquals(true, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(true, r.contains(Integer.MAX_VALUE));

		r = new Range(Integer.MIN_VALUE, 0);
		assertEquals(true, r.contains(Integer.MIN_VALUE));
		assertEquals(true, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(true, r.contains(-1000));
		assertEquals(true, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(0, 0);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(Integer.MIN_VALUE, -1);
		assertEquals(true, r.contains(Integer.MIN_VALUE));
		assertEquals(true, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(true, r.contains(-1000));
		assertEquals(true, r.contains(-1));
		assertEquals(false, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(1, Integer.MAX_VALUE);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-1));
		assertEquals(false, r.contains(0));
		assertEquals(true, r.contains(1));
		assertEquals(true, r.contains(1000));
		assertEquals(true, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(true, r.contains(Integer.MAX_VALUE));

		r = new Range(Integer.MIN_VALUE, 1);
		assertEquals(true, r.contains(Integer.MIN_VALUE));
		assertEquals(true, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(true, r.contains(-1000));
		assertEquals(true, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(true, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(-1, Integer.MAX_VALUE);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(true, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(true, r.contains(1));
		assertEquals(true, r.contains(1000));
		assertEquals(true, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(true, r.contains(Integer.MAX_VALUE));

		r = new Range(-200, 200);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-201));
		assertEquals(true, r.contains(-200));
		assertEquals(true, r.contains(-199));
		assertEquals(true, r.contains(-1));
		assertEquals(true, r.contains(0));
		assertEquals(true, r.contains(1));
		assertEquals(true, r.contains(199));
		assertEquals(true, r.contains(200));
		assertEquals(false, r.contains(201));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(-3000, -1950);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-3001));
		assertEquals(true, r.contains(-3000));
		assertEquals(true, r.contains(-2999));
		assertEquals(true, r.contains(-1951));
		assertEquals(true, r.contains(-1950));
		assertEquals(false, r.contains(-1949));
		assertEquals(false, r.contains(-1));
		assertEquals(false, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

		r = new Range(1746, 2334);
		assertEquals(false, r.contains(Integer.MIN_VALUE));
		assertEquals(false, r.contains(Integer.MIN_VALUE + 1));
		assertEquals(false, r.contains(-1000));
		assertEquals(false, r.contains(-1));
		assertEquals(false, r.contains(0));
		assertEquals(false, r.contains(1));
		assertEquals(false, r.contains(1745));
		assertEquals(true, r.contains(1746));
		assertEquals(true, r.contains(1747));
		assertEquals(true, r.contains(2333));
		assertEquals(true, r.contains(2334));
		assertEquals(false, r.contains(2335));
		assertEquals(false, r.contains(1000));
		assertEquals(false, r.contains(Integer.MAX_VALUE - 1));
		assertEquals(false, r.contains(Integer.MAX_VALUE));

	}

	@Test
	public void testSize() {
		Range r;
		// Valid construction
		for (int i = 0; i < goodPairs.length; i++) {
			int[] pair = goodPairs[i];
			int min = pair[0];
			int max = pair[1];
			r = new Range(min, max);
			assertEquals("Bad size for range " + r.toString(), ((long) max - (long) min + 1),
				r.size());
		}
	}

}
