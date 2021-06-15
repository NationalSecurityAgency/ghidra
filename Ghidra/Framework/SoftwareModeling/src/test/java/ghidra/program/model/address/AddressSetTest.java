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
package ghidra.program.model.address;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class AddressSetTest extends AbstractGenericTest {
	private AddressSpace space;
	private AddressSpace space2;
	private AddressSpace space3;
	private AddressFactory factory;
	private final int SIZE = 23;

	private AddressSet[] a = new AddressSet[SIZE];
	private AddressSet[] b = new AddressSet[SIZE];
	private AddressSet[] aUNIONb = new AddressSet[SIZE];
	private AddressSet[] aINTERSECTb = new AddressSet[SIZE];
	private AddressSet[] aINTERSECTbR = new AddressSet[SIZE];
	private AddressSet[] aMINUSb = new AddressSet[SIZE];
	private AddressSet[] aXORb = new AddressSet[SIZE];
	private boolean[] aCONTAINSb = new boolean[SIZE];

	@Before
	public void setUp() throws Exception {

		space = new GenericAddressSpace("xx", 32, AddressSpace.TYPE_RAM, 0);
		space2 = new GenericAddressSpace("xx1", 32, AddressSpace.TYPE_RAM, 2);
		space3 = new GenericAddressSpace("xx2", 32, AddressSpace.TYPE_RAM, 3);
		factory = new DefaultAddressFactory(new AddressSpace[] { space, space2, space3 });
		space = factory.getAddressSpace(space.getName());
		space2 = factory.getAddressSpace(space2.getName());
		space3 = factory.getAddressSpace(space3.getName());

		int idx = 0;

		// case 0: A is completely before B
		a[idx] = set(10, 20);
		b[idx] = set(30, 40);
		aUNIONb[idx] = set(10, 20, 30, 40);
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set(10, 20);
		aXORb[idx] = set(10, 20, 30, 40);
		aCONTAINSb[idx] = false;
		++idx;

		// case 1: B is completely before A
		a[idx] = set(30, 40);
		b[idx] = set(10, 20);
		aUNIONb[idx] = set(10, 20, 30, 40);
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set(30, 40);
		aXORb[idx] = set(10, 20, 30, 40);
		aCONTAINSb[idx] = false;
		++idx;

		// case 2: B overlaps the 2nd half of A
		a[idx] = set(30, 50);
		b[idx] = set(40, 60);
		aUNIONb[idx] = set(30, 60);
		aINTERSECTb[idx] = set(40, 50);
		aINTERSECTbR[idx] = set(40, 50);
		aMINUSb[idx] = set(30, 39);
		aXORb[idx] = set(30, 39, 51, 60);
		aCONTAINSb[idx] = false;
		++idx;

		// case 3: A overlaps the 2nd half of B
		a[idx] = set(40, 60);
		b[idx] = set(30, 50);
		aUNIONb[idx] = set(30, 60);
		aINTERSECTb[idx] = set(40, 50);
		aINTERSECTbR[idx] = set(40, 50);
		aMINUSb[idx] = set(51, 60);
		aXORb[idx] = set(30, 39, 51, 60);
		aCONTAINSb[idx] = false;
		++idx;

		// case 4: B is wholly contained in A
		a[idx] = set(30, 60);
		b[idx] = set(40, 50);
		aUNIONb[idx] = set(30, 60);
		aINTERSECTb[idx] = set(40, 50);
		aINTERSECTbR[idx] = set(40, 50);
		aMINUSb[idx] = set(30, 39, 51, 60);
		aXORb[idx] = set(30, 39, 51, 60);
		aCONTAINSb[idx] = true;
		++idx;

		// case 5: A is wholly contained in B
		a[idx] = set(10, 30);
		b[idx] = set(0, 50);
		aUNIONb[idx] = set(0, 50);
		aINTERSECTb[idx] = set(10, 30);
		aINTERSECTbR[idx] = set(10, 30);
		aMINUSb[idx] = set();
		aXORb[idx] = set(0, 9, 31, 50);
		aCONTAINSb[idx] = false;
		++idx;

		// case 6: B has two ranges, both of which are wholly contained in A
		a[idx] = set(10, 90);
		b[idx] = set(10, 50, 70, 80);
		aUNIONb[idx] = set(10, 90);
		aINTERSECTb[idx] = set(10, 50, 70, 80);
		aINTERSECTbR[idx] = set(10, 50);
		aMINUSb[idx] = set(51, 69, 81, 90);
		aXORb[idx] = set(51, 69, 81, 90);
		aCONTAINSb[idx] = true;
		++idx;

		// case 7: A has two ranges, B has two ranges, one in each of A's ranges
		a[idx] = set(10, 40, 60, 90);
		b[idx] = set(30, 40, 60, 90);
		aUNIONb[idx] = set(10, 40, 60, 90);
		aINTERSECTb[idx] = set(30, 40, 60, 90);
		aINTERSECTbR[idx] = set(30, 40);
		aMINUSb[idx] = set(10, 29);
		aXORb[idx] = set(10, 29);
		aCONTAINSb[idx] = true;
		++idx;

		// case 8: A has two ranges, B has one range which overlaps both of A's
		a[idx] = set(10, 40, 60, 90);
		b[idx] = set(30, 70);
		aUNIONb[idx] = set(10, 90);
		aINTERSECTb[idx] = set(30, 40, 60, 70);
		aINTERSECTbR[idx] = set(30, 40, 60, 70);
		aMINUSb[idx] = set(10, 29, 71, 90);
		aXORb[idx] = set(10, 29, 41, 59, 71, 90);
		aCONTAINSb[idx] = false;
		++idx;

		// case 9:
		a[idx] = set(20, 70, 80, 90);
		b[idx] = set(10, 30, 50, 60);
		aUNIONb[idx] = set(10, 70, 80, 90);
		aINTERSECTb[idx] = set(20, 30, 50, 60);
		aINTERSECTbR[idx] = set(20, 30);
		aMINUSb[idx] = set(31, 49, 61, 70, 80, 90);
		aXORb[idx] = set(10, 19, 31, 49, 61, 70, 80, 90);
		aCONTAINSb[idx] = false;
		++idx;

		// case 10:
		a[idx] = set(10, 80);
		b[idx] = set(20, 30, 50, 60, 70, 90);
		aUNIONb[idx] = set(10, 90);
		aINTERSECTb[idx] = set(20, 30, 50, 60, 70, 80);
		aINTERSECTbR[idx] = set(20, 30);
		aMINUSb[idx] = set(10, 19, 31, 49, 61, 69);
		aXORb[idx] = set(10, 19, 31, 49, 61, 69, 81, 90);
		aCONTAINSb[idx] = false;
		++idx;

		// case 11:
		a[idx] = set(20, 30, 40, 50, 60, 70);
		b[idx] = set(10, 80);
		aUNIONb[idx] = set(10, 80);
		aINTERSECTb[idx] = set(20, 30, 40, 50, 60, 70);
		aINTERSECTbR[idx] = set(20, 30, 40, 50, 60, 70);
		aMINUSb[idx] = set();
		aXORb[idx] = set(10, 19, 31, 39, 51, 59, 71, 80);
		aCONTAINSb[idx] = false;
		++idx;

		// case 12:
		a[idx] = set(10, 20, 30, 40, 50, 60, 70, 80, 90, 100);
		b[idx] = set(33, 38, 55, 75, 110, 120);
		aUNIONb[idx] = set(10, 20, 30, 40, 50, 80, 90, 100, 110, 120);
		aINTERSECTb[idx] = set(33, 38, 55, 60, 70, 75);
		aINTERSECTbR[idx] = set(33, 38);
		aMINUSb[idx] = set(10, 20, 30, 32, 39, 40, 50, 54, 76, 80, 90, 100);
		aXORb[idx] = set(10, 20, 30, 32, 39, 40, 50, 54, 61, 69, 76, 80, 90, 100, 110, 120);
		aCONTAINSb[idx] = false;
		++idx;

		// case 13:
		a[idx] = set(0, 30, 40, 50, 60, 70, 80, 90, 100, 110);
		b[idx] = set(5, 10, 15, 20, 40, 45, 50, 65, 73, 78, 95, 115);
		aUNIONb[idx] = set(0, 30, 40, 70, 73, 78, 80, 90, 95, 115);
		aINTERSECTb[idx] = set(5, 10, 15, 20, 40, 45, 50, 50, 60, 65, 100, 110);
		aINTERSECTbR[idx] = set(5, 10);
		aMINUSb[idx] = set(0, 4, 11, 14, 21, 30, 46, 49, 66, 70, 80, 90);
		aXORb[idx] =
			set(0, 4, 11, 14, 21, 30, 46, 49, 51, 59, 66, 70, 73, 78, 80, 90, 95, 99, 111, 115);
		aCONTAINSb[idx] = false;
		++idx;

		// case 14: to test linear contains
		a[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110);
		b[idx] = set(2, 3, 5, 7, 40, 45, 85, 90, 100, 102, 104, 110);
		aUNIONb[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110);
		aINTERSECTb[idx] = set(2, 3, 5, 7, 40, 45, 85, 90, 100, 102, 104, 110);
		aINTERSECTbR[idx] = set(2, 3);
		aMINUSb[idx] = set(0, 1, 4, 4, 8, 10, 20, 30, 46, 50, 60, 70, 80, 84, 103, 103);
		aXORb[idx] = set(0, 1, 4, 4, 8, 10, 20, 30, 46, 50, 60, 70, 80, 84, 103, 103);
		aCONTAINSb[idx] = true;
		++idx;

		// case 15: to test linear contains that fails
		a[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110);
		b[idx] = set(2, 3, 5, 7, 40, 45, 85, 95, 100, 102, 104, 110);
		aUNIONb[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 95, 100, 110);
		aINTERSECTb[idx] = set(2, 3, 5, 7, 40, 45, 85, 90, 100, 102, 104, 110);
		aINTERSECTbR[idx] = set(2, 3);
		aMINUSb[idx] = set(0, 1, 4, 4, 8, 10, 20, 30, 46, 50, 60, 70, 80, 84, 103, 103);
		aXORb[idx] = set(0, 1, 4, 4, 8, 10, 20, 30, 46, 50, 60, 70, 80, 84, 91, 95, 103, 103);
		aCONTAINSb[idx] = false;
		++idx;

		// case 16:
		a[idx] = set();
		b[idx] = set();
		aUNIONb[idx] = set();
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set();
		aXORb[idx] = set();
		aCONTAINSb[idx] = true;
		++idx;

		// case 17:
		a[idx] = set(10, 40);
		b[idx] = set();
		aUNIONb[idx] = set(10, 40);
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set(10, 40);
		aXORb[idx] = set(10, 40);
		aCONTAINSb[idx] = true;
		++idx;

		// case 18:
		a[idx] = set();
		b[idx] = set(10, 40);
		aUNIONb[idx] = set(10, 40);
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set();
		aXORb[idx] = set(10, 40);
		aCONTAINSb[idx] = false;
		++idx;

		// case 19:
		a[idx] = set(0x40, 0x50, 0x120, 0x130);
		b[idx] = set(0x10, 0x20, 0x90, 0x100);
		aUNIONb[idx] = set(0x10, 0x20, 0x40, 0x50, 0x90, 0x100, 0x120, 0x130);
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set(0x40, 0x50, 0x120, 0x130);
		aXORb[idx] = set(0x10, 0x20, 0x40, 0x50, 0x90, 0x100, 0x120, 0x130);
		aCONTAINSb[idx] = false;
		++idx;

		// case 20:
		a[idx] = set(0x10, 0x20, 0x30, 0x40, 0x60, 0x70);
		b[idx] = set(0x30, 0x45, 0x55, 0x70);
		aUNIONb[idx] = set(0x10, 0x20, 0x30, 0x45, 0x55, 0x70);
		aINTERSECTb[idx] = set(0x30, 0x40, 0x60, 0x70);
		aINTERSECTbR[idx] = set(0x30, 0x40);
		aMINUSb[idx] = set(0x10, 0x20);
		aXORb[idx] = set(0x10, 0x20, 0x41, 0x45, 0x55, 0x5f);
		aCONTAINSb[idx] = false;
		++idx;

		// case 21:
		a[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90);
		b[idx] = set(100, 110, 120, 130, 140, 150, 160, 170, 180, 190);
		aUNIONb[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
			170, 180, 190);
		aINTERSECTb[idx] = set();
		aINTERSECTbR[idx] = set();
		aMINUSb[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90);
		aXORb[idx] = set(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160,
			170, 180, 190);
		aCONTAINSb[idx] = false;
		++idx;

		// case 22
		a[idx] = set(30, 40, 10, 20);
		b[idx] = set(35, 36);
		aUNIONb[idx] = set(10, 20, 30, 40);
		aINTERSECTb[idx] = set(35, 36);
		aINTERSECTbR[idx] = set(35, 36);
		aMINUSb[idx] = set(10, 20, 30, 34, 37, 40);
		aXORb[idx] = set(10, 20, 30, 34, 37, 40);
		aCONTAINSb[idx] = true;
		++idx;

	}

	@Test
	public void testBasicAddRange() {
		AddressSet mySet = new AddressSet();
		mySet.addRange(addr(5), addr(8));
		Assert.assertEquals(1, mySet.getNumAddressRanges());
		Assert.assertEquals(4, mySet.getNumAddresses());

	}

	@Test
	public void testAddTwoOverlappingRanges() {
		AddressSet mySet = new AddressSet();
		mySet.addRange(addr(5), addr(8));
		mySet.addRange(addr(7), addr(10));
		Assert.assertEquals(1, mySet.getNumAddressRanges());
		Assert.assertEquals(6, mySet.getNumAddresses());

	}

	@Test
	public void testAddInMissingRangeBetweenTwoRanges() {
		AddressSet mySet = new AddressSet();
		mySet.addRange(addr(5), addr(8));
		Assert.assertEquals(4, mySet.getNumAddresses());
		mySet.addRange(addr(11), addr(12));
		Assert.assertEquals(6, mySet.getNumAddresses());
		mySet.addRange(addr(9), addr(10));
		Assert.assertEquals(1, mySet.getNumAddressRanges());
		Assert.assertEquals(8, mySet.getNumAddresses());

	}

	@Test
	public void testAddRangeThatConsumesSeveralExistingRanges() {
		AddressSet mySet = new AddressSet();
		mySet.addRange(addr(5), addr(8));
		mySet.addRange(addr(11), addr(12));
		mySet.addRange(addr(1), addr(20));
		Assert.assertEquals(1, mySet.getNumAddressRanges());
		Assert.assertEquals(20, mySet.getNumAddresses());
	}

	@Test
	public void testUnion() {
		for (int i = 0; i < SIZE; ++i) {
			Assert.assertEquals("case: " + i + " ", aUNIONb[i], a[i].union(b[i]));
		}
	}

	@Test
	public void testAdd() {
		for (int i = 0; i < SIZE; ++i) {
			a[i].add(b[i]);
			Assert.assertEquals("case: " + i + " ", aUNIONb[i], a[i]);
		}
	}

	@Test
	public void testIntersect() {
		for (int i = 0; i < SIZE; ++i) {
			Assert.assertEquals("case: " + i + " ", aINTERSECTb[i], a[i].intersect(b[i]));
		}
	}

	@Test
	public void testIntersectRange() {
		for (int i = 0; i < SIZE; ++i) {
			if (b[i].getNumAddressRanges() == 0) {
				continue;
			}
			AddressRange bR = b[i].iterator().next();
			Assert.assertEquals("case: " + i + " ", aINTERSECTbR[i],
				a[i].intersectRange(bR.getMinAddress(), bR.getMaxAddress()));
		}
	}

	@Test
	public void testIntersects() {
		AddressSet empty = set();
		for (int i = 0; i < SIZE; i++) {
			boolean isEmpty = aINTERSECTb[i].equals(empty);
			Assert.assertEquals("case: " + i + " ", !isEmpty, a[i].intersects(b[i]));
		}
	}

	@Test
	public void testDelete() {
		for (int i = 0; i < SIZE; ++i) {
			a[i].delete(b[i]);
			Assert.assertEquals("case: " + i + " ", aMINUSb[i], a[i]);
		}
	}

	@Test
	public void testSubtract() {
		for (int i = 0; i < SIZE; ++i) {
			Assert.assertEquals("case: " + i + " ", aMINUSb[i], a[i].subtract(b[i]));
		}
	}

	@Test
	public void testXOR() {
		for (int i = 0; i < SIZE; ++i) {
			Assert.assertEquals("case: " + i + " ", aXORb[i], a[i].xor(b[i]));
		}
	}

	@Test
	public void testContainsSet() {
		for (int i = 0; i < SIZE; ++i) {
			Assert.assertEquals("case: " + i + " ", aCONTAINSb[i], a[i].contains(b[i]));
		}
	}

	@Test
	public void testContainsAddress() {
		AddressSet set = set(0x100, 0x109, 0x200, 0x205, 0x256, 0x258);

		assertTrue(!set.contains(addr(0x99)));
		assertTrue(set.contains(addr(0x100)));
		assertTrue(set.contains(addr(0x101)));
		assertTrue(set.contains(addr(0x108)));
		assertTrue(set.contains(addr(0x109)));
		assertTrue(!set.contains(addr(0x110)));
		assertTrue(!set.contains(addr(0x199)));
		assertTrue(set.contains(addr(0x200)));
		assertTrue(set.contains(addr(0x201)));
		assertTrue(set.contains(addr(0x257)));
		assertTrue(set.contains(addr(0x258)));
		assertTrue(!set.contains(addr(0x259)));
	}

	@Test
	public void testContainsRange() {
		AddressSet set = set(0x100, 0x109, 0x200, 0x205, 0x256, 0x258);
		assertTrue(!set.contains(addr(0x50), addr(0x200)));
		assertTrue(set.contains(addr(0x100), addr(0x109)));
		assertTrue(set.contains(addr(0x101), addr(0x108)));
	}

	@Test
	public void testAddSucessiveRanges() {
		AddressSet set = set();
		set.addRange(addr(0x10), addr(0x20));
		set.addRange(addr(0x21), addr(0x30));
		Assert.assertEquals(1, set.getNumAddressRanges());
	}

	@Test
	public void testSpecialHandlingWhenLastRangeIsRemoved() {
		// addressSet has optimization code for adding in consecutive ranges, but has
		// to be careful that the "lastNode" variable is not stale.
		AddressSet set = set();
		set.addRange(addr(0x10), addr(0x20));
		set.deleteRange(addr(0x10), addr(0x10));
		set.addRange(addr(0x21), addr(0x30));
		Assert.assertEquals(1, set.getNumAddressRanges());

	}

	@Test
	public void testAddNullSet() {
		AddressSet set = set();
		set.add((AddressRange) null);
		set.add((AddressSet) null);
	}

	@Test
	public void testClear() {
		AddressSet set = set(0x100, 0x109, 0x200, 0x205, 0x256, 0x258);
		Assert.assertEquals(3, set.getNumAddressRanges());
		set.clear();
		Assert.assertEquals(0, set.getNumAddressRanges());
	}

	@Test
	public void testAddressIterator() {
		AddressSet set = new AddressSet();
		AddressIterator iter = set.getAddresses(true);
		assertTrue(!iter.hasNext());

		Address addr = addr(100);
		set = new AddressSet(addr);
		iter = set.getAddresses(true);
		assertTrue(iter.hasNext());
		Assert.assertEquals(addr, iter.next());
		assertTrue(!iter.hasNext());

		int[] addrs = new int[] { 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 200, 201, 202,
			203, 204, 205, 256, 257, 258 };
		set = set(100, 109, 200, 205, 256, 258);
		iter = set.getAddresses(true);
		for (int addr2 : addrs) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addr2), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testAddressIteratorAtEnd() {
		AddressSet set = set(10, 20);
		set.getAddresses(addr(20), true);
	}

	@Test
	public void testAddressIteratorStartAddressContained() {

		int[] addrs = new int[] { 0x202, 0x203, 0x204, 0x205, 0x256, 0x257, 0x258 };
		AddressSet set = set(0x100, 0x109, 0x200, 0x205, 0x256, 0x258);
		AddressIterator iter = set.getAddresses(addr(0x202), true);
		for (int addr : addrs) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addr), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testAddressIteratorStartAddressContainedInOnlyRange() {

		int[] addrs = new int[] { 0x108, 0x109 };
		AddressSet set = set(0x100, 0x109);
		AddressIterator iter = set.getAddresses(addr(0x108), true);
		for (int addr : addrs) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addr), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testEmptySet() {
		AddressSet set = set();
		assertNull(set.getMinAddress());
		assertNull(set.getMaxAddress());
	}

	@Test
	public void testAddressIteratorStartAddressNotContained() {

		int[] addrs = new int[] { 0x200, 0x201, 0x202, 0x203, 0x204, 0x205, 0x256, 0x257, 0x258 };
		AddressSet set = set(0x100, 0x109, 0x200, 0x205, 0x256, 0x258);
		AddressIterator iter = set.getAddresses(addr(0x150), true);
		for (int addr : addrs) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addr), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testBackwardAddressIterator() {
		AddressSet set = new AddressSet();
		AddressIterator iter = set.getAddresses(false);
		assertTrue(!iter.hasNext());

		Address addr = addr(100);
		set = new AddressSet(addr);
		iter = set.getAddresses(false);
		assertTrue(iter.hasNext());
		Assert.assertEquals(addr, iter.next());
		assertTrue(!iter.hasNext());

		int[] addrs = new int[] { 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 200, 201, 202,
			203, 204, 205, 256, 257, 258 };
		set = set(100, 109, 200, 205, 256, 258);
		iter = set.getAddresses(false);
		for (int i = addrs.length - 1; i >= 0; i--) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addrs[i]), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testBackwardsAddressIteratorStartAddressContained() {

		int[] addrs = new int[] { 0x202, 0x201, 0x200, 0x104, 0x103, 0x102, 0x101, 0x100 };
		AddressSet set = set(0x100, 0x104, 0x200, 0x205, 0x256, 0x258);
		AddressIterator iter = set.getAddresses(addr(0x202), false);
		for (int addr : addrs) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addr), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testBackwardsAddressIteratorStartAddressNotContained() {

		int[] addrs = new int[] { 0x104, 0x103, 0x102, 0x101, 0x100 };
		AddressSet set = set(0x100, 0x104, 0x200, 0x205, 0x256, 0x258);
		AddressIterator iter = set.getAddresses(addr(0x150), false);
		for (int addr : addrs) {
			assertTrue(iter.hasNext());
			Assert.assertEquals(addr(addr), iter.next());
		}
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testDeleteRangeAcrossAddresSpaces() {
		AddressSet set = set(0x10, 0x20);
		set.add(space2.getAddress(0x10), space2.getAddress(0x30));
		set.deleteRange(addr(0x15), space2.getAddress(0x20));
		Assert.assertEquals(21, set.getNumAddresses());

		set = new AddressSet(addr(0x10), addr(0x20));
		set.deleteRange(addr(0x15), space2.getAddress(0x20));
		Assert.assertEquals(5, set.getNumAddresses());
	}

	@Test
	public void testForwardRangeIteratorStartingInMiddle() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Iterator<AddressRange> it = set.iterator(addr(0x50), true);
		Assert.assertEquals(new AddressRangeImpl(addr(0x100), addr(0x110)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x200), addr(0x210)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x300), addr(0x305)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x105), true);
		Assert.assertEquals(new AddressRangeImpl(addr(0x100), addr(0x110)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x200), addr(0x210)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x300), addr(0x305)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x150), true);
		Assert.assertEquals(new AddressRangeImpl(addr(0x200), addr(0x210)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x300), addr(0x305)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x400), true);
		assertTrue(!it.hasNext());
	}

	@Test
	public void testBackwardRangeIteratorStartingInMiddle() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Iterator<AddressRange> it = set.iterator(addr(0x400), false);
		Assert.assertEquals(new AddressRangeImpl(addr(0x300), addr(0x305)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x200), addr(0x210)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x100), addr(0x110)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x304), false);
		Assert.assertEquals(new AddressRangeImpl(addr(0x300), addr(0x305)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x200), addr(0x210)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x100), addr(0x110)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x250), false);
		Assert.assertEquals(new AddressRangeImpl(addr(0x200), addr(0x210)), it.next());
		Assert.assertEquals(new AddressRangeImpl(addr(0x100), addr(0x110)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x100), false);
		Assert.assertEquals(new AddressRangeImpl(addr(0x100), addr(0x110)), it.next());
		assertTrue(!it.hasNext());

		it = set.iterator(addr(0x50), false);
		assertTrue(!it.hasNext());

	}

	@Test
	public void testBadAddRange() {
		AddressSet set = set();
		try {
			set.addRange(addr(10), addr(0));
			Assert.fail("Expected IllegalArgument Exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			set.addRange(addr(0), space2.getAddress(1));
			Assert.fail("Expected IllegalArgument Exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testAddingRangeThatSpansSpacesThrowsException() {
		AddressSet set = new AddressSet();
		try {
			set.add(new AddressRangeImpl(addr(0), space2.getAddress(1)));
			Assert.fail(
				"Expected Exception when adding range with start and end in different spaces.");
		}
		catch (IllegalArgumentException e) {
			//expected result
		}
	}

	@Test
	public void testConstructingAddressSetWithRange() {
		try {
			new AddressSet(new AddressRangeImpl(space.getAddress(0), space2.getAddress(0)));
			Assert.fail(
				"Expected Exception when adding range with start and end in different spaces.");
		}
		catch (IllegalArgumentException e) {
			//expected result
		}
	}

	@Test
	public void testHasSameAddresses() {
		AddressSet set1 = set(10, 20);
		AddressSet set2 = set(10, 20);
		AddressSet set3 = set(11, 20);

		assertTrue(set1.hasSameAddresses(set2));
		assertTrue(!set1.hasSameAddresses(set3));
	}

	@Test
	public void testEquals() {
		AddressSet set1 = set(10, 20);
		AddressSet set2 = set(10, 20);
		AddressSet set3 = set(11, 20);
		assertTrue(set1.equals(set2));
		assertTrue(!set1.equals(set3));
		assertTrue(!set1.equals(null));
		assertTrue(set1.equals(set1));
		assertTrue(!set1.equals(new Object()));
	}

	@Test
	public void testEqualsAndHashCode() {
		AddressSet set1 = set(10, 20);
		AddressSet set2 = set(10, 20);

		Assert.assertEquals(set1.hashCode(), set2.hashCode());
		Assert.assertEquals(0, set().hashCode());
	}

	@Test
	public void testForwardRangeIterator() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Iterator<AddressRange> it = set.iterator(true);
		Assert.assertEquals(range(0x100, 0x110), it.next());
		Assert.assertEquals(range(0x200, 0x210), it.next());
		Assert.assertEquals(range(0x300, 0x305), it.next());
		assertTrue(!it.hasNext());
	}

	@Test
	public void testBackwardRangeIterator() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Iterator<AddressRange> it = set.iterator(false);
		Assert.assertEquals(range(0x300, 0x305), it.next());
		Assert.assertEquals(range(0x200, 0x210), it.next());
		Assert.assertEquals(range(0x100, 0x110), it.next());
		assertTrue(!it.hasNext());
	}

	@Test
	public void testGetRangeContaining() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Assert.assertEquals(range(0x200, 0x210), set.getRangeContaining(addr(0x200)));
		Assert.assertEquals(range(0x200, 0x210), set.getRangeContaining(addr(0x201)));
		Assert.assertEquals(range(0x200, 0x210), set.getRangeContaining(addr(0x210)));
		assertNull(set.getRangeContaining(addr(0)));
	}

	@Test
	public void testGetFirstRange() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Assert.assertEquals(range(0x100, 0x110), set.getFirstRange());

		set = set();
		assertNull(set.getFirstRange());
	}

	@Test
	public void testGetLastRange() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		Assert.assertEquals(range(0x300, 0x305), set.getLastRange());
		set = set();
		assertNull(set.getLastRange());
	}

	@Test
	public void testSubtractEmptySet() {
		AddressSet set = set(0x100, 0x110, 0x200, 0x210, 0x300, 0x305);
		AddressSet emptySet = set();
		AddressSet newSet = set.subtract(emptySet);
		Assert.assertEquals(set, newSet);
	}

	@Test
	public void testTrimStart() {
		AddressSet set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		AddressSetView trimSet = AddressSetView.trimStart(set, addr(0x15));

		AddressSet expectedSet = set(0x16, 0x20, 0x30, 0x40);
		expectedSet.add(space2.getAddress(0x10), space2.getAddress(0x20));
		expectedSet.add(space2.getAddress(0x30), space2.getAddress(0x40));
		assertEquals(expectedSet, trimSet);

		trimSet = AddressSetView.trimStart(set, space2.getAddress(0x15));

		expectedSet = new AddressSet(space2.getAddress(0x16), space2.getAddress(0x20));
		expectedSet.add(space2.getAddress(0x30), space2.getAddress(0x40));
		assertEquals(expectedSet, trimSet);
	}

	@Test
	public void testdeleteFromMin() {
		AddressSet set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteFromMin(addr(0x15));

		AddressSet expectedSet = set(0x16, 0x20, 0x30, 0x40);
		expectedSet.add(space2.getAddress(0x10), space2.getAddress(0x20));
		expectedSet.add(space2.getAddress(0x30), space2.getAddress(0x40));
		assertEquals(expectedSet, set);

		set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteFromMin(space2.getAddress(0x15));

		expectedSet = new AddressSet(space2.getAddress(0x16), space2.getAddress(0x20));
		expectedSet.add(space2.getAddress(0x30), space2.getAddress(0x40));
		assertEquals(expectedSet, set);

		set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteFromMin(space2.getAddress(0x50));
		assertTrue(set.isEmpty());

		set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteFromMin(space2.getAddress(0x40));
		assertTrue(set.isEmpty());

		// make sure handles empty set
		set = new AddressSet();
		set.deleteFromMin(addr(0x30));
		assertTrue(set.isEmpty());
	}

	@Test
	public void testTrimEnd() {
		AddressSet set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		AddressSetView trimSet = AddressSetView.trimEnd(set, addr(0x15));

		AddressSet expectedSet = set(0x10, 0x14);
		assertEquals(expectedSet, trimSet);

		trimSet = AddressSetView.trimEnd(set, space2.getAddress(0x15));

		expectedSet = set(0x10, 0x20, 0x30, 0x40);
		expectedSet.add(space2.getAddress(0x10), space2.getAddress(0x14));
		assertEquals(expectedSet, trimSet);
	}

	@Test
	public void testDeleteFrom() {
		AddressSet set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		AddressSet origSet = new AddressSet(set);
		set.deleteToMax(space2.getAddress(0x50));
		assertEquals(origSet, set);

		set.deleteToMax(addr(0x15));

		AddressSet expectedSet = set(0x10, 0x14);
		assertEquals(expectedSet, set);

		set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteToMax(space2.getAddress(0x15));

		expectedSet = set(0x10, 0x20, 0x30, 0x40);
		expectedSet.add(space2.getAddress(0x10), space2.getAddress(0x14));
		assertEquals(expectedSet, set);

		set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteToMax(addr(0x0));
		assertTrue(set.isEmpty());

		set = set(0x10, 0x20, 0x30, 0x40);
		set.add(space2.getAddress(0x10), space2.getAddress(0x20));
		set.add(space2.getAddress(0x30), space2.getAddress(0x40));

		set.deleteToMax(addr(0x10));
		assertTrue(set.isEmpty());

		// make sure handles empty set
		set = new AddressSet();
		set.deleteToMax(addr(0x30));
		assertTrue(set.isEmpty());
	}

//
////
////	public void testSequentialInsertionSpeed() {
////		AddressSet set = set();
////		// first test coalescing addresses
////		// add a few so that it is non-trivial
////		set.add(range(0, 1));
////		set.add(range(3, 4));
////		set.add(range(7, 9));
////
////		Date start = new Date();
////		for (int i = 10; i < 10000000; i++) {
////			set.add(addr(i));
////		}
////		Date end = new Date();
////		System.out.println("time for 10,000,000 sequential coalescing adds: " +
////			(end.getTime() - start.getTime()));
////
////		// now test sequentail non-coalescing addresses
////		set.clear();
////		start = new Date();
////		for (int i = 10; i < 10000000; i++) {
////			set.add(addr(2 * i));
////		}
////		end = new Date();
////		System.out.println("time for 10,000,000 non-coalescing sequential adds: " +
////			(end.getTime() - start.getTime()));
////
////	}
//
//	public void testRandomInsertionSpeed() {
//		AddressSet set = set();
//
//		Date start = new Date();
//		for (int i = 10; i < 1000000; i++) {
//			int value = (int) (Integer.MAX_VALUE * Math.random());
//			set.add(addr(value));
//		}
//		Date end = new Date();
//		System.out.println("time for 1,000,000 random insertions: " +
//			(end.getTime() - start.getTime()));
//
//	}
//
//	public void testRandomAccessesOnRandomData() {
//		AddressSet set = set();
//
//		int maxAddress = 200000;
//		for (int i = 0; i < maxAddress / 2; i++) {
//			int value = (int) (maxAddress * Math.random());
//			set.add(addr(value));
//		}
//		int count = 0;
//		Date start = new Date();
//		for (int i = 0; i < 10000000; i++) {
//			int value = (int) (maxAddress * Math.random());
//			if (set.contains(addr(value))) {
//				count++;
//			}
//		}
//		Date end = new Date();
//		System.out.println("contains hit " + count);
//		System.out.println("time for 10,000,000 random lookups = " +
//			(end.getTime() - start.getTime()));
//
//	}

	private Address addr(int offset) {
		return new GenericAddress(space, offset);
	}

	private AddressRange range(int start, int end) {
		return new AddressRangeImpl(addr(start), addr(end));
	}

	private AddressSet set() {
		return new AddressSet();
	}

	private AddressSet set(int a, int b) {
		return new AddressSet(addr(a), addr(b));
	}

	private AddressSet set(int a, int b, int c, int d) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f, int g, int h) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		set.addRange(addr(g), addr(h));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		set.addRange(addr(g), addr(h));
		set.addRange(addr(i), addr(j));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j,
			int k, int l) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		set.addRange(addr(g), addr(h));
		set.addRange(addr(i), addr(j));
		set.addRange(addr(k), addr(l));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j,
			int k, int l, int m, int n, int o, int p) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		set.addRange(addr(g), addr(h));
		set.addRange(addr(i), addr(j));
		set.addRange(addr(k), addr(l));
		set.addRange(addr(m), addr(n));
		set.addRange(addr(o), addr(p));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j,
			int k, int l, int m, int n, int o, int p, int q, int r) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		set.addRange(addr(g), addr(h));
		set.addRange(addr(i), addr(j));
		set.addRange(addr(k), addr(l));
		set.addRange(addr(m), addr(n));
		set.addRange(addr(o), addr(p));
		set.addRange(addr(q), addr(r));
		return set;
	}

	private AddressSet set(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j,
			int k, int l, int m, int n, int o, int p, int q, int r, int s, int t) {
		AddressSet set = new AddressSet(addr(a), addr(b));
		set.addRange(addr(c), addr(d));
		set.addRange(addr(e), addr(f));
		set.addRange(addr(g), addr(h));
		set.addRange(addr(i), addr(j));
		set.addRange(addr(k), addr(l));
		set.addRange(addr(m), addr(n));
		set.addRange(addr(o), addr(p));
		set.addRange(addr(q), addr(r));
		set.addRange(addr(s), addr(t));
		return set;
	}
}
