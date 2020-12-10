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

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class UnionAddressSetViewTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Language toy;

	protected Address addr(long offset) {
		return toy.getDefaultSpace().getAddress(offset);
	}

	protected Address daddr(long offset) {
		return toy.getDefaultDataSpace().getAddress(offset);
	}

	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	protected AddressRange drng(long min, long max) {
		return new AddressRangeImpl(daddr(min), daddr(max));
	}

	protected AddressSet set(AddressRange... ranges) {
		AddressSet set = new AddressSet();
		for (AddressRange rng : ranges) {
			set.add(rng);
		}
		return set;
	}

	protected List<Address> addrs(long... offsets) {
		List<Address> result = new ArrayList<>(offsets.length);
		for (long off : offsets) {
			result.add(addr(off));
		}
		return result;
	}

	@Before
	public void setUpIteratorTest() throws LanguageNotFoundException {
		toy = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:harvard"));
	}

	@Test
	public void testCounts() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertTrue(union.isEmpty());
		assertEquals(0, union.getNumAddresses());
		assertEquals(0, union.getNumAddressRanges());

		union = new UnionAddressSetView(new AddressSet());
		assertTrue(union.isEmpty());
		assertEquals(0, union.getNumAddresses());
		assertEquals(0, union.getNumAddressRanges());

		AddressSet a = set(rng(0x0000, 0x0fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		union = new UnionAddressSetView(a, b);
		assertFalse(union.isEmpty());
		assertEquals(0x2000, union.getNumAddresses());
		assertEquals(1, union.getNumAddressRanges());
	}

	@Test
	public void testContains() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertFalse(union.contains(addr(0x0800)));
		assertFalse(union.contains(addr(0x0800), addr(0x1800)));

		union = new UnionAddressSetView(new AddressSet());
		assertFalse(union.contains(addr(0x0800), addr(0x1800)));

		AddressSet a = set(rng(0x0000, 0x0fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		union = new UnionAddressSetView(a, b);
		assertTrue(union.contains(addr(0x0800)));
		assertTrue(union.contains(addr(0x1800)));
		assertFalse(union.contains(addr(0x2800)));
		assertTrue(union.contains(addr(0x0800), addr(0x1800)));
		assertFalse(union.contains(addr(0x0800), addr(0x2800)));
		assertTrue(union.contains(set(rng(0x0800, 0x1800), rng(0x1900, 0x1fff))));
		assertFalse(union.contains(set(rng(0x0800, 0x1800), rng(0x1900, 0x2000))));
	}

	@Test
	public void testEndpoints() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertNull(union.getMinAddress());
		assertNull(union.getMaxAddress());

		union = new UnionAddressSetView(new AddressSet());
		assertNull(union.getMinAddress());
		assertNull(union.getMaxAddress());

		AddressSet a = set(rng(0x0000, 0x0fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		union = new UnionAddressSetView(a, b);
		assertEquals(addr(0x0000), union.getMinAddress());
		assertEquals(addr(0x1fff), union.getMaxAddress());
	}

	protected <T> List<T> collect(Iterator<T> it) {
		List<T> result = new ArrayList<>();
		while (it.hasNext()) {
			result.add(it.next());
		}
		return result;
	}

	protected AddressSet randomSet() {
		Random r = new Random();
		AddressSet result = new AddressSet();
		for (int i = 0; i < 20; i++) {
			int len = r.nextInt(0x7ff) + 1;
			int off = r.nextInt(0x10000 - len);
			result.add(rng(off, off + len - 1));
		}
		return result;
	}

	@Test
	public void testIterator() {
		AddressSetView union;

		union = new UnionAddressSetView(set(rng(0x0000, 0x0fff)), set(rng(0x1000, 0x1fff)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(false)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(addr(0x0800), true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(addr(0x0800), false)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(addr(0x1800), true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(addr(0x1800), false)));
		assertEquals(List.of(), collect(union.iterator(addr(0x2fff), true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(union.iterator(addr(0x2fff), false)));

		union = new UnionAddressSetView(set(rng(0x0000, 0x07ff)), set(rng(0x1000, 0x17ff)));
		assertEquals(List.of(rng(0x0000, 0x07ff), rng(0x1000, 0x17ff)),
			collect(union.iterator(true)));
		assertEquals(List.of(rng(0x1000, 0x17ff), rng(0x0000, 0x07ff)),
			collect(union.iterator(false)));

		union = new UnionAddressSetView(set(rng(0x80000000, 0xffff0fff)),
			set(rng(0xffff1000, 0xffffffff)));
		assertEquals(List.of(rng(0x80000000, 0xffffffff)), collect(union.iterator(true)));

		AddressSet a = randomSet();
		AddressSet b = randomSet();
		try {
			union = new UnionAddressSetView(a, b);
			AddressSetView expected = a.union(b);
			assertEquals(collect(expected.getAddressRanges(true)), collect(union.iterator(true)));
			assertEquals(collect(expected.getAddressRanges(false)), collect(union.iterator(false)));
			assertEquals(collect(expected.getAddressRanges(addr(0x8000), true)),
				collect(union.iterator(addr(0x8000), true)));
			assertEquals(collect(expected.getAddressRanges(addr(0x8000), false)),
				collect(union.iterator(addr(0x8000), false)));
		}
		catch (AssertionError e) {
			System.out.println("Failing sets: ");
			System.out.println("  A: " + a);
			System.out.println("  B: " + b);
			throw e;
		}
	}

	@Test
	public void testIteratorMultipleSpaces() {
		AddressSetView union;

		union = new UnionAddressSetView(set(rng(0x0000, 0x0fff)), set(drng(0x1000, 0x1fff)));
		assertEquals(List.of(rng(0x0000, 0x0fff), drng(0x1000, 0x1fff)),
			collect(union.iterator(true)));

		union =
			new UnionAddressSetView(set(rng(0x80000000, 0xffffffff)), set(drng(0x0000, 0x0fff)));
		assertEquals(List.of(rng(0x80000000, 0xffffffff), drng(0x0000, 0x0fff)),
			collect(union.iterator(true)));
	}

	@Test
	public void testGetAddresses() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertFalse(union.getAddresses(true).hasNext());
		assertFalse(union.getAddresses(false).hasNext());

		union = new UnionAddressSetView(new AddressSet());
		assertFalse(union.getAddresses(true).hasNext());
		assertFalse(union.getAddresses(false).hasNext());

		union = new UnionAddressSetView(set(rng(1, 3), rng(8, 9)), set(rng(2, 4), rng(6, 7)));
		assertEquals(addrs(1, 2, 3, 4, 6, 7, 8, 9), collect(union.getAddresses(true)));
		assertEquals(addrs(9, 8, 7, 6, 4, 3, 2, 1), collect(union.getAddresses(false)));
		assertEquals(addrs(3, 4, 6, 7, 8, 9), collect(union.getAddresses(addr(3), true)));
		assertEquals(addrs(6, 7, 8, 9), collect(union.getAddresses(addr(5), true)));
		assertEquals(addrs(8, 7, 6, 4, 3, 2, 1), collect(union.getAddresses(addr(8), false)));
		assertEquals(addrs(4, 3, 2, 1), collect(union.getAddresses(addr(5), false)));
	}

	@Test
	public void testGetRangeContaining() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertNull(union.getRangeContaining(addr(0x0800)));

		union = new UnionAddressSetView(new AddressSet());
		assertNull(union.getRangeContaining(addr(0x0800)));

		AddressSet a = set(rng(0x0100, 0x0fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		union = new UnionAddressSetView(a, b);
		assertNull(union.getRangeContaining(addr(0x0000)));
		assertNull(union.getRangeContaining(addr(0x0000)));
		assertNull(union.getRangeContaining(addr(0x00ff)));
		assertEquals(rng(0x0100, 0x1fff), union.getRangeContaining(addr(0x0100)));
		assertEquals(rng(0x0100, 0x1fff), union.getRangeContaining(addr(0x0800)));
		assertEquals(rng(0x0100, 0x1fff), union.getRangeContaining(addr(0x1fff)));
		assertNull(union.getRangeContaining(addr(0x2000)));
	}

	@Test
	public void testHasSameAddresses() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertTrue(union.hasSameAddresses(new AddressSet()));

		union = new UnionAddressSetView(new AddressSet());
		assertTrue(union.hasSameAddresses(new AddressSet()));

		AddressSet a = set(rng(0x0100, 0x0fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		union = new UnionAddressSetView(a, b);
		assertFalse(union.hasSameAddresses(new AddressSet()));
		assertTrue(union.hasSameAddresses(set(rng(0x0100, 0x1fff))));
		assertFalse(union.hasSameAddresses(set(rng(0x0000, 0x1fff))));
		assertFalse(union.hasSameAddresses(set(rng(0x0100, 0x2fff))));
		assertFalse(union.hasSameAddresses(set(rng(0x0100, 0x1fff), rng(0x3000, 0x3fff))));
	}

	@Test
	public void testGetFirstLastRanges() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertNull(union.getFirstRange());
		assertNull(union.getLastRange());

		union = new UnionAddressSetView(new AddressSet());
		assertNull(union.getFirstRange());
		assertNull(union.getLastRange());

		AddressSet a = set(rng(0x0100, 0x0fff), rng(0x3000, 0x3fff));
		AddressSet b = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		union = new UnionAddressSetView(a, b);
		assertEquals(rng(0x0100, 0x1fff), union.getFirstRange());
		assertEquals(rng(0x3000, 0x4fff), union.getLastRange());
	}

	@Test
	public void testIntersect() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertFalse(union.intersects(addr(0x1000), addr(0x1fff)));
		assertEquals(new AddressSet(), union.intersectRange(addr(0x1000), addr(0x1fff)));

		union = new UnionAddressSetView(new AddressSet());
		assertFalse(union.intersects(addr(0x1000), addr(0x1fff)));
		assertEquals(new AddressSet(), union.intersectRange(addr(0x1000), addr(0x1fff)));

		AddressSet a = set(rng(0x0100, 0x0fff), rng(0x3000, 0x3fff));
		AddressSet b = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		union = new UnionAddressSetView(a, b);
		assertFalse(union.intersects(addr(0x0000), addr(0x00ff)));
		assertEquals(new AddressSet(), union.intersectRange(addr(0x0000), addr(0x00ff)));
		assertFalse(union.intersects(addr(0x5000), addr(0x5fff)));
		assertEquals(new AddressSet(), union.intersectRange(addr(0x5000), addr(0x5fff)));
		assertTrue(union.intersects(addr(0x0000), addr(0x0fff)));
		assertEquals(set(rng(0x0100, 0x0fff)), union.intersectRange(addr(0x0000), addr(0x0fff)));
		assertTrue(union.intersects(addr(0x4000), addr(0x5fff)));
		assertEquals(set(rng(0x4000, 0x4fff)), union.intersectRange(addr(0x4000), addr(0x4fff)));
	}

	@Test
	public void testUnion() {
		AddressSet a = set(rng(0x0100, 0x0fff), rng(0x3000, 0x3fff));
		AddressSet b = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		AddressSetView union = new UnionAddressSetView(a, b);
		assertEquals(set(rng(0x0100, 0x4fff)), union.union(set(rng(0x2000, 0x2fff))));
	}

	@Test
	public void testSubtract() {
		AddressSet a = set(rng(0x0100, 0x0fff), rng(0x3000, 0x3fff));
		AddressSet b = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		AddressSetView union = new UnionAddressSetView(a, b);
		assertEquals(set(rng(0x0100, 0x17ff), rng(0x3800, 0x4fff)),
			union.subtract(set(rng(0x1800, 0x37ff))));
	}

	@Test
	public void testXor() {
		AddressSet a = set(rng(0x0100, 0x0fff), rng(0x3000, 0x3fff));
		AddressSet b = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		AddressSetView union = new UnionAddressSetView(a, b);
		assertEquals(set(rng(0x0100, 0x17ff), rng(0x2000, 0x2fff), rng(0x3800, 0x4fff)),
			union.xor(set(rng(0x1800, 0x37ff))));
	}

	@Test
	public void testFindFirstAddressInCommon() {
		AddressSetView union;

		union = new UnionAddressSetView();
		assertNull(union.findFirstAddressInCommon(set(rng(0x1000, 0x1fff))));

		union = new UnionAddressSetView(new AddressSet());
		assertNull(union.findFirstAddressInCommon(set(rng(0x1000, 0x1fff))));

		AddressSet a = set(rng(0x0100, 0x0fff), rng(0x3000, 0x3fff));
		AddressSet b = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		union = new UnionAddressSetView(a, b);
		assertNull(union.findFirstAddressInCommon(set(rng(0x2000, 0x2fff))));
		assertEquals(addr(0x0800), union.findFirstAddressInCommon(set(rng(0x0800, 0x1fff))));
		assertEquals(addr(0x3000), union.findFirstAddressInCommon(set(rng(0x2000, 0x37ff))));
	}
}
