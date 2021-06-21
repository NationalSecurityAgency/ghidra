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

public class IntersectionAddressSetViewTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Language toy;

	protected Address addr(long offset) {
		return toy.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
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
		toy = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID("Toy:BE:64:default"));
	}

	@Test
	public void testCounts() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertTrue(intersection.isEmpty());
		assertEquals(0, intersection.getNumAddresses());
		assertEquals(0, intersection.getNumAddressRanges());

		// Disjoint, connected
		intersection =
			new IntersectionAddressSetView(set(rng(0x0000, 0x0fff)), set(rng(0x1000, 0x1fff)));
		assertTrue(intersection.isEmpty());
		assertEquals(0, intersection.getNumAddresses());
		assertEquals(0, intersection.getNumAddressRanges());

		// One enclosed
		intersection =
			new IntersectionAddressSetView(set(rng(0x0000, 0x2fff)), set(rng(0x1000, 0x1fff)));
		assertFalse(intersection.isEmpty());
		assertEquals(0x1000, intersection.getNumAddresses());
		assertEquals(1, intersection.getNumAddressRanges());

		// Overlapping
		intersection =
			new IntersectionAddressSetView(set(rng(0x0000, 0x1fff)), set(rng(0x1000, 0x2fff)));
		assertFalse(intersection.isEmpty());
		assertEquals(0x1000, intersection.getNumAddresses());
		assertEquals(1, intersection.getNumAddressRanges());
	}

	@Test
	public void testContains() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertFalse(intersection.contains(addr(0x0800), addr(0x1800)));

		AddressSet a = set(rng(0x0000, 0x1fff));
		AddressSet b = set(rng(0x1000, 0x2fff));
		intersection = new IntersectionAddressSetView(a, b);
		assertFalse(intersection.contains(addr(0x0800)));
		assertTrue(intersection.contains(addr(0x1800)));
		assertFalse(intersection.contains(addr(0x2800)));
		assertFalse(intersection.contains(addr(0x3000)));
		assertTrue(intersection.contains(addr(0x1800), addr(0x1bff)));
		assertFalse(intersection.contains(addr(0x1800), addr(0x2bff)));
		assertFalse(intersection.contains(addr(0x0800), addr(0x1bff)));
		assertFalse(intersection.contains(addr(0x1fff), addr(0x2fff)));
		assertFalse(intersection.contains(addr(0x2000), addr(0x3000)));
		assertTrue(intersection.contains(set(rng(0x1200, 0x15ff), rng(0x1a00, 0x1dff))));
		assertFalse(intersection.contains(set(rng(0x0800, 0x15ff), rng(0x1a00, 0x1dff))));
		assertFalse(intersection.contains(set(rng(0x1200, 0x15ff), rng(0x1a00, 0x2000))));
	}

	@Test
	public void testEndpoints() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertNull(intersection.getMinAddress());
		assertNull(intersection.getMaxAddress());

		intersection =
			new IntersectionAddressSetView(set(rng(0x0000, 0x0fff)), set(rng(0x1000, 0x1fff)));
		assertNull(intersection.getMinAddress());
		assertNull(intersection.getMaxAddress());

		intersection =
			new IntersectionAddressSetView(set(rng(0x1000, 0x2fff)), set(rng(0x0000, 0x1fff)));
		assertEquals(addr(0x1000), intersection.getMinAddress());
		assertEquals(addr(0x1fff), intersection.getMaxAddress());

		intersection =
			new IntersectionAddressSetView(set(rng(0x1000, 0x1fff)), set(rng(0x0000, 0x2fff)));
		assertEquals(addr(0x1000), intersection.getMinAddress());
		assertEquals(addr(0x1fff), intersection.getMaxAddress());
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
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(set(rng(0x1000, 0x3fff)),
			set(rng(0x0000, 0x1fff), rng(0x3000, 0x4fff)));
		assertEquals(List.of(rng(0x1000, 0x1fff), rng(0x3000, 0x3fff)),
			collect(intersection.iterator(true)));
		assertEquals(List.of(rng(0x3fff, 0x3000), rng(0x1000, 0x1fff)),
			collect(intersection.iterator(false)));
		assertEquals(List.of(rng(0x1000, 0x1fff), rng(0x3000, 0x3fff)),
			collect(intersection.iterator(addr(0x0800), true)));
		assertEquals(List.of(), collect(intersection.iterator(addr(0x0800), false)));
		assertEquals(List.of(rng(0x1000, 0x1fff), rng(0x3000, 0x3fff)),
			collect(intersection.iterator(addr(0x1800), true)));
		assertEquals(List.of(rng(0x1000, 0x1fff)),
			collect(intersection.iterator(addr(0x1800), false)));
		assertEquals(List.of(), collect(intersection.iterator(addr(0x4fff), true)));
		assertEquals(List.of(rng(0x3000, 0x3fff), rng(0x1000, 0x1fff)),
			collect(intersection.iterator(addr(0x4fff), false)));

		AddressSet a = randomSet();
		AddressSet b = randomSet();
		try {
			intersection = new IntersectionAddressSetView(a, b);
			AddressSetView expected = a.intersect(b);
			assertEquals(collect(expected.getAddressRanges(true)),
				collect(intersection.iterator(true)));
			assertEquals(collect(expected.getAddressRanges(false)),
				collect(intersection.iterator(false)));
			assertEquals(collect(expected.getAddressRanges(addr(0x8000), true)),
				collect(intersection.iterator(addr(0x8000), true)));
			assertEquals(collect(expected.getAddressRanges(addr(0x8000), false)),
				collect(intersection.iterator(addr(0x8000), false)));
		}
		catch (AssertionError e) {
			System.out.println("Failing sets: ");
			System.out.println("  A: " + a);
			System.out.println("  B: " + b);
			throw e;
		}
	}

	@Test
	public void testGetAddresses() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertFalse(intersection.getAddresses(true).hasNext());
		assertFalse(intersection.getAddresses(false).hasNext());

		intersection =
			new IntersectionAddressSetView(set(rng(1, 3), rng(5, 9)), set(rng(2, 4), rng(6, 7)));
		assertEquals(addrs(2, 3, 6, 7), collect(intersection.getAddresses(true)));
		assertEquals(addrs(7, 6, 3, 2), collect(intersection.getAddresses(false)));
		assertEquals(addrs(3, 6, 7), collect(intersection.getAddresses(addr(3), true)));
		assertEquals(addrs(6, 7), collect(intersection.getAddresses(addr(5), true)));
		assertEquals(addrs(7, 6, 3, 2), collect(intersection.getAddresses(addr(8), false)));
		assertEquals(addrs(3, 2), collect(intersection.getAddresses(addr(5), false)));
	}

	@Test
	public void testGetRangeContaining() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertNull(intersection.getRangeContaining(addr(0x0800)));

		AddressSet a = set(rng(0x0000, 0x1fff), rng(0x4000, 0x4fff));
		AddressSet b = set(rng(0x1000, 0x2fff));
		intersection = new IntersectionAddressSetView(a, b);
		assertNull(intersection.getRangeContaining(addr(0x0000)));
		assertNull(intersection.getRangeContaining(addr(0x0800)));
		assertNull(intersection.getRangeContaining(addr(0x0fff)));
		assertEquals(rng(0x1000, 0x1fff), intersection.getRangeContaining(addr(0x1000)));
		assertEquals(rng(0x1000, 0x1fff), intersection.getRangeContaining(addr(0x1800)));
		assertEquals(rng(0x1000, 0x1fff), intersection.getRangeContaining(addr(0x1fff)));
		assertNull(intersection.getRangeContaining(addr(0x2000)));
		assertNull(intersection.getRangeContaining(addr(0x2800)));
		assertNull(intersection.getRangeContaining(addr(0x2fff)));
		assertNull(intersection.getRangeContaining(addr(0x3000)));
		assertNull(intersection.getRangeContaining(addr(0x4800)));
	}

	@Test
	public void testHasSameAddresses() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertTrue(intersection.hasSameAddresses(new AddressSet()));

		AddressSet a = set(rng(0x0000, 0x1fff));
		AddressSet b = set(rng(0x1000, 0x2fff));
		intersection = new IntersectionAddressSetView(a, b);
		assertFalse(intersection.hasSameAddresses(new AddressSet()));
		assertTrue(intersection.hasSameAddresses(set(rng(0x1000, 0x1fff))));
		assertFalse(intersection.hasSameAddresses(set(rng(0x0000, 0x1fff))));
		assertFalse(intersection.hasSameAddresses(set(rng(0x1000, 0x2fff))));
		assertFalse(intersection.hasSameAddresses(set(rng(0x1000, 0x1fff), rng(0x3000, 0x3fff))));
	}

	@Test
	public void testGetFirstLastRanges() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertNull(intersection.getFirstRange());
		assertNull(intersection.getLastRange());

		AddressSet a = set(rng(0x0000, 0x1fff), rng(0x3000, 0x4fff));
		AddressSet b = set(rng(0x1000, 0x3fff));
		intersection = new IntersectionAddressSetView(a, b);
		assertEquals(rng(0x1000, 0x1fff), intersection.getFirstRange());
		assertEquals(rng(0x3000, 0x3fff), intersection.getLastRange());
	}

	@Test
	public void testIntersect() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertFalse(intersection.intersects(addr(0x1000), addr(0x1fff)));
		assertEquals(new AddressSet(), intersection.intersectRange(addr(0x1000), addr(0x1fff)));

		AddressSet a = set(rng(0x0000, 0x1fff), rng(0x3000, 0x4fff));
		AddressSet b = set(rng(0x1000, 0x3fff));
		intersection = new IntersectionAddressSetView(a, b);
		assertFalse(intersection.intersects(addr(0x0000), addr(0x00ff)));
		assertEquals(new AddressSet(), intersection.intersectRange(addr(0x0000), addr(0x00ff)));

		assertFalse(intersection.intersects(addr(0x5000), addr(0x5fff)));
		assertEquals(new AddressSet(), intersection.intersectRange(addr(0x5000), addr(0x5fff)));

		assertTrue(intersection.intersects(addr(0x0000), addr(0x1fff)));
		assertEquals(set(rng(0x1000, 0x1fff)),
			intersection.intersectRange(addr(0x0000), addr(0x1fff)));

		assertTrue(intersection.intersects(addr(0x1800), addr(0x37ff)));
		assertEquals(set(rng(0x1800, 0x1fff), rng(0x3000, 0x37ff)),
			intersection.intersectRange(addr(0x1800), addr(0x37ff)));
	}

	@Test
	public void testUnion() {
		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		AddressSetView intersection = new IntersectionAddressSetView(a, b);
		assertEquals(set(rng(0x0000, 0x1fff)), intersection.union(set(rng(0x0000, 0x1fff))));
	}

	@Test
	public void testSubtract() {
		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		AddressSetView intersection = new IntersectionAddressSetView(a, b);
		assertEquals(set(rng(0x1000, 0x13ff), rng(0x1c00, 0x1fff)),
			intersection.subtract(set(rng(0x1400, 0x1bff))));
	}

	@Test
	public void testXor() {
		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		AddressSetView intersection = new IntersectionAddressSetView(a, b);
		assertEquals(set(rng(0x0000, 0x0fff)), intersection.xor(set(rng(0x0000, 0x1fff))));
	}

	@Test
	public void testFindFirstAddressInCommon() {
		AddressSetView intersection;

		intersection = new IntersectionAddressSetView(new AddressSet(), new AddressSet());
		assertNull(intersection.findFirstAddressInCommon(set(rng(0x1000, 0x1fff))));

		AddressSet a = set(rng(0x0000, 0x1fff));
		AddressSet b = set(rng(0x1000, 0x2fff));
		intersection = new IntersectionAddressSetView(a, b);
		assertNull(intersection.findFirstAddressInCommon(set(rng(0x0000, 0x0fff))));
		assertEquals(addr(0x1000), intersection.findFirstAddressInCommon(set(rng(0x0800, 0x1fff))));
		assertEquals(addr(0x1800), intersection.findFirstAddressInCommon(set(rng(0x1800, 0x3fff))));
	}
}
