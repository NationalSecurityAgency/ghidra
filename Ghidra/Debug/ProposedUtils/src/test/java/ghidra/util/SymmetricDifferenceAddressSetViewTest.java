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

public class SymmetricDifferenceAddressSetViewTest extends AbstractGhidraHeadlessIntegrationTest {
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
		AddressSetView xor;

		xor = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertTrue(xor.isEmpty());
		assertEquals(0, xor.getNumAddresses());
		assertEquals(0, xor.getNumAddressRanges());

		// Disjoint, connected
		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x0fff)),
			set(rng(0x1000, 0x1fff)));
		assertFalse(xor.isEmpty());
		assertEquals(0x2000, xor.getNumAddresses());
		assertEquals(1, xor.getNumAddressRanges());

		// Subtract from middle
		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x2fff)),
			set(rng(0x1000, 0x1fff)));
		assertFalse(xor.isEmpty());
		assertEquals(0x2000, xor.getNumAddresses());
		assertEquals(2, xor.getNumAddressRanges());

		// Reverse of above
		xor = new SymmetricDifferenceAddressSetView(set(rng(0x1000, 0x1fff)),
			set(rng(0x0000, 0x2fff)));
		assertFalse(xor.isEmpty());
		assertEquals(0x2000, xor.getNumAddresses());
		assertEquals(2, xor.getNumAddressRanges());
	}

	@Test
	public void testContains() {
		AddressSetView xor;

		xor = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertFalse(xor.contains(addr(0x0800), addr(0x1800)));

		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		xor = new SymmetricDifferenceAddressSetView(a, b);
		assertTrue(xor.contains(addr(0x0800)));
		assertFalse(xor.contains(addr(0x1800)));
		assertTrue(xor.contains(addr(0x2800)));
		assertFalse(xor.contains(addr(0x3000)));
		assertTrue(xor.contains(addr(0x0800), addr(0x0fff)));
		assertFalse(xor.contains(addr(0x0800), addr(0x1000)));
		assertTrue(xor.contains(addr(0x2000), addr(0x2fff)));
		assertFalse(xor.contains(addr(0x1fff), addr(0x2fff)));
		assertFalse(xor.contains(addr(0x2000), addr(0x3000)));
		assertTrue(xor.contains(set(rng(0x0400, 0x0c00), rng(0x2400, 0x2c00))));
		assertFalse(xor.contains(set(rng(0x0400, 0x0c00), rng(0x1c00, 0x2fff))));
		assertFalse(xor.contains(set(rng(0x0400, 0x0c00), rng(0x2400, 0x3c00))));
	}

	@Test
	public void testEndpoints() {
		AddressSetView xor;

		xor = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertNull(xor.getMinAddress());
		assertNull(xor.getMaxAddress());

		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x2fff)),
			set(rng(0x1000, 0x1fff)));
		assertEquals(addr(0x0000), xor.getMinAddress());
		assertEquals(addr(0x2fff), xor.getMaxAddress());

		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x2fff)),
			set(rng(0x1000, 0x2fff)));
		assertEquals(addr(0x0000), xor.getMinAddress());
		assertEquals(addr(0x0fff), xor.getMaxAddress());

		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x2fff)),
			set(rng(0x0000, 0x1fff)));
		assertEquals(addr(0x2000), xor.getMinAddress());
		assertEquals(addr(0x2fff), xor.getMaxAddress());
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
		AddressSetView xor;

		xor = new SymmetricDifferenceAddressSetView(set(rng(0x1000, 0x1fff)),
			set(rng(0x0000, 0x0fff)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(false)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(addr(0x0800), true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(addr(0x0800), false)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(addr(0x1800), true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(addr(0x1800), false)));
		assertEquals(List.of(), collect(xor.iterator(addr(0x2fff), true)));
		assertEquals(List.of(rng(0x0000, 0x1fff)), collect(xor.iterator(addr(0x2fff), false)));

		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x2fff)),
			set(rng(0x1000, 0x1fff)));
		assertEquals(List.of(rng(0x0000, 0x0fff), rng(0x2000, 0x2fff)),
			collect(xor.iterator(true)));
		assertEquals(List.of(rng(0x2000, 0x2fff), rng(0x0000, 0x0fff)),
			collect(xor.iterator(false)));

		//    +---+---+---+---+---+
		//    0 . 1 . 2 . 3 . 4 . 5
		// A: ----    ----
		// B:       ----      ----
		// X: ----  --  --    ----
		//        <- ^
		xor = new SymmetricDifferenceAddressSetView(set(rng(0x0000, 0x0fff), rng(0x2000, 0x2fff)),
			set(rng(0x1800, 0x27ff), rng(0x4000, 0x4fff)));
		assertEquals(List.of(rng(0x1800, 0x1fff), rng(0x2800, 0x2fff), rng(0x4000, 0x4fff)),
			collect(xor.iterator(addr(0x1c00), true)));
		assertEquals(List.of(rng(0x1800, 0x1fff), rng(0x0000, 0x0fff)),
			collect(xor.iterator(addr(0x1c00), false)));

		AddressSet a = null;
		AddressSet b = null;
		try {
			// This one has been particularly elusive.
			// Increase the likelihood of failure, if there is indeed an error.
			a = randomSet();
			b = randomSet();
			for (int i = 0; i < 10000; i++) {
				xor = new SymmetricDifferenceAddressSetView(a, b);
				AddressSetView expected = a.xor(b);
				assertEquals(collect(expected.getAddressRanges(true)), collect(xor.iterator(true)));
				assertEquals(collect(expected.getAddressRanges(false)),
					collect(xor.iterator(false)));
				assertEquals(collect(expected.getAddressRanges(addr(0x8000), true)),
					collect(xor.iterator(addr(0x8000), true)));
				assertEquals(collect(expected.getAddressRanges(addr(0x8000), false)),
					collect(xor.iterator(addr(0x8000), false)));
			}
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
		AddressSetView difference;

		difference = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertFalse(difference.getAddresses(true).hasNext());
		assertFalse(difference.getAddresses(false).hasNext());

		difference = new SymmetricDifferenceAddressSetView(set(rng(1, 3), rng(8, 9)),
			set(rng(2, 4), rng(6, 7)));
		assertEquals(addrs(1, 4, 6, 7, 8, 9), collect(difference.getAddresses(true)));
		assertEquals(addrs(9, 8, 7, 6, 4, 1), collect(difference.getAddresses(false)));
		assertEquals(addrs(4, 6, 7, 8, 9), collect(difference.getAddresses(addr(3), true)));
		assertEquals(addrs(6, 7, 8, 9), collect(difference.getAddresses(addr(5), true)));
		assertEquals(addrs(8, 7, 6, 4, 1), collect(difference.getAddresses(addr(8), false)));
		assertEquals(addrs(4, 1), collect(difference.getAddresses(addr(5), false)));
	}

	@Test
	public void testGetRangeContaining() {
		AddressSetView difference;

		difference = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertNull(difference.getRangeContaining(addr(0x0800)));

		AddressSet a = set(rng(0x0000, 0x2fff), rng(0x4000, 0x4fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		difference = new SymmetricDifferenceAddressSetView(a, b);
		assertEquals(rng(0x0000, 0x0fff), difference.getRangeContaining(addr(0x0000)));
		assertEquals(rng(0x0000, 0x0fff), difference.getRangeContaining(addr(0x0800)));
		assertEquals(rng(0x0000, 0x0fff), difference.getRangeContaining(addr(0x0fff)));
		assertNull(difference.getRangeContaining(addr(0x1000)));
		assertNull(difference.getRangeContaining(addr(0x1800)));
		assertNull(difference.getRangeContaining(addr(0x1fff)));
		assertEquals(rng(0x2000, 0x2fff), difference.getRangeContaining(addr(0x2000)));
		assertEquals(rng(0x2000, 0x2fff), difference.getRangeContaining(addr(0x2800)));
		assertEquals(rng(0x2000, 0x2fff), difference.getRangeContaining(addr(0x2fff)));
		assertNull(difference.getRangeContaining(addr(0x3000)));
		assertEquals(rng(0x4000, 0x4fff), difference.getRangeContaining(addr(0x4800)));
	}

	@Test
	public void testHasSameAddresses() {
		AddressSetView difference;

		difference = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertTrue(difference.hasSameAddresses(new AddressSet()));

		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		difference = new SymmetricDifferenceAddressSetView(a, b);
		assertFalse(difference.hasSameAddresses(new AddressSet()));
		assertTrue(difference.hasSameAddresses(set(rng(0x0000, 0x0fff), rng(0x2000, 0x2fff))));
		assertFalse(difference.hasSameAddresses(set(rng(0x0000, 0x0fff))));
		assertFalse(difference.hasSameAddresses(set(rng(0x2000, 0x2fff))));
		assertFalse(difference.hasSameAddresses(set(rng(0x0000, 0x0fff), rng(0x2000, 0x3000))));
	}

	@Test
	public void testGetFirstLastRanges() {
		AddressSetView difference;

		difference = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertNull(difference.getFirstRange());
		assertNull(difference.getLastRange());

		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		difference = new SymmetricDifferenceAddressSetView(a, b);
		assertEquals(rng(0x0000, 0x0fff), difference.getFirstRange());
		assertEquals(rng(0x2000, 0x2fff), difference.getLastRange());
	}

	@Test
	public void testIntersect() {
		AddressSetView difference;

		difference = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertFalse(difference.intersects(addr(0x1000), addr(0x1fff)));
		assertEquals(new AddressSet(), difference.intersectRange(addr(0x1000), addr(0x1fff)));

		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		difference = new SymmetricDifferenceAddressSetView(a, b);
		assertTrue(difference.intersects(addr(0x0000), addr(0x00ff)));
		assertEquals(set(rng(0x000, 0x00ff)),
			difference.intersectRange(addr(0x0000), addr(0x00ff)));
		assertFalse(difference.intersects(addr(0x5000), addr(0x5fff)));
		assertEquals(new AddressSet(), difference.intersectRange(addr(0x5000), addr(0x5fff)));
		assertTrue(difference.intersects(addr(0x0000), addr(0x1fff)));
		assertEquals(set(rng(0x0000, 0x0fff)),
			difference.intersectRange(addr(0x0000), addr(0x1fff)));
		assertTrue(difference.intersects(addr(0x0000), addr(0x3fff)));
		assertEquals(set(rng(0x0000, 0x0fff), rng(0x2000, 0x2fff)),
			difference.intersectRange(addr(0x0000), addr(0x3fff)));
	}

	@Test
	public void testUnion() {
		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		AddressSetView difference = new SymmetricDifferenceAddressSetView(a, b);
		assertEquals(set(rng(0x0000, 0x2fff)), difference.union(set(rng(0x1000, 0x1fff))));
	}

	@Test
	public void testSubtract() {
		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		AddressSetView difference = new SymmetricDifferenceAddressSetView(a, b);
		assertEquals(set(rng(0x0000, 0x03ff), rng(0x0c00, 0x0fff), rng(0x2000, 0x2fff)),
			difference.subtract(set(rng(0x0400, 0x0bff))));
	}

	@Test
	public void testXor() {
		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		AddressSetView difference = new SymmetricDifferenceAddressSetView(a, b);
		assertEquals(set(rng(0x0000, 0x07ff), rng(0x1000, 0x1fff), rng(0x2800, 0x2fff)),
			difference.xor(set(rng(0x0800, 0x27ff))));
	}

	@Test
	public void testFindFirstAddressInCommon() {
		AddressSetView difference;

		difference = new SymmetricDifferenceAddressSetView(new AddressSet(), new AddressSet());
		assertNull(difference.findFirstAddressInCommon(set(rng(0x1000, 0x1fff))));

		AddressSet a = set(rng(0x0000, 0x2fff));
		AddressSet b = set(rng(0x1000, 0x1fff));
		difference = new SymmetricDifferenceAddressSetView(a, b);
		assertNull(difference.findFirstAddressInCommon(set(rng(0x1000, 0x1fff))));
		assertEquals(addr(0x0800), difference.findFirstAddressInCommon(set(rng(0x0800, 0x1fff))));
		assertEquals(addr(0x2000), difference.findFirstAddressInCommon(set(rng(0x1800, 0x3fff))));
	}
}
