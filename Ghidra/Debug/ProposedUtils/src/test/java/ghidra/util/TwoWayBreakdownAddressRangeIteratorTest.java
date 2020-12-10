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
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.TwoWayBreakdownAddressRangeIterator.Which;

public class TwoWayBreakdownAddressRangeIteratorTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Language toy;

	protected TwoWayBreakdownAddressRangeIterator makeIterator(AddressSet a, AddressSet b,
			boolean forward) {
		return new TwoWayBreakdownAddressRangeIterator(a.iterator(forward), b.iterator(forward),
			forward);
	}

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

	protected Pair<AddressRange, Which> pair(long min, long max, Which which) {
		return new ImmutablePair<>(rng(min, max), which);
	}

	/**
	 * Copies each entry into a new list, since the iterator may modify the entry in place
	 * 
	 * @param it the source iterator
	 * @return the destination (new) list
	 */
	protected static <K, V> List<Entry<K, V>> toList(Iterator<Entry<K, V>> it) {
		List<Entry<K, V>> result = new ArrayList<>();
		while (it.hasNext()) {
			Entry<K, V> ent = it.next();
			result.add(new ImmutablePair<>(ent.getKey(), ent.getValue()));
		}
		return result;
	}

	@Before
	public void setUpIteratorTest() throws LanguageNotFoundException {
		toy = DefaultLanguageService.getLanguageService().getLanguage(
			new LanguageID("Toy:BE:64:default"));
	}

	@Test
	public void testBothEmpty() {
		AddressSet a = new AddressSet();
		AddressSet b = new AddressSet();

		assertFalse(makeIterator(a, b, true).hasNext());
		assertFalse(makeIterator(a, b, false).hasNext());
	}

	@Test
	public void testOneEmpty() {
		AddressSet a = new AddressSet();
		AddressSet b = set(rng(0x4000, 0x4fff), rng(0x6000, 0x6fff));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x4000, 0x4fff, Which.RIGHT), pair(0x6000, 0x6fff, Which.RIGHT));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x4000, 0x4fff, Which.LEFT), pair(0x6000, 0x6fff, Which.LEFT));
		actual = toList(makeIterator(b, a, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x6fff, Which.RIGHT), pair(0x4000, 0x4fff, Which.RIGHT));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x6fff, Which.LEFT), pair(0x4000, 0x4fff, Which.LEFT));
		actual = toList(makeIterator(b, a, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testConnected() {
		AddressSet a = set(rng(0x3000, 0x3fff), rng(0x5000, 0x5fff));
		AddressSet b = set(rng(0x4000, 0x4fff), rng(0x6000, 0x6fff));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x3000, 0x3fff, Which.LEFT), pair(0x4000, 0x4fff, Which.RIGHT),
			pair(0x5000, 0x5fff, Which.LEFT), pair(0x6000, 0x6fff, Which.RIGHT));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x3000, 0x3fff, Which.RIGHT), pair(0x4000, 0x4fff, Which.LEFT),
			pair(0x5000, 0x5fff, Which.RIGHT), pair(0x6000, 0x6fff, Which.LEFT));
		actual = toList(makeIterator(b, a, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x6fff, Which.RIGHT), pair(0x5000, 0x5fff, Which.LEFT),
			pair(0x4000, 0x4fff, Which.RIGHT), pair(0x3000, 0x3fff, Which.LEFT));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x6fff, Which.LEFT), pair(0x5000, 0x5fff, Which.RIGHT),
			pair(0x4000, 0x4fff, Which.LEFT), pair(0x3000, 0x3fff, Which.RIGHT));
		actual = toList(makeIterator(b, a, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testDisjoint() {
		AddressSet a = set(rng(0x3000, 0x37ff), rng(0x5000, 0x57ff));
		AddressSet b = set(rng(0x4000, 0x47ff), rng(0x6000, 0x67ff));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x3000, 0x37ff, Which.LEFT), pair(0x4000, 0x47ff, Which.RIGHT),
			pair(0x5000, 0x57ff, Which.LEFT), pair(0x6000, 0x67ff, Which.RIGHT));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x3000, 0x37ff, Which.RIGHT), pair(0x4000, 0x47ff, Which.LEFT),
			pair(0x5000, 0x57ff, Which.RIGHT), pair(0x6000, 0x67ff, Which.LEFT));
		actual = toList(makeIterator(b, a, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x67ff, Which.RIGHT), pair(0x5000, 0x57ff, Which.LEFT),
			pair(0x4000, 0x47ff, Which.RIGHT), pair(0x3000, 0x37ff, Which.LEFT));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x67ff, Which.LEFT), pair(0x5000, 0x57ff, Which.RIGHT),
			pair(0x4000, 0x47ff, Which.LEFT), pair(0x3000, 0x37ff, Which.RIGHT));
		actual = toList(makeIterator(b, a, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testOverlapEmptyBetween() {
		AddressSet a = set(rng(0x3000, 0x4fff), rng(0x7000, 0x8fff));
		AddressSet b = set(rng(0x4000, 0x5fff), rng(0x8000, 0x9fff));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x3000, 0x3fff, Which.LEFT), pair(0x4000, 0x4fff, Which.BOTH),
			pair(0x5000, 0x5fff, Which.RIGHT), pair(0x7000, 0x7fff, Which.LEFT),
			pair(0x8000, 0x8fff, Which.BOTH), pair(0x9000, 0x9fff, Which.RIGHT));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x3000, 0x3fff, Which.RIGHT), pair(0x4000, 0x4fff, Which.BOTH),
			pair(0x5000, 0x5fff, Which.LEFT), pair(0x7000, 0x7fff, Which.RIGHT),
			pair(0x8000, 0x8fff, Which.BOTH), pair(0x9000, 0x9fff, Which.LEFT));
		actual = toList(makeIterator(b, a, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x9000, 0x9fff, Which.RIGHT), pair(0x8000, 0x8fff, Which.BOTH),
			pair(0x7000, 0x7fff, Which.LEFT), pair(0x5000, 0x5fff, Which.RIGHT),
			pair(0x4000, 0x4fff, Which.BOTH), pair(0x3000, 0x3fff, Which.LEFT));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);

		expected = List.of(pair(0x9000, 0x9fff, Which.LEFT), pair(0x8000, 0x8fff, Which.BOTH),
			pair(0x7000, 0x7fff, Which.RIGHT), pair(0x5000, 0x5fff, Which.LEFT),
			pair(0x4000, 0x4fff, Which.BOTH), pair(0x3000, 0x3fff, Which.RIGHT));
		actual = toList(makeIterator(b, a, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testOverlapMiddle() {
		AddressSet a = set(rng(0x3000, 0x5fff));
		AddressSet b = set(rng(0x4000, 0x4fff));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x3000, 0x3fff, Which.LEFT), pair(0x4000, 0x4fff, Which.BOTH),
			pair(0x5000, 0x5fff, Which.LEFT));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x3000, 0x3fff, Which.RIGHT), pair(0x4000, 0x4fff, Which.BOTH),
			pair(0x5000, 0x5fff, Which.RIGHT));
		actual = toList(makeIterator(b, a, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x5000, 0x5fff, Which.LEFT), pair(0x4000, 0x4fff, Which.BOTH),
			pair(0x3000, 0x3fff, Which.LEFT));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);

		expected = List.of(pair(0x5000, 0x5fff, Which.RIGHT), pair(0x4000, 0x4fff, Which.BOTH),
			pair(0x3000, 0x3fff, Which.RIGHT));
		actual = toList(makeIterator(b, a, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testSame() {
		AddressSet a = set(rng(0x4000, 0x4fff), rng(0x6000, 0x6fff));
		AddressSet b = set(rng(0x4000, 0x4fff), rng(0x6000, 0x6fff));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x4000, 0x4fff, Which.BOTH), pair(0x6000, 0x6fff, Which.BOTH));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x6000, 0x6fff, Which.BOTH), pair(0x4000, 0x4fff, Which.BOTH));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testOverlapAtExtremes() {
		AddressSet a = set(rng(0x0000, 0x0fff), rng(-0x2000, -0x0001));
		AddressSet b = set(rng(0x0000, 0x1fff), rng(-0x1000, -0x0001));

		List<Entry<AddressRange, Which>> expected;
		List<Entry<AddressRange, Which>> actual;

		expected = List.of(pair(0x0000, 0x0fff, Which.BOTH), pair(0x1000, 0x1fff, Which.RIGHT),
			pair(-0x2000, -0x1001, Which.LEFT), pair(-0x1000, -0x0001, Which.BOTH));
		actual = toList(makeIterator(a, b, true));
		assertEquals(expected, actual);

		expected = List.of(pair(0x0000, 0x0fff, Which.BOTH), pair(0x1000, 0x1fff, Which.LEFT),
			pair(-0x2000, -0x1001, Which.RIGHT), pair(-0x1000, -0x0001, Which.BOTH));
		actual = toList(makeIterator(b, a, true));
		assertEquals(expected, actual);

		expected = List.of(pair(-0x1000, -0x0001, Which.BOTH), pair(-0x2000, -0x1001, Which.LEFT),
			pair(0x1000, 0x1fff, Which.RIGHT), pair(0x0000, 0x0fff, Which.BOTH));
		actual = toList(makeIterator(a, b, false));
		assertEquals(expected, actual);

		expected = List.of(pair(-0x1000, -0x0001, Which.BOTH), pair(-0x2000, -0x1001, Which.RIGHT),
			pair(0x1000, 0x1fff, Which.LEFT), pair(0x0000, 0x0fff, Which.BOTH));
		actual = toList(makeIterator(b, a, false));
		assertEquals(expected, actual);
	}

	@Test
	public void testRandom() {
		AddressSet a = randomSet();
		AddressSet b = randomSet();

		runIteratorTest(a, b, true);
		runIteratorTest(b, a, true);
		runIteratorTest(a, b, false);
		runIteratorTest(b, a, false);
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

	protected void runIteratorTest(AddressSet a, AddressSet b, boolean forward) {
		AddressSet both = a.intersect(b);
		AddressSet left = a.subtract(b);
		AddressSet right = b.subtract(a);

		TwoWayBreakdownAddressRangeIterator it = makeIterator(a, b, forward);
		while (it.hasNext()) {
			Entry<AddressRange, Which> next = it.next();
			AddressSet which;
			switch (next.getValue()) {
				case BOTH:
					which = both;
					break;
				case LEFT:
					which = left;
					break;
				case RIGHT:
					which = right;
					break;
				default:
					throw new AssertionError();
			}
			if (forward) {
				assertEquals(which.getMinAddress(), next.getKey().getMinAddress());
			}
			else {
				assertEquals(which.getMaxAddress(), next.getKey().getMaxAddress());
			}
			which.delete(next.getKey());
		}

		assertTrue(both.isEmpty());
		assertTrue(left.isEmpty());
		assertTrue(right.isEmpty());
	}
}
