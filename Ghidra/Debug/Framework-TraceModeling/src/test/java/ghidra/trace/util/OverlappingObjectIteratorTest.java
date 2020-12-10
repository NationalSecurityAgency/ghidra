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
package ghidra.trace.util;

import static org.junit.Assert.assertEquals;

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

public class OverlappingObjectIteratorTest extends AbstractGhidraHeadlessIntegrationTest {
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

	protected Pair<AddressRange, AddressRange> pair(AddressRange a, AddressRange b) {
		return new ImmutablePair<>(a, b);
	}

	protected List<Address> addrs(long... offsets) {
		List<Address> result = new ArrayList<>(offsets.length);
		for (long off : offsets) {
			result.add(addr(off));
		}
		return result;
	}

	/**
	 * Copies each entry into a new list, since the iterator may modify the entry in place
	 * 
	 * @param it the source iterator
	 * @return the destination (new) list
	 */
	protected static <K, V> List<Pair<K, V>> toList(Iterator<Pair<K, V>> it) {
		List<Pair<K, V>> result = new ArrayList<>();
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

	protected static List<Pair<AddressRange, AddressRange>> getOverlaps(AddressSet a,
			AddressSet b) {
		return toList(new OverlappingObjectIterator<>( //
			a.iterator(), OverlappingObjectIterator.ADDRESS_RANGE, //
			b.iterator(), OverlappingObjectIterator.ADDRESS_RANGE));
	}

	@Test
	public void testEmpty() {
		assertEquals(List.of(), getOverlaps(set(), set()));
		assertEquals(List.of(), getOverlaps(set(), set(rng(0x1000, 0x1fff))));
		assertEquals(List.of(), getOverlaps(set(rng(0x1000, 0x1fff)), set()));
	}

	@Test
	public void testDisjoint() {
		AddressSet a = set(rng(0x1000, 0x1fff), rng(0x4000, 0x4fff));
		AddressSet b = set(rng(0x2000, 0x2fff), rng(0x6000, 0x6fff));

		assertEquals(List.of(), getOverlaps(a, b));
		assertEquals(List.of(), getOverlaps(b, a));
	}

	@Test
	public void testEndsOverlap() {
		AddressSet a = set(rng(0x1000, 0x2fff));
		AddressSet b = set(rng(0x2000, 0x3fff));

		assertEquals(List.of(pair(rng(0x1000, 0x2fff), rng(0x2000, 0x3fff))), getOverlaps(a, b));
		assertEquals(List.of(pair(rng(0x2000, 0x3fff), rng(0x1000, 0x2fff))), getOverlaps(b, a));
	}

	@Test
	public void testOneEnclosed() {
		AddressSet a = set(rng(0x1000, 0x3fff));
		AddressSet b = set(rng(0x2000, 0x2fff));

		assertEquals(List.of(pair(rng(0x1000, 0x3fff), rng(0x2000, 0x2fff))), getOverlaps(a, b));
		assertEquals(List.of(pair(rng(0x2000, 0x2fff), rng(0x1000, 0x3fff))), getOverlaps(b, a));
	}

	@Test
	public void testSame() {
		AddressSet a = set(rng(0x1000, 0x1fff));
		AddressSet b = set(rng(0x1000, 0x1fff));

		assertEquals(List.of(pair(rng(0x1000, 0x1fff), rng(0x1000, 0x1fff))), getOverlaps(a, b));
	}

	@Test
	public void testStaggered() {
		AddressSet a = set(rng(0x1000, 0x3fff), rng(0x5000, 0x7fff));
		AddressSet b = set(rng(0x3000, 0x5fff), rng(0x7000, 0x9fff));

		assertEquals(List.of( //
			pair(rng(0x1000, 0x3fff), rng(0x3000, 0x5fff)), //
			pair(rng(0x5000, 0x7fff), rng(0x3000, 0x5fff)), //
			pair(rng(0x5000, 0x7fff), rng(0x7000, 0x9fff))  //
		), getOverlaps(a, b));
		assertEquals(List.of( //
			pair(rng(0x3000, 0x5fff), rng(0x1000, 0x3fff)), //
			pair(rng(0x3000, 0x5fff), rng(0x5000, 0x7fff)), //
			pair(rng(0x7000, 0x9fff), rng(0x5000, 0x7fff))  //
		), getOverlaps(b, a));
	}

	@Test
	public void testTwoEnclosed() {
		AddressSet a = set(rng(0x1000, 0x5fff));
		AddressSet b = set(rng(0x2000, 0x2fff), rng(0x4000, 0x4fff));

		assertEquals(List.of( //
			pair(rng(0x1000, 0x5fff), rng(0x2000, 0x2fff)), //
			pair(rng(0x1000, 0x5fff), rng(0x4000, 0x4fff))  //
		), getOverlaps(a, b));
		assertEquals(List.of( //
			pair(rng(0x2000, 0x2fff), rng(0x1000, 0x5fff)), //
			pair(rng(0x4000, 0x4fff), rng(0x1000, 0x5fff))  //
		), getOverlaps(b, a));
	}
}
