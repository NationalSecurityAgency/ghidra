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
package ghidra.features.base.memsearch.combiner;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.program.model.address.*;

public class MemoryMatchCombinerTest {

	private GenericAddressSpace space;

	private MemoryMatch m1;
	private MemoryMatch m2;
	private MemoryMatch m3;
	private MemoryMatch m4;
	private MemoryMatch m5;
	private MemoryMatch m6;
	private MemoryMatch m7;
	private MemoryMatch m8;

	List<MemoryMatch> list1;
	List<MemoryMatch> list2;
	List<MemoryMatch> result;

	@Before
	public void setUp() {
		space = new GenericAddressSpace("test", 64, AddressSpace.TYPE_RAM, 0);

		m1 = createMatch(1, 4);
		m2 = createMatch(2, 4);
		m3 = createMatch(3, 4);
		m4 = createMatch(4, 4);
		m5 = createMatch(5, 4);
		m6 = createMatch(6, 4);
		m7 = createMatch(7, 4);
		m8 = createMatch(8, 4);
	}

	@Test
	public void testUnionAllUnique() {
		list1 = list(m1, m8);
		list2 = list(m2, m3, m4);
		result = union(list1, list2);
		assertEquals(list(m1, m2, m3, m4, m8), result);
	}

	@Test
	public void testUnionWithEmptyList() {
		list1 = list(m1, m8);
		list2 = list();
		result = union(list1, list2);
		assertEquals(list(m1, m8), result);

		list1 = list();
		list2 = list(m5, m7);
		result = union(list1, list2);
		assertEquals(list(m5, m7), result);

	}

	@Test
	public void testUnionWithDups() {
		list1 = list(m1, m2, m3);
		list2 = list(m3, m4, m5);
		result = union(list1, list2);
		assertEquals(list(m1, m2, m3, m4, m5), result);
	}

	@Test
	public void testUnionWithDupsKeepsLonger() {
		MemoryMatch m3_short = createMatch(3, 2);
		MemoryMatch m3_long = createMatch(3, 8);

		list1 = list(m1, m2, m3);
		list2 = list(m3_short, m4, m5);
		result = union(list1, list2);
		assertEquals(list(m1, m2, m3, m4, m5), result);

		list2 = list(m3_long, m4, m5);
		result = union(list1, list2);
		assertEquals(list(m1, m2, m3_long, m4, m5), result);
	}

	@Test
	public void testIntersectionAllUnique() {
		list1 = list(m1, m8);
		list2 = list(m2, m3, m4);
		result = intersect(list1, list2);
		assertEquals(list(), result);
	}

	@Test
	public void testIntersectionAllSame() {
		list1 = list(m1, m2);
		list2 = list(m1, m2);
		result = intersect(list1, list2);
		assertEquals(list(m1, m2), result);
	}

	@Test
	public void testIntersectionSomeSameSomeUnique() {
		list1 = list(m1, m2, m3);
		list2 = list(m2, m3, m4);
		result = intersect(list1, list2);
		assertEquals(list(m2, m3), result);
	}

	@Test
	public void testIntersectionKeepsLonger() {
		MemoryMatch m4_long = createMatch(4, 8);
		MemoryMatch m3_long = createMatch(3, 8);
		list1 = list(m1, m2, m3, m4_long);
		list2 = list(m1, m2, m3_long, m4);
		result = intersect(list1, list2);
		assertEquals(list(m1, m2, m3_long, m4_long), result);
	}

	@Test
	public void testXor() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m3, m4, m5, m6);
		result = xor(list1, list2);
		assertEquals(list(m1, m2, m5, m6), result);
	}

	@Test
	public void testXorNothingInCommon() {
		list1 = list(m1, m2);
		list2 = list(m3, m4);
		result = xor(list1, list2);
		assertEquals(list(m1, m2, m3, m4), result);
	}

	@Test
	public void testXorAllInCommon() {
		list1 = list(m1, m2);
		list2 = list(m1, m2);
		result = xor(list1, list2);
		assertEquals(list(), result);
	}

	@Test
	public void testXorWithEmpty() {
		list1 = list(m1, m2);
		list2 = list();
		result = xor(list1, list2);
		assertEquals(list(m1, m2), result);

		list1 = list();
		list2 = list(m1, m2);
		result = xor(list1, list2);
		assertEquals(list(m1, m2), result);
	}

	@Test
	public void testXorLengthDontMatter() {
		MemoryMatch m4_long = createMatch(4, 8);
		MemoryMatch m3_short = createMatch(3, 2);

		list1 = list(m1, m2, m3, m4);
		list2 = list(m3_short, m4_long, m5);
		result = xor(list1, list2);
		assertEquals(list(m1, m2, m5), result);

		list1 = list(m1, m2, m3_short, m4_long);
		list2 = list(m3, m4, m5);
		result = xor(list1, list2);
		assertEquals(list(m1, m2, m5), result);
	}

	@Test
	public void testAMinusB() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m2, m3);
		result = aMinusB(list1, list2);
		assertEquals(list(m1, m4), result);
	}

	@Test
	public void testAMinusBSameSet() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m1, m2, m3, m4);
		result = aMinusB(list1, list2);
		assertEquals(list(), result);
	}

	@Test
	public void testAMinusBNothingInCommon() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m5, m6, m7, m8);
		result = aMinusB(list1, list2);
		assertEquals(list(m1, m2, m3, m4), result);
	}

	@Test
	public void testAMinusBEmptyList() {
		list1 = list();
		list2 = list(m5, m6, m7, m8);
		result = aMinusB(list1, list2);
		assertEquals(list(), result);

		list1 = list(m5, m6, m7, m8);
		list2 = list();
		result = aMinusB(list1, list2);
		assertEquals(list(m5, m6, m7, m8), result);
	}

	@Test
	public void testAMinusBLengthDontMatter() {
		MemoryMatch m4_long = createMatch(4, 8);
		MemoryMatch m3_short = createMatch(3, 2);

		list1 = list(m1, m2, m3, m4);
		list2 = list(m3_short, m4_long, m5);
		result = aMinusB(list1, list2);
		assertEquals(list(m1, m2), result);

		list1 = list(m1, m2, m3_short, m4_long);
		list2 = list(m3, m4, m5);
		result = aMinusB(list1, list2);
		assertEquals(list(m1, m2), result);
	}

	@Test
	public void testBMinusA() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m2, m3, m4, m5, m6);
		result = BMinusA(list1, list2);
		assertEquals(list(m5, m6), result);
	}

	@Test
	public void testBMinusASameSet() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m1, m2, m3, m4);
		result = BMinusA(list1, list2);
		assertEquals(list(), result);
	}

	@Test
	public void testBMinusANothingInCommon() {
		list1 = list(m1, m2, m3, m4);
		list2 = list(m5, m6, m7, m8);
		result = BMinusA(list1, list2);
		assertEquals(list(m5, m6, m7, m8), result);
	}

	@Test
	public void testBMinusAEmptyList() {
		list1 = list();
		list2 = list(m5, m6, m7, m8);
		result = BMinusA(list1, list2);
		assertEquals(list(m5, m6, m7, m8), result);

		list1 = list(m5, m6, m7, m8);
		list2 = list();
		result = BMinusA(list1, list2);
		assertEquals(list(), result);
	}

	@Test
	public void testBMinusALengthDontMatter() {
		MemoryMatch m4_long = createMatch(4, 8);
		MemoryMatch m3_short = createMatch(3, 2);

		list1 = list(m1, m2, m3, m4);
		list2 = list(m3_short, m4_long, m5);
		result = BMinusA(list1, list2);
		assertEquals(list(m5), result);

		list1 = list(m1, m2, m3_short, m4_long);
		list2 = list(m3, m4, m5);
		result = BMinusA(list1, list2);
		assertEquals(list(m5), result);
	}

	private List<MemoryMatch> xor(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		Combiner combiner = Combiner.XOR;
		List<MemoryMatch> results = new ArrayList<>(combiner.combine(matches1, matches2));
		Collections.sort(results);
		return results;
	}

	private List<MemoryMatch> union(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		Combiner combiner = Combiner.UNION;
		List<MemoryMatch> results = new ArrayList<>(combiner.combine(matches1, matches2));
		Collections.sort(results);
		return results;
	}

	private List<MemoryMatch> intersect(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		Combiner combiner = Combiner.INTERSECT;
		List<MemoryMatch> results = new ArrayList<>(combiner.combine(matches1, matches2));
		Collections.sort(results);
		return results;
	}

	private List<MemoryMatch> aMinusB(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		Combiner combiner = Combiner.A_MINUS_B;
		List<MemoryMatch> results = new ArrayList<>(combiner.combine(matches1, matches2));
		Collections.sort(results);
		return results;
	}

	private List<MemoryMatch> BMinusA(List<MemoryMatch> matches1, List<MemoryMatch> matches2) {
		Combiner combiner = Combiner.B_MINUS_A;
		List<MemoryMatch> results = new ArrayList<>(combiner.combine(matches1, matches2));
		Collections.sort(results);
		return results;
	}

	private List<MemoryMatch> list(MemoryMatch... matches) {
		return Arrays.asList(matches);
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	private MemoryMatch createMatch(int offset, int length) {
		Address address = addr(offset);
		byte[] bytes = new byte[length];
		return new MemoryMatch(address, bytes, null);
	}
}
