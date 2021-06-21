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

import org.junit.Test;

public class MergeSortingIteratorTest {
	@Test
	public void testEmptyMap() {
		Map<String, Iterator<Integer>> iterMap = new HashMap<>();
		Iterator<Entry<String, Integer>> iter =
			MergeSortingIterator.withLabels(iterMap, Comparator.naturalOrder());
		assertFalse(iter.hasNext());
	}

	@Test
	public void testMapOfEmpties() {
		Map<String, Iterator<Integer>> iterMap = new HashMap<>();
		iterMap.put("A", Collections.emptyIterator());
		iterMap.put("B", Collections.emptyIterator());
		Iterator<Entry<String, Integer>> iter =
			MergeSortingIterator.withLabels(iterMap, Comparator.naturalOrder());
		assertFalse(iter.hasNext());
	}

	@Test
	public void test2By2Seq() {
		Map<String, Iterator<Integer>> iterMap = new HashMap<>();
		iterMap.put("A", List.of(1, 2).iterator());
		iterMap.put("B", List.of(3, 4).iterator());
		Iterator<Entry<String, Integer>> iter =
			MergeSortingIterator.withLabels(iterMap, Comparator.naturalOrder());
		Entry<String, Integer> entry;

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("A", entry.getKey());
		assertEquals(1, entry.getValue().intValue());

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("A", entry.getKey());
		assertEquals(2, entry.getValue().intValue());

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("B", entry.getKey());
		assertEquals(3, entry.getValue().intValue());

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("B", entry.getKey());
		assertEquals(4, entry.getValue().intValue());
	}

	@Test
	public void test2By2Alt() {
		Map<String, Iterator<Integer>> iterMap = new HashMap<>();
		iterMap.put("A", List.of(1, 3).iterator());
		iterMap.put("B", List.of(2, 4).iterator());
		Iterator<Entry<String, Integer>> iter =
			MergeSortingIterator.withLabels(iterMap, Comparator.naturalOrder());
		Entry<String, Integer> entry;

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("A", entry.getKey());
		assertEquals(1, entry.getValue().intValue());

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("B", entry.getKey());
		assertEquals(2, entry.getValue().intValue());

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("A", entry.getKey());
		assertEquals(3, entry.getValue().intValue());

		assertTrue(iter.hasNext());
		entry = iter.next();
		assertEquals("B", entry.getKey());
		assertEquals(4, entry.getValue().intValue());
	}
}
