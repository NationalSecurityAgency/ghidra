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
package ghidra.generic.util.datastruct;

import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.collections4.comparators.ReverseComparator;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;

import ghidra.generic.util.datastruct.TreeValueSortedMap;
import ghidra.generic.util.datastruct.ValueSortedMap;

public class TreeValueSortedMapTest {
	@Test
	public void testNaturalOrder() {
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		queue.put("2nd", 2);
		queue.put("1st", 1);
		queue.put("3rd", 3);
		List<String> ordered = new ArrayList<>(queue.keySet());
		assertEquals(Arrays.asList(new String[] { "1st", "2nd", "3rd" }), ordered);
	}

	@Test
	public void testExplicitOrdered() {
		ValueSortedMap<String, Integer> queue =
			TreeValueSortedMap.createWithComparator(new ReverseComparator<>());
		queue.put("2nd", 2);
		queue.put("1st", 1);
		queue.put("3rd", 3);
		List<String> ordered = new ArrayList<>(queue.keySet());
		assertEquals(Arrays.asList(new String[] { "3rd", "2nd", "1st" }), ordered);
	}

	@Test
	public void testBoundsSearches() {
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();

		assertNull(queue.lowerEntryByValue(4));
		assertNull(queue.floorEntryByValue(4));
		assertNull(queue.ceilingEntryByValue(4));
		assertNull(queue.higherEntryByValue(4));

		assertEquals(-1, queue.values().lowerIndex(4));
		assertEquals(-1, queue.values().floorIndex(4));
		assertEquals(-1, queue.values().ceilingIndex(4));
		assertEquals(-1, queue.values().higherIndex(4));

		queue.put("4th", 4);

		assertNull(queue.lowerEntryByValue(3));
		assertEquals(-1, queue.values().lowerIndex(3));
		assertNull(queue.lowerEntryByValue(4));
		assertEquals(-1, queue.values().lowerIndex(4));
		assertEquals("4th", queue.lowerEntryByValue(5).getKey());
		assertEquals(0, queue.values().lowerIndex(5));

		assertNull(queue.floorEntryByValue(3));
		assertEquals(-1, queue.values().floorIndex(3));
		assertEquals("4th", queue.floorEntryByValue(4).getKey());
		assertEquals(0, queue.values().floorIndex(4));
		assertEquals("4th", queue.floorEntryByValue(5).getKey());
		assertEquals(0, queue.values().floorIndex(5));

		assertEquals("4th", queue.ceilingEntryByValue(3).getKey());
		assertEquals(0, queue.values().ceilingIndex(3));
		assertEquals("4th", queue.ceilingEntryByValue(4).getKey());
		assertEquals(0, queue.values().ceilingIndex(4));
		assertNull(queue.ceilingEntryByValue(5));
		assertEquals(-1, queue.values().ceilingIndex(5));

		assertEquals("4th", queue.higherEntryByValue(3).getKey());
		assertEquals(0, queue.values().higherIndex(3));
		assertNull(queue.higherEntryByValue(4));
		assertEquals(-1, queue.values().higherIndex(4));
		assertNull(queue.higherEntryByValue(5));
		assertEquals(-1, queue.values().higherIndex(5));

		queue.put("2nd", 2);
		queue.put("6th", 6);

		assertNull(queue.lowerEntryByValue(1));
		assertNull(queue.lowerEntryByValue(2));
		assertEquals("2nd", queue.lowerEntryByValue(3).getKey());
		assertEquals("2nd", queue.lowerEntryByValue(4).getKey());
		assertEquals("4th", queue.lowerEntryByValue(5).getKey());
		assertEquals("4th", queue.lowerEntryByValue(6).getKey());
		assertEquals("6th", queue.lowerEntryByValue(7).getKey());
		assertEquals(2, queue.values().lowerIndex(7)); // Only this once

		assertNull(queue.floorEntryByValue(1));
		assertEquals("2nd", queue.floorEntryByValue(2).getKey());
		assertEquals("2nd", queue.floorEntryByValue(3).getKey());
		assertEquals("4th", queue.floorEntryByValue(4).getKey());
		assertEquals("4th", queue.floorEntryByValue(5).getKey());
		assertEquals("6th", queue.floorEntryByValue(6).getKey());
		assertEquals("6th", queue.floorEntryByValue(7).getKey());

		assertEquals("2nd", queue.ceilingEntryByValue(1).getKey());
		assertEquals("2nd", queue.ceilingEntryByValue(2).getKey());
		assertEquals("4th", queue.ceilingEntryByValue(3).getKey());
		assertEquals("4th", queue.ceilingEntryByValue(4).getKey());
		assertEquals("6th", queue.ceilingEntryByValue(5).getKey());
		assertEquals("6th", queue.ceilingEntryByValue(6).getKey());
		assertNull(queue.ceilingEntryByValue(7));

		assertEquals("2nd", queue.higherEntryByValue(1).getKey());
		assertEquals("4th", queue.higherEntryByValue(2).getKey());
		assertEquals("4th", queue.higherEntryByValue(3).getKey());
		assertEquals("6th", queue.higherEntryByValue(4).getKey());
		assertEquals("6th", queue.higherEntryByValue(5).getKey());
		assertNull(queue.higherEntryByValue(6));
		assertNull(queue.higherEntryByValue(7));
	}

	@Test
	public void testIsEmpty() {
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		assertTrue(queue.isEmpty());

		assertFalse(queue.containsKey("1st"));
		assertFalse(queue.containsValue(1));
		assertEquals(-1, queue.values().indexOf(1));

		queue.put("1st", 1);
		assertFalse(queue.isEmpty());
	}

	protected <K, V> void checkConsistent(ValueSortedMap<K, V> queue) {
		Iterator<Entry<K, V>> it = queue.entrySet().iterator();
		V last = null;
		Set<K> seen = new HashSet<>();
		for (int i = 0; i < queue.size(); i++) {
			Entry<K, V> e = it.next();
			assertTrue("Indices and iterator did not give same order",
				queue.entrySet().get(i) == e);
			assertEquals("Incorrect computed index", i, queue.entrySet().indexOf(e));
			if (!seen.add(e.getKey())) {
				fail("Unique index did not give unique key");
			}
			@SuppressWarnings("unchecked")
			Comparable<V> lc = (Comparable<V>) last;
			if (last != null && lc.compareTo(e.getValue()) > 0) {
				fail("Costs should be monotonic");
			}
			last = e.getValue();
		}
		for (int i = queue.size(); i < queue.size() * 2; i++) {
			try {
				queue.entrySet().get(i);
				fail();
			}
			catch (IndexOutOfBoundsException e) {
				// pass
			}
		}
		for (int i = -queue.size(); i < 0; i++) {
			try {
				queue.entrySet().get(i);
				fail();
			}
			catch (IndexOutOfBoundsException e) {
				// pass
			}
		}
	}

	@Test
	public void testAddRandomly() {
		final int COUNT = 1000;
		final int ROUNDS = 5;
		Random rand = new Random();
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		for (int r = 0; r < ROUNDS; r++) {
			for (int i = 0; i < COUNT; i++) {
				queue.put("Element" + i, rand.nextInt(50));
			}
			checkConsistent(queue);
			queue.clear();
		}
	}

	@Test
	public void testRemoveRandomly() {
		final int COUNT = 100;
		Random rand = new Random();
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		HashSet<String> all = new HashSet<>();
		for (int i = 0; i < COUNT; i++) {
			queue.put("Element" + i, rand.nextInt(50));
			all.add("Element" + i);
		}
		checkConsistent(queue);

		String[] shuffled = all.toArray(new String[all.size()]);
		for (int i = 0; i < shuffled.length; i++) {
			ArrayUtils.swap(shuffled, i, i + rand.nextInt(shuffled.length - i));
		}
		for (String s : shuffled) {
			queue.remove(s);
			checkConsistent(queue);
		}
		assertTrue(queue.isEmpty());
		assertTrue(queue.size() == 0);
	}

	@Test
	public void testUpdateRandomly() {
		final int COUNT = 100;
		Random rand = new Random();
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		for (int i = 0; i < COUNT; i++) {
			queue.put("Element" + i, rand.nextInt(50));
		}
		checkConsistent(queue);

		for (int i = 0; i < COUNT; i++) {
			String e = "Element" + rand.nextInt(queue.size());
			int oldCost = queue.get(e);
			int retCost = queue.put(e, rand.nextInt(50));
			assertEquals(oldCost, retCost);
			checkConsistent(queue);
		}
	}

	@Test
	public void testValueIndices() {
		final int ROUNDS = 1000;
		Random rand = new Random();
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		int[] vals = // 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22
			new int[] { 0, 0, 1, 1, 1, 2, 3, 4, 4, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 8, 8, 10 };
		for (int r = 0; r < ROUNDS; r++) {
			for (int i = 0; i < vals.length; i++) {
				ArrayUtils.swap(vals, i, i + rand.nextInt(vals.length - i));
			}
			for (int i = 0; i < vals.length; i++) {
				queue.put("Element" + i, vals[i]);
			}
			checkConsistent(queue);
			assertEquals(0, queue.values().indexOf(0));
			assertEquals(1, queue.values().lastIndexOf(0));
			assertEquals(2, queue.values().indexOf(1));
			assertEquals(4, queue.values().lastIndexOf(1));
			assertEquals(5, queue.values().indexOf(2));
			assertEquals(5, queue.values().lastIndexOf(2));
			assertEquals(6, queue.values().indexOf(3));
			assertEquals(6, queue.values().lastIndexOf(3));
			assertEquals(7, queue.values().indexOf(4));
			assertEquals(8, queue.values().lastIndexOf(4));
			assertEquals(9, queue.values().indexOf(5));
			assertEquals(10, queue.values().lastIndexOf(5));
			assertEquals(11, queue.values().indexOf(6));
			assertEquals(19, queue.values().lastIndexOf(6));
			assertEquals(-1, queue.values().indexOf(7));
			assertEquals(-1, queue.values().lastIndexOf(7));
			assertEquals(20, queue.values().indexOf(8));
			assertEquals(21, queue.values().lastIndexOf(8));
			assertEquals(-1, queue.values().indexOf(9));
			assertEquals(-1, queue.values().lastIndexOf(9));
			assertEquals(22, queue.values().indexOf(10));
			assertEquals(22, queue.values().lastIndexOf(10));
		}
	}

	@Test
	public void testAsMonotonicQueue() {
		final int COUNT = 1000;
		Random rand = new Random();
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		for (int i = 0; i < COUNT; i++) {
			queue.put("ElementA" + i, rand.nextInt(50));
		}
		checkConsistent(queue);
		int last = -1;
		for (int i = 0; i < COUNT; i++) {
			Entry<String, Integer> ent = queue.entrySet().poll();
			assertTrue(last <= ent.getValue());
			last = ent.getValue();
			queue.put("ElementB" + i, last + rand.nextInt(50));
		}
		checkConsistent(queue);
		for (int i = 0; i < COUNT; i++) {
			Entry<String, Integer> ent = queue.entrySet().poll();
			assertTrue(last <= ent.getValue());
			last = ent.getValue();
		}
		checkConsistent(queue);
		assertEquals(0, queue.size());
		assertTrue(queue.isEmpty());
	}

	@Test
	public void testClearViaKeyIterator() {
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		for (int i = 0; i < 10; i++) {
			queue.put("Element" + i, i);
		}
		Iterator<String> kit = queue.keySet().iterator();
		while (kit.hasNext()) {
			kit.next();
			kit.remove();
		}

		assertTrue(queue.isEmpty());
	}

	@Test
	public void testRemoveOddsViaValueIterator() {
		ValueSortedMap<String, Integer> queue = TreeValueSortedMap.createWithNaturalOrder();
		for (int i = 0; i < 10; i++) {
			queue.put("Element" + i, i);
		}
		Iterator<Integer> vit = queue.values().iterator();
		while (vit.hasNext()) {
			int val = vit.next();
			if (val % 2 == 1) {
				vit.remove();
			}
		}

		for (int val : queue.values()) {
			assertEquals(0, val % 2);
		}
	}

	@Test(expected = IllegalStateException.class)
	public void testNominalBehaviorIteratorRemoveBeforeNext() {
		Set<Integer> set = new HashSet<>();
		set.add(5);
		Iterator<Integer> it = set.iterator();
		it.remove();
	}
}
