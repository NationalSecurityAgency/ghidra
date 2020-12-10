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

import org.apache.commons.lang3.ArrayUtils;
import org.junit.Test;

import ghidra.generic.util.datastruct.DynamicSortedTreeSet;

public class DynamicSortedTreeSetTest {
	public static class NonComparable {
		public NonComparable(String key, int cost) {
			this.key = key;
			this.cost = cost;
		}

		@Override
		public String toString() {
			return key + "=" + cost;
		}

		protected String key;
		protected int cost;
	}

	public static class TestElem extends NonComparable implements Comparable<TestElem> {
		public TestElem(String key, int cost) {
			super(key, cost);
		}

		@Override
		public int compareTo(TestElem that) {
			return key.compareTo(that.key);
		}
	}

	public static class CostComparator implements Comparator<TestElem> {
		@Override
		public int compare(TestElem a, TestElem b) {
			return a.cost - b.cost;
		}
	}

	@Test
	public void testNaturalOrder() {
		DynamicSortedTreeSet<String> queue = new DynamicSortedTreeSet<>();
		queue.add("2nd");
		queue.add("1st");
		queue.add("3rd");
		List<String> ordered = new ArrayList<>(queue);
		assertEquals(Arrays.asList(new String[] { "1st", "2nd", "3rd" }), ordered);
	}

	@Test(expected = ClassCastException.class)
	public void testUnorderedError() {
		DynamicSortedTreeSet<NonComparable> queue = new DynamicSortedTreeSet<>();
		queue.add(new NonComparable("2nd", 2));
		queue.add(new NonComparable("1st", 1));
	}

	@Test
	public void testExplicitOrdered() {
		DynamicSortedTreeSet<TestElem> queue = new DynamicSortedTreeSet<>(new CostComparator());
		queue.add(new TestElem("2ndB", 2));
		queue.add(new TestElem("2ndA", 2));
		queue.add(new TestElem("1st", 1));
		queue.add(new TestElem("3rd", 3));
		List<String> ordered = new ArrayList<>();
		for (TestElem elem : queue) {
			ordered.add(elem.key);
		}
		assertEquals(Arrays.asList(new String[] { "1st", "2ndB", "2ndA", "3rd" }), ordered);
	}

	@Test
	public void testIsEmpty() {
		DynamicSortedTreeSet<TestElem> queue = new DynamicSortedTreeSet<>(new CostComparator());
		assertTrue(queue.isEmpty());
		queue.add(new TestElem("1st", 1));
		assertFalse(queue.isEmpty());
	}

	protected <E> void checkConsistent(DynamicSortedTreeSet<E> queue, Comparator<E> comp) {
		Iterator<E> it = queue.iterator();
		E last = null;
		Set<E> seen = new HashSet<>();
		for (int i = 0; i < queue.size(); i++) {
			E e = it.next();
			assertTrue("Indices and iterator did not give same order", queue.get(i) == e);
			assertEquals("Incorrect computed index", i, queue.indexOf(e));
			if (!seen.add(e)) {
				fail("Unique index did not give unique element");
			}
			if (last != null && comp.compare(last, e) > 0) {
				fail("Costs should be monotonic");
			}
			last = e;
		}
		for (int i = queue.size(); i < queue.size() * 2; i++) {
			try {
				queue.get(i);
				fail();
			}
			catch (IndexOutOfBoundsException e) {
				// pass
			}
		}
		for (int i = -queue.size(); i < 0; i++) {
			try {
				queue.get(i);
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
		final int ROUNDS = 10;
		Random rand = new Random();
		CostComparator comp = new CostComparator();
		DynamicSortedTreeSet<TestElem> queue = new DynamicSortedTreeSet<>(comp);
		for (int r = 0; r < ROUNDS; r++) {
			for (int i = 0; i < COUNT; i++) {
				queue.add(new TestElem("Element" + i, rand.nextInt(50)));
			}
			checkConsistent(queue, comp);
			queue.clear();
		}
	}

	@Test
	public void testRemoveRandomly() {
		final int COUNT = 100;
		Random rand = new Random();
		CostComparator comp = new CostComparator();
		DynamicSortedTreeSet<TestElem> queue = new DynamicSortedTreeSet<>(comp);
		HashSet<TestElem> all = new HashSet<>();
		for (int i = 0; i < COUNT; i++) {
			TestElem e = new TestElem("Element" + i, rand.nextInt(50));
			queue.add(e);
			all.add(e);
		}
		checkConsistent(queue, comp);

		TestElem[] shuffled = all.toArray(new TestElem[all.size()]);
		for (int i = 0; i < shuffled.length; i++) {
			ArrayUtils.swap(shuffled, i, i + rand.nextInt(shuffled.length - i));
		}
		for (TestElem e : shuffled) {
			queue.remove(e);
			checkConsistent(queue, comp);
		}
		assertTrue(queue.isEmpty());
		assertTrue(queue.size() == 0);
	}

	@Test
	public void testUpdateRandomly() {
		final int COUNT = 100;
		Random rand = new Random();
		CostComparator comp = new CostComparator();
		DynamicSortedTreeSet<TestElem> queue = new DynamicSortedTreeSet<>(comp);
		for (int i = 0; i < COUNT; i++) {
			queue.add(new TestElem("Element" + i, rand.nextInt(50)));
		}
		checkConsistent(queue, comp);

		for (int i = 0; i < COUNT; i++) {
			TestElem e = queue.get(rand.nextInt(queue.size()));
			int oldCost = e.cost;
			if (rand.nextInt(2) == 0) {
				e.cost = rand.nextInt(50);
			}
			boolean result = queue.update(e);
			if (oldCost == e.cost) {
				assertEquals(false, result);
			}
			// NOTE: A different cost does not necessarily promote the updated element
			checkConsistent(queue, comp);
		}
	}
}
