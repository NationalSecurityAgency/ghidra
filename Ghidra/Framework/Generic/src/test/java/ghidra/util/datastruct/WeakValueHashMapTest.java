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
package ghidra.util.datastruct;

import static org.junit.Assert.*;

import java.util.*;
import java.util.Map.Entry;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class WeakValueHashMapTest extends AbstractGenericTest {

	public WeakValueHashMapTest() {
		super();
	}

	@Test
	public void testMap1() throws InterruptedException {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		Foo fooA = new Foo("AAA");
		Foo fooB = new Foo("BBB");
		Foo fooC = new Foo("CCC");
		cache.put(0, fooA);
		cache.put(1, fooB);
		cache.put(2, fooC);

		assertEquals(3, cache.size(), 0);

		assertEquals("AAA", cache.get(0).getName());
		assertEquals("BBB", cache.get(1).getName());
		assertEquals("CCC", cache.get(2).getName());

		fooA = null;
		fooB = null;
		fooC = null;
		gc(cache, 0);

		assertEquals(0, cache.size());

	}

	@Test
	public void testGetValues() throws InterruptedException {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		Foo fooA = new Foo("AAA");
		Foo fooB = new Foo("BBB");
		Foo fooC = new Foo("CCC");
		cache.put(0, fooA);
		cache.put(1, fooB);
		cache.put(2, fooC);

		Collection<Foo> values = cache.values();
		fooA = null;
		fooB = null;

		assertEquals(3, values.size());
		gc(cache, 1);
		assertEquals(1, values.size());
		assertEquals(fooC, values.iterator().next());
	}

	@Test
	public void testEntrySet() throws InterruptedException {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		Foo fooA = new Foo("AAA");
		Foo fooB = new Foo("BBB");
		Foo fooC = new Foo("CCC");
		cache.put(0, fooA);
		cache.put(1, fooB);
		cache.put(2, fooC);

		Set<Map.Entry<Integer, Foo>> entries = cache.entrySet();
		assertEquals(3, entries.size());
		fooA = null;
		fooC = null;

		gc(cache, 1);
		assertEquals(fooB, entries.iterator().next().getValue());
		assertEquals(1, entries.size());

	}

	@Test
	public void testValuesIterator() {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		Foo fooA = new Foo("AAA");
		Foo fooB = new Foo("BBB");
		Foo fooC = new Foo("CCC");
		cache.put(0, fooA);
		cache.put(1, fooB);
		cache.put(2, fooC);

		Set<Foo> expectedValues = new HashSet<>(Set.of(fooA, fooB, fooC));

		Collection<Foo> values = cache.values();
		Iterator<Foo> it = values.iterator();

		assertTrue(it.hasNext());
		Foo foo = it.next();
		assertTrue(expectedValues.contains(foo));
		expectedValues.remove(foo);

		assertTrue(it.hasNext());
		foo = it.next();
		assertTrue(expectedValues.contains(foo));
		expectedValues.remove(foo);

		assertTrue(it.hasNext());
		foo = it.next();
		assertTrue(expectedValues.contains(foo));
		expectedValues.remove(foo);

		assertFalse(it.hasNext());
		assertTrue(expectedValues.isEmpty());
	}

	@Test
	public void testRemoveFromValuesIterator() {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		Foo fooA = new Foo("AAA");
		Foo fooB = new Foo("BBB");
		Foo fooC = new Foo("CCC");
		cache.put(0, fooA);
		cache.put(1, fooB);
		cache.put(2, fooC);

		Collection<Foo> values = cache.values();
		Iterator<Foo> it = values.iterator();
		while (it.hasNext()) {
			Foo f = it.next();
			it.remove();
		}

		assertEquals(0, values.size());
		assertEquals(0, cache.size());

	}

	@Test
	public void testEntriesIterator() {
		WeakValueHashMap<Integer, Foo> cache = new WeakValueHashMap<Integer, Foo>();
		Foo fooA = new Foo("AAA");
		Foo fooB = new Foo("BBB");
		Foo fooC = new Foo("CCC");
		cache.put(0, fooA);
		cache.put(1, fooB);
		cache.put(2, fooC);
		Set<Foo> expectedValues = new HashSet<>(Set.of(fooA, fooB, fooC));

		Set<Entry<Integer, Foo>> entries = cache.entrySet();
		assertEquals(3, entries.size());

		Iterator<Entry<Integer, Foo>> it = entries.iterator();

		assertTrue(it.hasNext());
		Map.Entry<Integer, Foo> entry = it.next();
		assertTrue(expectedValues.contains(entry.getValue()));
		expectedValues.remove(entry.getValue());

		assertTrue(it.hasNext());
		entry = it.next();
		assertTrue(expectedValues.contains(entry.getValue()));
		expectedValues.remove(entry.getValue());

		assertTrue(it.hasNext());
		entry = it.next();
		assertTrue(expectedValues.contains(entry.getValue()));
		expectedValues.remove(entry.getValue());

		assertFalse(it.hasNext());
	}

	private void gc(WeakValueHashMap<Integer, Foo> cache, int expectedSize)
			throws InterruptedException {
		for (int i = 0; i < 100; i++) {
			System.gc();
			Thread.sleep(10);
			cache.get(0);
			if (cache.size() == expectedSize) {
				break;
			}
		}
	}

	static class Foo {
		String name;

		Foo(String name) {
			this.name = name;
		}

		String getName() {
			return name;
		}
	}
}
