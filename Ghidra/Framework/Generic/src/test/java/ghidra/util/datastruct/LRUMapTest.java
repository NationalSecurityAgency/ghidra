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

import org.junit.*;

import generic.test.AbstractGenericTest;

public class LRUMapTest extends AbstractGenericTest {
	private static int CACHE_SIZE = 3;

	private LRUMap<String, String> map;

	public LRUMapTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		int size = 3;
		map = new LRUMap<String, String>(size);

		// this creates an cache order of: 3, 2, 1
		map.put("key1", "value1");
		map.put("key2", "value2");
		map.put("key3", "value3");
	}

	@Test
	public void testMultiplePointsDoesntIncreaseSize() {
		map = new LRUMap<String, String>(3);

		map.put("key1", "value1");
		map.put("key1", "value1");
		assertEquals("Multiple additions resulted in multiple entries", map.size(), 1);
	}

	@Test
	public void testSizeRestriction() {
		map.put("key4", "value4");

		assertEquals("Should only have " + CACHE_SIZE + " entries after adding more " +
			"elements than would fit that size", CACHE_SIZE, map.size());
		assertFalse("Map did not remove the eldest entry", map.containsKey("key1"));
	}

	@Test
	public void testGetAccessReodersElement() {
		// move 1 to the top/front
		map.get("key1");

		Set<String> keySet = map.keySet();
		assertEquals("Calling get on an element did not move it to the bottom", "key1",
			keySet.iterator().next());

		// move 2 to the top/front
		map.get("key2");
		assertEquals("Calling get on an element did not move it to the bottom", "key2",
			keySet.iterator().next());
	}

	@Test
	public void testPutAccessReodersElement() {
		// move 1 to the top/front
		map.put("key1", "value1");

		Set<String> keySet = map.keySet();
		assertEquals("Calling get on an element did not move it to the front", "key1",
			keySet.iterator().next());

		// move 2 to the top/front
		map.put("key2", "value2");
		assertEquals("Calling get on an element did not move it to the front", "key2",
			keySet.iterator().next());
	}

	@Test
	public void testConcurrentModification() {

		Iterator<String> iterator = map.keySet().iterator();
		assertTrue(iterator.hasNext());
		map.put("key4", "value4");
		try {
			iterator.next();
			Assert.fail("Expected Concurrent Modification Exception");
		}
		catch (ConcurrentModificationException e) {
			// expected
		}

	}

	@Test
	public void testRemove() {
		map.remove("key2");
		assertEquals(2, map.size());
		assertTrue(map.containsKey("key1"));
		assertTrue(map.containsKey("key3"));
		assertTrue(!map.containsKey("key2"));
	}

	@Test
	public void testClear() {
		map.clear();

		assertEquals(0, map.size());
		assertTrue(!map.containsKey("key1"));
		assertTrue(!map.containsKey("key3"));
		assertTrue(!map.containsKey("key2"));

	}

	@Test
	public void testPutAll() {
		LRUMap<String, String> map2 = new LRUMap<String, String>(CACHE_SIZE);
		map2.putAll(map);
		assertTrue(map.containsKey("key1"));
		assertTrue(map.containsKey("key2"));
		assertTrue(map.containsKey("key3"));
	}

	@Test
	public void testIteratorRemove() {
		Iterator<String> iterator = map.keySet().iterator();
		iterator.next();
		iterator.next();
		iterator.remove();

		assertEquals(2, map.size());
		assertTrue(map.containsKey("key1"));
		assertTrue(!map.containsKey("key2"));
		assertTrue(map.containsKey("key3"));

		iterator = map.keySet().iterator();
		assertEquals("key3", iterator.next());
		assertEquals("key1", iterator.next());
		iterator.remove();

		assertEquals(1, map.size());
		assertTrue(!map.containsKey("key1"));
		assertTrue(!map.containsKey("key2"));
		assertTrue(map.containsKey("key3"));

		iterator = map.keySet().iterator();
		iterator.next();
		iterator.remove();

		assertEquals(0, map.size());
	}

	@Test
	public void testContainsValue() {

		assertTrue(map.containsValue("value2"));
		assertTrue(!map.containsValue("value5"));
	}

	@Test
	public void testValueSetIterator() {

		Iterator<String> iterator = map.values().iterator();
		assertEquals("value3", iterator.next());
		assertEquals("value2", iterator.next());
		assertEquals("value1", iterator.next());
	}

	@Test
	public void testKeySetIterator() {
		Iterator<String> iterator = map.keySet().iterator();
		assertTrue(iterator.hasNext());
		assertEquals("key3", iterator.next());
		assertEquals("key2", iterator.next());
		assertEquals("key1", iterator.next());
		assertTrue(!iterator.hasNext());
	}

	@Test
	public void testEntrySetIterator() {
		LRUMap<Integer, Integer> integerMap = new LRUMap<Integer, Integer>(CACHE_SIZE = 3);

		int count = 1;
		integerMap.put(count, count++);
		integerMap.put(count, count++);
		integerMap.put(count, count++);

		Integer expectedValue = count - 1;
		Set<Entry<Integer, Integer>> entrySet = integerMap.entrySet();
		for (Entry<Integer, Integer> entry : entrySet) {
			assertEquals(entry.getKey(), expectedValue);
			assertEquals(entry.getValue(), expectedValue);
			expectedValue = expectedValue - 1;
		}
	}

	@Test
	public void testEntrySetContainsAndRemove() {
		Set<Entry<String, String>> entrySet = map.entrySet();

		Iterator<Entry<String, String>> iterator = entrySet.iterator();
		Entry<String, String> oldestItem = iterator.next();

		assertTrue(entrySet.contains(oldestItem));
		assertTrue(entrySet.remove(oldestItem));
		assertFalse(entrySet.contains(oldestItem));
	}

	@Test
	public void testEntrySetClear() {
		Set<Entry<String, String>> entrySet = map.entrySet();

		entrySet.clear();
		assertEquals(0, entrySet.size());
		assertEquals(0, map.size());
	}

	@Test
	public void testKeySetContainsAndRemove() {
		Set<String> keySet = map.keySet();

		Iterator<String> iterator = keySet.iterator();
		String oldestItem = iterator.next();

		assertTrue(keySet.contains(oldestItem));
		assertTrue(keySet.remove(oldestItem));
		assertFalse(keySet.contains(oldestItem));
	}

	@Test
	public void testKeySetClear() {
		Set<String> keySet = map.keySet();

		keySet.clear();
		assertEquals(0, keySet.size());
		assertEquals(0, map.size());
	}

	@Test
	public void testValueSetContainsAndRemove() {
		Collection<String> values = map.values();

		Iterator<String> iterator = values.iterator();
		String oldestItem = iterator.next();

		assertTrue(values.contains(oldestItem));
		assertTrue(values.remove(oldestItem));
		assertFalse(values.contains(oldestItem));
	}

	@Test
	public void testValueSetClear() {
		Collection<String> values = map.values();

		values.clear();
		assertEquals(0, values.size());
		assertEquals(0, map.size());
	}
}
