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
package util;

import static org.hamcrest.collection.IsIn.*;
import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.Test;

public class CollectionUtilsTest {

	@Test
	public void testAsSet_VarArgs() {

		Set<String> set = CollectionUtils.asSet("One", "Two");
		assertNotNull(set);
		assertEquals(2, set.size());

		Iterator<String> iterator = set.iterator();
		assertEquals("One", iterator.next());
		assertEquals("Two", iterator.next());
	}

	@Test
	public void testAsSet_VarArgs_Null() {

		Set<String> set = CollectionUtils.asSet((String) null);
		assertNotNull(set);
		assertTrue(set.isEmpty());
	}

	@Test
	public void testAsSet_Collection_FromSet() {

		Collection<String> c = new HashSet<>(Arrays.asList("One", "Two"));

		Set<String> set = CollectionUtils.asSet(c);
		Iterator<String> iterator = set.iterator();
		assertEquals("One", iterator.next());
		assertEquals("Two", iterator.next());
	}

	@Test
	public void testAsSet_Collection_FromList() {

		Collection<String> c = new ArrayList<>(Arrays.asList("One", "Two"));
		Set<String> set = CollectionUtils.asSet(c);
		assertNotNull(set);

		Iterator<String> iterator = set.iterator();
		assertEquals("One", iterator.next());
		assertEquals("Two", iterator.next());
	}

	@Test
	public void testAsSet_Collection_FromNull() {

		Collection<String> c = null;
		Set<String> set = CollectionUtils.asSet(c);
		assertNotNull(set);
		assertTrue(set.isEmpty());
	}

	@Test
	public void testAsList_VarArgs() {

		List<String> list = CollectionUtils.asList("One", "Two");
		assertNotNull(list);
		assertEquals("One", list.get(0));
		assertEquals("Two", list.get(1));
	}

	@Test
	public void testAsList_VarArgs_Null() {

		List<String> list = CollectionUtils.asList((String) null);
		assertNotNull(list);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testAsList_List() {

		List<String> list = new ArrayList<>(Arrays.asList("One", "Two"));
		list = CollectionUtils.asList(list);
		assertNotNull(list);
		assertEquals("One", list.get(0));
		assertEquals("Two", list.get(1));
	}

	@Test
	public void testAsList_List_Empty() {

		List<String> list = new ArrayList<>();
		list = CollectionUtils.asList(list);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testAsList_List_Null() {

		List<String> list = null;
		list = CollectionUtils.asList(list);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testAsList_Array_Null() {

		String[] array = null;
		List<String> list = CollectionUtils.asList(array);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testAsList_Collection_FromList() {

		Collection<String> c = new ArrayList<>(Arrays.asList("One", "Two"));
		List<String> list = CollectionUtils.asList(c);
		assertNotNull(list);
		assertEquals("One", list.get(0));
		assertEquals("Two", list.get(1));
	}

	@Test
	public void testAsList_Collection_FromSet() {

		Collection<String> c = new HashSet<>(Arrays.asList("One", "Two"));
		List<String> list = CollectionUtils.asList(c);
		assertNotNull(list);
		assertEquals("One", list.get(0));
		assertEquals("Two", list.get(1));
	}

	@Test
	public void testAsList_Collection_FromNull() {

		List<String> list = CollectionUtils.asList((Collection<String>) null);
		assertNotNull(list);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testNonNull_Collection_NonNull() {

		Collection<String> c = new HashSet<>(Arrays.asList("One", "Two"));
		c = CollectionUtils.nonNull(c);
		assertNotNull(c);

		Iterator<String> iterator = c.iterator();
		assertEquals("One", iterator.next());
		assertEquals("Two", iterator.next());
	}

	@Test
	public void testNonNull_Collection_Null() {
		Collection<String> c = null;
		c = CollectionUtils.nonNull(c);
		assertNotNull(c);
		assertTrue(c.isEmpty());
	}

	@Test
	public void testAsList_Iterator() {

		List<String> list = new ArrayList<>(Arrays.asList("One", "Two"));
		Iterator<String> iterator = list.iterator();
		list = CollectionUtils.asList(iterator);
		assertNotNull(list);
		assertEquals("One", list.get(0));
		assertEquals("Two", list.get(1));
	}

	@Test
	public void testAsList_Iterator_Null() {

		List<String> list = CollectionUtils.asList((Iterator<String>) null);
		assertNotNull(list);
		assertTrue(list.isEmpty());
	}

	@Test
	public void testIsAllSameType_Collection() {

		List<Object> list = new ArrayList<>();
		list.add("One");
		list.add("Two");
		assertTrue(CollectionUtils.isAllSameType(list, String.class));
		assertFalse(CollectionUtils.isAllSameType(list, Integer.class));

		list.clear();
		list.add("One");
		list.add(Integer.valueOf(2));
		assertFalse(CollectionUtils.isAllSameType(list, String.class));
		assertFalse(CollectionUtils.isAllSameType(list, Integer.class));
	}

	@Test
	public void testAsIterable_Iterator() {

		List<String> list = new ArrayList<>(Arrays.asList("One", "Two"));
		Iterator<String> iterator = list.iterator();
		Iterable<String> iterable = CollectionUtils.asIterable(iterator);
		assertNotNull(iterable);
		iterator = iterable.iterator();
		assertNotNull(iterator);
		assertTrue(iterator.hasNext());
		assertEquals("One", iterator.next());
	}

	@Test
	public void testAsIterable_Collections() {

		List<String> original = Arrays.asList("One", "Two", "Three", "Four");
		Collection<String> a = Arrays.asList(original.get(0), original.get(1));
		Collection<String> b = Arrays.asList(original.get(2));
		Collection<String> c = Collections.emptyList();
		Collection<String> d = Arrays.asList(original.get(3));
		Iterable<String> iterable = CollectionUtils.asIterable(a, b, c, d);

		List<String> result = new ArrayList<>();
		iterable.forEach(s -> result.add(s));
		assertEquals(original, result);
	}

	@Test
	public void testAsList_UnknownToType() {
		List<String> list = new ArrayList<>();
		list.add("A");
		list.add("B");
		list.add("C");

		List<?> src = list;//note: this is contrived!

		List<String> dest = CollectionUtils.asList(src, String.class);

		assertEquals(src.size(), dest.size());

		assertEquals(src.get(0), dest.get(0));
		assertEquals(src.get(1), dest.get(1));
		assertEquals(src.get(2), dest.get(2));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAsList_UnknownToType_MixedTypes() {
		List<Object> list = new ArrayList<>();
		list.add("A");
		list.add(Integer.valueOf(1));
		list.add("C");

		CollectionUtils.asList(list, String.class);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testAsCollection_UnknownToType_MixedTypes() {
		List<Object> list = new ArrayList<>();
		list.add("A");
		list.add(Integer.valueOf(1));
		list.add("C");

		CollectionUtils.asCollection(list, String.class);
	}

	@Test
	public void testAsList_Enumeration_UnknownToType_MixedTypes() {
		Vector<String> vector = new Vector<>();
		vector.add("A");
		vector.add("B");
		vector.add("C");
		Enumeration<String> enumeration = vector.elements();

		List<String> list = CollectionUtils.asList(enumeration);
		assertNotNull(list);
		assertEquals("A", list.get(0));
		assertEquals("B", list.get(1));
		assertEquals("C", list.get(2));

	}

	@Test
	public void testAny() {

		Collection<String> c = Arrays.asList("One", "Two");
		String any = CollectionUtils.any(c);
		assertNotNull(any);
		assertThat(any, isOneOf("One", "Two"));
	}

	@Test
	public void testAny_Empty() {
		Collection<String> c = Collections.emptyList();
		String any = CollectionUtils.any(c);
		assertNull(any);
	}

	@Test
	public void testAnyNull() {
		Collection<String> c = null;
		String any = CollectionUtils.any(c);
		assertNull(any);
	}

	@Test
	public void testIsOneOf() {
		assertFalse(CollectionUtils.isOneOf(null, "Hi"));
		assertFalse(CollectionUtils.isOneOf("Bye", "Hi", "Hey", "Ho"));

		assertTrue(CollectionUtils.isOneOf("Hi", "Hi"));
		assertTrue(CollectionUtils.isOneOf(1, 1));
		assertTrue(CollectionUtils.isOneOf(3, 1, 2, 3));
		assertTrue(CollectionUtils.isOneOf(Integer.valueOf(3), 1, 2, 3));
	}

	@Test
	public void testIsOneOf_Null() {

		assertFalse(CollectionUtils.isOneOf("a", (Object) null));

		assertTrue(CollectionUtils.isOneOf((Object) null, (Object) null));
		assertTrue(CollectionUtils.isOneOf((Object) null, "a", null, "b"));
	}

	public void testIsAllNull() {

		assertTrue(CollectionUtils.isAllNull());
		assertTrue(CollectionUtils.isAllNull((Object[]) null));
		assertTrue(CollectionUtils.isAllNull(null, null));
		assertTrue(CollectionUtils.isAllNull(null, null, null));

		assertFalse(CollectionUtils.isAllNull("One"));
		assertFalse(CollectionUtils.isAllNull("One", null));
		assertFalse(CollectionUtils.isAllNull(1, "Bob", null));
	}

	public void testStreamCollection() {

		List<String> original = Arrays.asList("One", "Two", "Three", "Four");
		Stream<String> stream = CollectionUtils.asStream(original);
		List<String> result = stream.collect(Collectors.toList());
		assertEquals(original, result);
	}

	@Test
	public void testStreamCollections() {

		List<String> original = Arrays.asList("One", "Two", "Three", "Four");
		Collection<String> a = Arrays.asList(original.get(0), original.get(1));
		Collection<String> b = Arrays.asList(original.get(2));
		Collection<String> c = Collections.emptyList();
		Collection<String> d = Arrays.asList(original.get(3));
		Stream<String> stream = CollectionUtils.asStream(a, b, c, d);
		List<String> result = stream.collect(Collectors.toList());
		assertEquals(original, result);
	}

}
