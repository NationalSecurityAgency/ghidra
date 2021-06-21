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
package generic;

import static org.junit.Assert.*;

import java.util.*;

import org.apache.commons.collections4.IteratorUtils;
import org.junit.Test;

public class NestedIteratorTest {
	@Test
	public void testEmptyOuter() {
		List<Object> result =
			IteratorUtils.toList(NestedIterator.start(Collections.emptyIterator(), o -> {
				fail();
				return null;
			}));
		assertTrue(result.isEmpty());
	}

	@Test
	public void testSingleOuterEmptyInner() {
		List<Object> result = IteratorUtils.toList(
			NestedIterator.start(List.of("Test").iterator(), s -> Collections.emptyIterator()));
		assertTrue(result.isEmpty());
	}

	@Test
	public void testDoubleOuterEmptyInner() {
		List<Object> result = IteratorUtils.toList(
			NestedIterator.start(List.of("T1", "T2").iterator(), s -> Collections.emptyIterator()));
		assertTrue(result.isEmpty());
	}

	@Test
	public void testSingleOuterSingleInner() {
		List<String> result = IteratorUtils
			.toList(NestedIterator.start(List.of(0).iterator(), n -> List.of("Test").iterator()));
		assertEquals(List.of("Test"), result);
	}

	@Test
	public void testFirstEmptySecondSingleton() {
		List<String> result = IteratorUtils.toList(NestedIterator.start(List.of(0, 1).iterator(),
			n -> n == 0 ? Collections.emptyIterator() : List.of("Test").iterator()));
		assertEquals(List.of("Test"), result);
	}

	@Test
	public void testSingleOuterDoubleInner() {
		List<String> result = IteratorUtils.toList(
			NestedIterator.start(List.of(0).iterator(), n -> List.of("T1", "T2").iterator()));
		assertEquals(List.of("T1", "T2"), result);
	}

	@Test
	public void testDoubleOuterDoubleInner() {
		List<String> result = IteratorUtils.toList(NestedIterator.start(List.of(0, 1).iterator(),
			n -> (n == 0 ? List.of("T1", "T2") : List.of("T3", "T4")).iterator()));
		assertEquals(List.of("T1", "T2", "T3", "T4"), result);
	}

	@Test
	public void testMultipleHasNextCalls() {
		Iterator<String> it = NestedIterator.start(List.of(0, 1).iterator(),
			n -> (n == 0 ? List.of("T1", "T2") : List.of("T3", "T4")).iterator());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertEquals("T1", it.next());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertEquals("T2", it.next());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertEquals("T3", it.next());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertTrue(it.hasNext());
		assertEquals("T4", it.next());
		assertFalse(it.hasNext());
	}

	@Test
	public void testNoHasNextCalls() {
		Iterator<String> it = NestedIterator.start(List.of(0, 1).iterator(),
			n -> (n == 0 ? List.of("T1", "T2") : List.of("T3", "T4")).iterator());
		assertEquals("T1", it.next());
		assertEquals("T2", it.next());
		assertEquals("T3", it.next());
		assertEquals("T4", it.next());
		assertFalse(it.hasNext());
		assertEquals(null, it.next());
	}

	@Test
	public void testRemoveAfterHasNextCheck() { // This is an odd test
		List<String> a = new ArrayList<>(List.of("T1", "T2"));
		List<String> b = new ArrayList<>(List.of("T3", "T4"));
		List<List<String>> listList = new ArrayList<>(List.of(a, b));

		Iterator<String> it = NestedIterator.start(listList.iterator(), l -> l.iterator());
		assertEquals("T1", it.next());
		assertEquals("T2", it.next());
		assertTrue(it.hasNext()); // Odd to do this right before a remove, but....
		it.remove();
		assertEquals("T3", it.next());
		assertEquals("T4", it.next());
		assertFalse(it.hasNext());

		assertEquals(List.of("T1"), a);
		assertEquals(List.of("T3", "T4"), b);
	}
}
