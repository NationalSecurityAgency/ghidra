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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.*;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import generic.util.*;
import ghidra.util.exception.AssertException;

// for list creation operations
public class MultiIteratorTest extends AbstractGenericTest {

	public MultiIteratorTest() {
		super();
	}

	@Test
	public void testSingleIterator_Forward() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(1, 2, 3);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testSingleIterator_Backward() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(3, 2, 1);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, false);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testMultipleIterators_Forward() {
		PeekableIterator<Integer> peekable1 = new NumberPeekableIterator(3, 5, 7);
		PeekableIterator<Integer> peekable2 = new NumberPeekableIterator(2, 4, 6, 8, 10);
		PeekableIterator<Integer> peekable3 = new NumberPeekableIterator(1, 9);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable1, peekable2, peekable3);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(4), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(5), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(6), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(7), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(8), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(9), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(10), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testMultipleIterators_Backward() {
		PeekableIterator<Integer> peekable1 = new NumberPeekableIterator(7, 5, 3);
		PeekableIterator<Integer> peekable2 = new NumberPeekableIterator(10, 8, 6, 4, 2);
		PeekableIterator<Integer> peekable3 = new NumberPeekableIterator(9, 1);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable1, peekable2, peekable3);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, false);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(10), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(9), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(8), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(7), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(6), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(5), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(4), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testMultipleIterators_DuplicateValues() {
		PeekableIterator<Integer> peekable1 = new NumberPeekableIterator(1, 2, 2, 2, 3);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable1);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testMultipleIterators_DuplicateValues_DifferentIterators() {
		PeekableIterator<Integer> peekable1 = new NumberPeekableIterator(1, 2, 3);
		PeekableIterator<Integer> peekable2 = new NumberPeekableIterator(2, 4, 6);
		PeekableIterator<Integer> peekable3 = new NumberPeekableIterator(3, 5, 7);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable1, peekable2, peekable3);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(4), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(5), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(6), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(7), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testSingleIterator_HasNextManyTimes_Forward() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(1, 2, 3);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		iterator.hasNext();
		iterator.hasNext();
		iterator.hasNext();
		iterator.hasNext();

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testSingleIterator_HasNextManyTimes_Backward() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(3, 2, 1);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, false);

		iterator.hasNext();
		iterator.hasNext();
		iterator.hasNext();
		iterator.hasNext();

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(3), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new Integer(1), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testNextManyTimesWithoutCallingHasNext_Fowrard() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(1, 2, 3);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		iterator.next(); // 1
		iterator.next(); // 2
		iterator.next(); // 3 
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testNextManyTimesWithoutCallingHasNext_Backward() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(3, 2, 1);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, false);

		iterator.next(); // 3
		iterator.next(); // 2
		iterator.next(); // 1 
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testNonComparableItems_Forward() {
		List<TestItem> data = new ArrayList<>();
		data.add(new TestItem(1));
		data.add(new TestItem(2));
		data.add(new TestItem(3));

		PeekableIterator<TestItem> peekable =
			new WrappingPeekableIterator<>(data.iterator());
		List<PeekableIterator<TestItem>> list = Arrays.asList(peekable);

		MultiIterator<TestItem> iterator = new MultiIterator<>(list, true);
		try {
			iterator.next();
			Assert.fail("Should have failed because elements are not comparable");
		}
		catch (AssertException e) {
			// good!
		}

		iterator = new MultiIterator<>(list, new TestItemComparator(), true);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new TestItem(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new TestItem(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new TestItem(3), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testNonComparableItems_Backward() {
		List<TestItem> data = new ArrayList<>();
		data.add(new TestItem(1));
		data.add(new TestItem(2));
		data.add(new TestItem(3));

		PeekableIterator<TestItem> peekable =
			new WrappingPeekableIterator<>(data.iterator());
		List<PeekableIterator<TestItem>> list = Arrays.asList(peekable);

		MultiIterator<TestItem> iterator = new MultiIterator<>(list, false);
		try {
			iterator.next();
			Assert.fail("Should have failed because elements are not comparable");
		}
		catch (AssertException e) {
			// good!
		}

		iterator = new MultiIterator<>(list, new TestItemComparator(), false);

		assertTrue(iterator.hasNext());
		Assert.assertEquals(new TestItem(1), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new TestItem(2), iterator.next());
		assertTrue(iterator.hasNext());
		Assert.assertEquals(new TestItem(3), iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testSingleItemIterator() {
		PeekableIterator<Integer> peekable = new NumberPeekableIterator(1);

		List<PeekableIterator<Integer>> list = Arrays.asList(peekable);
		MultiIterator<Integer> iterator = new MultiIterator<>(list, true);

		iterator.next(); // 1 
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testWrappingPeekableIterator() {
		// Note: this test doesn't really below here, but I didn't feel it was worthwhile to
		// create a new test file just for one test

		List<TestItem> data = new ArrayList<>();
		data.add(new TestItem(1));
		data.add(new TestItem(2));
		data.add(new TestItem(3));

		PeekableIterator<TestItem> peekable =
			new WrappingPeekableIterator<>(data.iterator());

		// make sure we can call peek multiple times
		TestItem peek = peekable.peek();
		Assert.assertEquals(new TestItem(1), peek);
		peek = peekable.peek();
		Assert.assertEquals(new TestItem(1), peek);
		peek = peekable.peek();
		Assert.assertEquals(new TestItem(1), peek);

		assertTrue(peekable.hasNext());
		assertTrue(peekable.hasNext());
		assertTrue(peekable.hasNext());
		assertTrue(peekable.hasNext());

		TestItem next = peekable.next();
		Assert.assertEquals(new TestItem(1), next);
		next = peekable.next();
		Assert.assertEquals(new TestItem(2), next);
		next = peekable.next();
		Assert.assertEquals(new TestItem(3), next);

		assertFalse(peekable.hasNext());

		try {
			peekable.peek();
			Assert.fail("Shouldn't be able to peek after fully iterating");
		}
		catch (NoSuchElementException e) {
			// good!
		}
	}

//==================================================================================================
// Private Methods
//==================================================================================================

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestItem {

		String name;

		TestItem(int ID) {
			name = Integer.toString(ID);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + ((name == null) ? 0 : name.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			TestItem other = (TestItem) obj;
			if (!getOuterType().equals(other.getOuterType())) {
				return false;
			}

			if (name == null) {
				if (other.name != null) {
					return false;
				}
			}
			else if (!name.equals(other.name)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			return name;
		}

		private MultiIteratorTest getOuterType() {
			return MultiIteratorTest.this;
		}
	}

	private class TestItemComparator implements Comparator<TestItem> {
		@Override
		public int compare(TestItem t1, TestItem t2) {
			return t1.name.compareTo(t2.name);
		}
	}

	private class NumberPeekableIterator implements PeekableIterator<Integer> {

		private int current = 0;
		private int[] values;

		NumberPeekableIterator(int... values) {
			this.values = values;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean hasNext() {
			return current < values.length;
		}

		@Override
		public Integer next() {
			return values[current++];
		}

		@Override
		public Integer peek() {
			if (current >= values.length) {
				throw new NoSuchElementException();
			}
			return values[current];
		}

	}
}
