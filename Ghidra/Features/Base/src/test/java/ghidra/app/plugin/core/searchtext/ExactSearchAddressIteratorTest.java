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
package ghidra.app.plugin.core.searchtext;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;
import ghidra.program.util.MultiAddressIterator;

public class ExactSearchAddressIteratorTest extends AbstractGenericTest {

	private AddressSpace space = new GenericAddressSpace("Bob", 32, AddressSpace.TYPE_RAM, 0);

	public ExactSearchAddressIteratorTest() {
		super();
	}

	@Test
	public void testSingleIterator_Forward() {
		AddressIterator searchIterator = new NumberAddressIterator(1, 2, 3);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator }, true);

		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(1), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(2), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(3), exactSearchIterator.next());
		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testSingleIterator_Backward() {
		AddressIterator searchIterator = new NumberAddressIterator(3, 2, 1);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator }, false);

		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(3), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(2), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(1), exactSearchIterator.next());
		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testMultipleIterators_Forward() {
		AddressIterator searchIterator1 = new NumberAddressIterator(3, 5, 7);
		AddressIterator searchIterator2 = new NumberAddressIterator(2, 4, 6, 8, 10);
		AddressIterator searchIterator3 = new NumberAddressIterator(1, 9);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator1, searchIterator2,
				searchIterator3 }, true);

		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(1), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(2), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(3), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(4), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(5), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(6), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(7), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(8), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(9), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(10), exactSearchIterator.next());

		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testMultipleIterators_Backward() {
		AddressIterator searchIterator1 = new NumberAddressIterator(0x64, 0x61, 0x32);
		AddressIterator searchIterator2 = new NumberAddressIterator(0x3e8, 0x384, 0x21, 0xb, 1);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator1, searchIterator2 },
				false);

		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0x3e8), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0x384), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0x64), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0x61), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0x32), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0x21), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(0xb), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(1), exactSearchIterator.next());

		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testMultipleIterators_DuplicateAddresses() {
		AddressIterator searchIterator1 = new NumberAddressIterator(1, 5, 7);
		AddressIterator searchIterator2 = new NumberAddressIterator(1, 4, 5, 7, 10);
		AddressIterator searchIterator3 = new NumberAddressIterator(1, 9);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator1, searchIterator2,
				searchIterator3 }, true);

		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(1), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(4), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(5), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(7), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(9), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(10), exactSearchIterator.next());

		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testSingleIterator_HasNextManyTimes_Forward() {
		AddressIterator searchIterator = new NumberAddressIterator(1, 2, 3);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator }, true);

		assertTrue(exactSearchIterator.hasNext());
		assertTrue(exactSearchIterator.hasNext());
		assertTrue(exactSearchIterator.hasNext());
		assertTrue(exactSearchIterator.hasNext());

		assertEquals(addr(1), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(2), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(3), exactSearchIterator.next());
		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testSingleIterator_HasNextManyTimes_Backward() {
		AddressIterator searchIterator = new NumberAddressIterator(3, 2, 1);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator }, false);

		assertTrue(exactSearchIterator.hasNext());
		assertTrue(exactSearchIterator.hasNext());
		assertTrue(exactSearchIterator.hasNext());
		assertTrue(exactSearchIterator.hasNext());

		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(3), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(2), exactSearchIterator.next());
		assertTrue(exactSearchIterator.hasNext());
		assertEquals(addr(1), exactSearchIterator.next());
		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testNextManyTimesWithoutCallingHasNext_Fowrard() {
		AddressIterator searchIterator = new NumberAddressIterator(1, 2, 3);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator }, true);

		exactSearchIterator.next();// 1
		exactSearchIterator.next();// 2
		exactSearchIterator.next();// 3

		assertFalse(exactSearchIterator.hasNext());
	}

	@Test
	public void testNextManyTimesWithoutCallingHasNext_Backward() {
		AddressIterator searchIterator = new NumberAddressIterator(3, 2, 1);

		MultiAddressIterator exactSearchIterator =
			new MultiAddressIterator(new AddressIterator[] { searchIterator }, false);

		exactSearchIterator.next();// 3
		exactSearchIterator.next();// 2
		exactSearchIterator.next();// 1

		assertFalse(exactSearchIterator.hasNext());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private Address addr(int offset) {
		return space.getAddress(offset);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class NumberAddressIterator implements AddressIterator {

		private int current = 0;
		private int[] values;

		NumberAddressIterator(int... values) {
			this.values = values;
		}

		@Override
		public boolean hasNext() {
			return current < values.length;
		}

		@Override
		public Address next() {
			return space.getAddress(values[current++]);
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}
}
