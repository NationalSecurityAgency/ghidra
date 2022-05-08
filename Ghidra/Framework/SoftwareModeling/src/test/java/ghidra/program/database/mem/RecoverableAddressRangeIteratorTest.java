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
package ghidra.program.database.mem;

import static org.junit.Assert.*;

import java.util.NoSuchElementException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;

public class RecoverableAddressRangeIteratorTest extends AbstractGenericTest {

	private AddressSpace space;
	private AddressSet set;

	@Before
	public void setUp() throws Exception {

		space = new GenericAddressSpace("xx", 32, AddressSpace.TYPE_RAM, 0);

		set = new AddressSet();
		set.add(range(0x100, 0x200));
		set.add(range(0x250, 0x250));
		set.add(range(0x300, 0x400));
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	private AddressRange range(long start, long end) {
		return new AddressRangeImpl(addr(start), addr(end));
	}

	@Test
	public void test1Forward() {

		AddressRangeIterator it = new RecoverableAddressRangeIterator(set, addr(150), true);

		assertTrue(it.hasNext());
		assertEquals(range(0x100, 0x200), it.next()); // triggers prefetch of range(0x250, 0x250)

		set.add(addr(0x220)); // will get skipped due to underlying iterator prefetch

		assertEquals(range(0x250, 0x250), it.next()); // triggers prefetch of range(0x300, 0x400)

		set.add(range(0x350, 0x500)); // modifies existing RedBlackEntry node - no iterator recovery triggered

		assertEquals(range(0x300, 0x400), it.next()); // triggers prefetch of END

		assertFalse(it.hasNext());

		try {
			it.next();
			fail("Expected NoSuchElementException");
		}
		catch (NoSuchElementException e) {
			// expected
		}
	}

	@Test
	public void test2Forward() {

		AddressRangeIterator it = new RecoverableAddressRangeIterator(set, addr(150), true);

		assertTrue(it.hasNext());
		assertEquals(range(0x100, 0x200), it.next()); // triggers prefetch of range(0x250, 0x250)

		set.add(range(0x220, 0x400));

		assertEquals(range(0x250, 0x250), it.next()); // triggers recovery prefetch of partial range(0x251, 0x400) 

		assertEquals(range(0x251, 0x400), it.next()); // triggers prefetch of END

		assertFalse(it.hasNext());
	}

	@Test
	public void test3Forward() {

		AddressRangeIterator it = new RecoverableAddressRangeIterator(set, addr(150), true);

		assertTrue(it.hasNext());
		assertEquals(range(0x100, 0x200), it.next()); // triggers prefetch of range(0x250, 0x250)

		set.delete(range(0x220, 0x400));

		assertEquals(range(0x250, 0x250), it.next()); // triggers recovery prefetch of END

		assertFalse(it.hasNext());
	}

	@Test
	public void test1Reverse() {

		AddressRangeIterator it = new RecoverableAddressRangeIterator(set, addr(0x350), false);

		assertTrue(it.hasNext());
		assertEquals(range(0x300, 0x400), it.next()); // triggers prefetch of range(0x250, 0x250)

		set.add(addr(0x220));

		assertEquals(range(0x250, 0x250), it.next()); // triggers recovery prefetch of range(0x220, 0x220)

		assertEquals(range(0x220, 0x220), it.next()); // triggers prefetch of range(0x100, 0x200)

		assertEquals(range(0x100, 0x200), it.next()); // triggers prefetch of END

		assertFalse(it.hasNext());
	}

	@Test
	public void test2Reverse() {

		AddressRangeIterator it = new RecoverableAddressRangeIterator(set, addr(0x350), false);

		assertTrue(it.hasNext());
		assertEquals(range(0x300, 0x400), it.next()); // triggers prefetch of range(0x250, 0x250)

		set.add(range(0x220, 0x380));

		assertEquals(range(0x250, 0x250), it.next()); // triggers recovery prefetch of partial range(0x220, 0x24f) 

		assertEquals(range(0x220, 0x24f), it.next()); // triggers prefetch of range(0x100, 0x200)

		assertEquals(range(0x100, 0x200), it.next()); // triggers prefetch of END

		assertFalse(it.hasNext());
	}

	@Test
	public void test3Reverse() {

		AddressRangeIterator it = new RecoverableAddressRangeIterator(set, addr(0x350), false);

		assertTrue(it.hasNext());
		assertEquals(range(0x300, 0x400), it.next()); // triggers prefetch of range(0x250, 0x250)

		set.delete(range(0x100, 0x220));

		assertEquals(range(0x250, 0x250), it.next()); // triggers recovery prefetch of END

		assertFalse(it.hasNext());
	}

}
