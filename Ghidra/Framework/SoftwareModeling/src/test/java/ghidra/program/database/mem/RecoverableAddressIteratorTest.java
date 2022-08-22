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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;

public class RecoverableAddressIteratorTest extends AbstractGenericTest {

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

	private void assertHasAddressRange(AddressRange range, boolean forward, AddressIterator it) {
		Address nextAddr, endAddr;
		if (forward) {
			nextAddr = range.getMinAddress();
			endAddr = range.getMaxAddress();
		}
		else {
			nextAddr = range.getMaxAddress();
			endAddr = range.getMinAddress();
		}
		while (true) {
			assertEquals(nextAddr, it.next());
			if (nextAddr.equals(endAddr)) {
				break;
			}
			nextAddr = forward ? nextAddr.next() : nextAddr.previous();
		}
	}

	@Test
	public void test1Forward() {

		AddressIterator it = new RecoverableAddressIterator(set, addr(0x150), true);

		assertTrue(it.hasNext());

		set.add(range(0x350, 0x500));

		assertHasAddressRange(range(0x150, 0x200), true, it);

		set.add(addr(0x220)); // will get skipped due to underlying iterator prefetch

		assertHasAddressRange(range(0x250, 0x250), true, it);

		assertHasAddressRange(range(0x300, 0x400), true, it);

		assertHasAddressRange(range(0x401, 0x500), true, it);

		assertFalse(it.hasNext());
		assertNull(it.next());
	}

	@Test
	public void test2Forward() {

		AddressIterator it = new RecoverableAddressIterator(set, addr(0x150), true);

		assertTrue(it.hasNext());

		set.add(range(0x210, 0x215));

		assertHasAddressRange(range(0x150, 0x200), true, it);

		set.add(range(0x220, 0x500));

		assertHasAddressRange(range(0x210, 0x215), true, it);

		assertHasAddressRange(range(0x220, 0x500), true, it);

		assertFalse(it.hasNext());
	}

	@Test
	public void test3Forward() {

		AddressIterator it = new RecoverableAddressIterator(set, addr(0x150), true);

		assertTrue(it.hasNext());

		set.add(range(0x210, 0x215));

		assertHasAddressRange(range(0x150, 0x200), true, it);

		set.delete(range(0x220, 0x500));

		assertHasAddressRange(range(0x210, 0x215), true, it);

		assertFalse(it.hasNext());
	}

	@Test
	public void test1Reverse() {

		AddressIterator it = new RecoverableAddressIterator(set, addr(0x350), false);

		assertTrue(it.hasNext());

		set.add(addr(0x240));

		assertHasAddressRange(range(0x300, 0x350), false, it);

		set.add(range(0x50, 0x150));

		assertHasAddressRange(range(0x250, 0x250), false, it);

		set.add(range(0x50, 0x150));

		assertHasAddressRange(range(0x240, 0x240), false, it);

		assertHasAddressRange(range(0x50, 0x200), false, it);

		assertFalse(it.hasNext());
	}

	@Test
	public void test2Reverse() {

		AddressIterator it = new RecoverableAddressIterator(set, addr(0x350), false);

		assertTrue(it.hasNext());

		set.add(addr(0x240));

		assertHasAddressRange(range(0x300, 0x350), false, it);

		set.delete(range(0x100, 0x200));

		assertHasAddressRange(range(0x250, 0x250), false, it);

		assertHasAddressRange(range(0x240, 0x240), false, it);

		assertFalse(it.hasNext());
	}

}
