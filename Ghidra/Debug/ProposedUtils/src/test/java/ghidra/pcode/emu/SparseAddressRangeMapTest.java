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
package ghidra.pcode.emu;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.model.address.*;

public class SparseAddressRangeMapTest {
	AddressSpace space = new GenericAddressSpace("test", 64, AddressSpace.TYPE_RAM, 0);

	Address addr(long off) {
		return space.getAddress(off);
	}

	AddressRange range(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	@Test
	public void testIsEmpty() {
		SparseAddressRangeMap<String> map = new SparseAddressRangeMap<>();
		assertTrue(map.isEmpty());

		map.put(range(0x0, 0xff), "Hello!");
		assertFalse(map.isEmpty());

		map.clear();
		assertTrue(map.isEmpty());
	}

	@Test
	public void testHasEntry() {
		SparseAddressRangeMap<String> map = new SparseAddressRangeMap<>();
		assertFalse(map.hasEntry(addr(0x0f), "Hello!"::equals));

		map.put(range(0x0, 0xff), "Hello!");
		assertTrue(map.hasEntry(addr(0x0f), "Hello!"::equals));
		assertFalse(map.hasEntry(addr(0x100), "Hello!"::equals));
		assertFalse(map.hasEntry(addr(0x0f), "Good bye!"::equals));

		map.clear();
		assertFalse(map.hasEntry(addr(0x0f), "Hello!"::equals));
	}

	@Test
	public void testHasEntrySpansPages() {
		SparseAddressRangeMap<String> map = new SparseAddressRangeMap<>();
		map.put(range(0x100, 0x1100), "Hello!");
		assertTrue(map.hasEntry(addr(0x0fff), "Hello!"::equals));
		assertTrue(map.hasEntry(addr(0x1000), "Hello!"::equals));
	}

	@Test
	public void testHasEntryOverlapping() {
		SparseAddressRangeMap<String> map = new SparseAddressRangeMap<>();
		map.put(range(0x0, 0xff), "Hello!");
		map.put(range(0x10, 0x10f), "Good bye!");
		assertTrue(map.hasEntry(addr(0x0f), "Hello!"::equals));
		assertTrue(map.hasEntry(addr(0x20), "Hello!"::equals));
		assertTrue(map.hasEntry(addr(0x20), "Good bye!"::equals));
		assertTrue(map.hasEntry(addr(0x100), "Good bye!"::equals));
	}
}
