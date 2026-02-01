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
package ghidra.program.model.address;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class AddressRangeSplitterTest {
	private AddressSpace space;

	@Before
	public void setUp() {
		space = new GenericAddressSpace("test", 64, AddressSpace.TYPE_RAM, 0);
	}

	@Test
	public void testRangeDoesntNeedSplitting() {
		AddressRange range = range(0, 100);
		AddressRangeSplitter splitter = new AddressRangeSplitter(range, 1000, true);
		assertTrue(splitter.hasNext());
		assertEquals(range(0, 100), splitter.next());
		assertFalse(splitter.hasNext());
		assertNull(splitter.next());
	}

	@Test
	public void testRangeSplitting() {
		AddressRange range = range(0, 500);
		AddressRangeSplitter splitter = new AddressRangeSplitter(range, 100, true);

		assertTrue(splitter.hasNext());
		assertEquals(range(0, 99), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(100, 199), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(200, 299), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(300, 399), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(400, 499), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(500, 500), splitter.next());

		assertFalse(splitter.hasNext());
		assertNull(splitter.next());
	}

	@Test
	public void testSplittingRangeWhoseLengthIsLong() {
		AddressRange range = range(0, 0xffffffffffffffffL);
		AddressRangeSplitter splitter = new AddressRangeSplitter(range, 100, true);

		assertTrue(splitter.hasNext());
		assertEquals(range(0, 99), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(100, 199), splitter.next());
		assertTrue(splitter.hasNext());

	}

	@Test
	public void testReverseRangeDoesntNeedSplitting() {
		AddressRange range = range(0, 100);
		AddressRangeSplitter splitter = new AddressRangeSplitter(range, 1000, true);
		assertTrue(splitter.hasNext());
		assertEquals(range(0, 100), splitter.next());
		assertFalse(splitter.hasNext());
		assertNull(splitter.next());
	}

	@Test
	public void testReverseRangeSplitting() {
		AddressRange range = range(0, 500);
		AddressRangeSplitter splitter = new AddressRangeSplitter(range, 100, false);

		assertTrue(splitter.hasNext());
		assertEquals(range(401, 500), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(301, 400), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(201, 300), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(101, 200), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(1, 100), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(0, 0), splitter.next());

		assertFalse(splitter.hasNext());
		assertNull(splitter.next());
	}

	@Test
	public void testReverseSplittingRangeWhoseLengthIsLong() {
		AddressRange range = range(0, 0xffffffffffffffffL);
		AddressRangeSplitter splitter = new AddressRangeSplitter(range, 0x100, false);

		assertTrue(splitter.hasNext());
		assertEquals(range(0xffffffffffffff00L, 0xffffffffffffffffL), splitter.next());
		assertTrue(splitter.hasNext());
		assertEquals(range(0xfffffffffffffe00L, 0xfffffffffffffeffL), splitter.next());
		assertTrue(splitter.hasNext());

	}

	private AddressRange range(long start, long end) {
		return new AddressRangeImpl(addr(start), addr(end));
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}
}
