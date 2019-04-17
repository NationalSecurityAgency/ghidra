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

import static org.junit.Assert.assertTrue;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class SegmentedAddressTest extends AbstractGenericTest {

	private SegmentedAddressSpace space;

	@Before
	public void setUp() {
		space = new SegmentedAddressSpace("Test", 1);
	}

	@Test
	public void testGetSegment() {
		try {
			SegmentedAddress addr = (SegmentedAddress) space.getAddress("123:1000");
			Assert.assertEquals(0x123, addr.getSegment());
		}
		catch (AddressFormatException e) {
		}
	}

	@Test
	public void testCompareTo() {
		assertTrue(addr(0, 0).compareTo(addr(0, 0)) == 0);
		assertTrue(addr(0, 1).compareTo(addr(0, 0)) > 0);
		assertTrue(addr(0, 0).compareTo(addr(0, 1)) < 0);
		assertTrue(addr(0, 1).compareTo(addr(1, 0)) < 0);
		assertTrue(addr(1, 0).compareTo(addr(0, 1)) > 0);
		assertTrue(addr(0x1234, 0x5).compareTo(addr(0x1000, 0x2345)) == 0);

		AddressSpace sp = new GenericAddressSpace("Test", 20, AddressSpace.TYPE_RAM, 0);
		Address a = new GenericAddress(sp, 0);

		assertTrue(addr(0, 0).compareTo(a) > 0);

	}

	@Test
	public void testEquals() {
		assertTrue(addr(0, 0).equals(addr(0, 0)));
		assertTrue(!addr(0, 1).equals(addr(0, 0)));
		assertTrue(addr(0x1234, 0x5).equals(addr(0x1000, 0x2345)));

		AddressSpace sp = new GenericAddressSpace("Test", 8, AddressSpace.TYPE_RAM, 0);
		Address a = new GenericAddress(sp, 0);
		assertTrue(!addr(0, 0).equals(a));
	}

	private SegmentedAddress addr(int seg, long off) {
		return new SegmentedAddress(space, seg, (int) off);
	}

	@Test
	public void testAddressSet() {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x8000, 0), addr(0xf000, 0xffff));
		Assert.assertEquals(0x80000, set.getNumAddresses());
		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x8000, 0), addr(0x8000, 0xffff));
		Assert.assertEquals(0x10000, set2.getNumAddresses());
		assertTrue(set.intersects(set2));
		AddressSet set3 = set.intersect(set2);
		Assert.assertEquals(0x10000, set3.getNumAddresses());
	}

}
