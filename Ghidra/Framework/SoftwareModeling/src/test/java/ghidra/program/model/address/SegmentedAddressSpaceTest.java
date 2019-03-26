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

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.*;

import generic.test.AbstractGenericTest;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 */
public class SegmentedAddressSpaceTest extends AbstractGenericTest {

	private SegmentedAddressSpace space;

	public SegmentedAddressSpaceTest() {
		super();
	}

    @Before
    public void setUp() {
		space = new SegmentedAddressSpace("Test", 0);
	}

@Test
    public void testCreateAddressSpace() {

		Assert.assertEquals("Test", space.getName());
		Assert.assertEquals(21, space.getSize());

	}

@Test
    public void testGetAddress() {
		try {
			SegmentedAddress addr = (SegmentedAddress) space.getAddress("12345");
			Assert.assertEquals(0x2345, addr.getSegmentOffset());
			Assert.assertEquals(0x1000, addr.getSegment());
			Assert.assertEquals(0x12345, addr.getOffset());

			addr = (SegmentedAddress) space.getAddress("1000:2345");

			Assert.assertEquals(0x2345, addr.getSegmentOffset());
			Assert.assertEquals(0x1000, addr.getSegment());
			Assert.assertEquals(0x12345, addr.getOffset());

			addr = (SegmentedAddress) space.getAddress("Test:12345");
			Assert.assertEquals(0x2345, addr.getSegmentOffset());
			Assert.assertEquals(0x1000, addr.getSegment());
			Assert.assertEquals(0x12345, addr.getOffset());

			addr = (SegmentedAddress) space.getAddress("Test:1000:2345");
			Assert.assertEquals(0x2345, addr.getSegmentOffset());
			Assert.assertEquals(0x1000, addr.getSegment());
			Assert.assertEquals(0x12345, addr.getOffset());

		}
		catch (AddressFormatException e) {
			Assert.fail(e.getMessage());
		}

		try {
			Address addr = space.getAddress(":10");
			assertNull(addr);

			addr = space.getAddress("Foo:0");
			assertNull(addr);

		}
		catch (AddressFormatException e) {
			Assert.fail(e.getMessage());
		}

		try {
			space.getAddress("3:ffffff");
			Assert.fail("Should not have given back an address!");
		}
		catch (AddressFormatException e) {
		}
		try {
			space.getAddress("Testxyz");
			Assert.fail("Should not have given back an address!");
		}
		catch (AddressFormatException e) {
		}
		try {
			space.getAddress("ffffff");
			Assert.fail("Should not have given back an address!");
		}
		catch (AddressFormatException e) {
		}
	}

	private SegmentedAddress addr(int seg, long off) {
		return new SegmentedAddress(space, seg, (int) off);
	}

@Test
    public void testSubtract() {

		Assert.assertEquals(10, space.subtract(addr(1, 32), addr(1, 22)));
		Assert.assertEquals(-16, space.subtract(addr(5, 0), addr(5, 16)));
		Assert.assertEquals(0, space.subtract(addr(3, 12), addr(3, 12)));
		Assert.assertEquals(0, space.subtract(addr(2, 0), addr(0, 32)));
		Assert.assertEquals(16, space.subtract(addr(1, 0), addr(0, 0)));
		Assert.assertEquals(-16, space.subtract(addr(0, 0), addr(1, 0)));

		SegmentedAddressSpace sp2 = new SegmentedAddressSpace("SpaceTwo", 2);
		SegmentedAddress addr2 = new SegmentedAddress(sp2, 0, 0);

		try {
			space.subtract(addr(0, 0), addr2);
			Assert.fail("Subtract should have failed!");
		}
		catch (IllegalArgumentException e) {
		}

		Assert.assertEquals(addr(4, 2), space.subtract(addr(4, 5), 3));
		Assert.assertEquals(addr(0, 0x2f), space.subtract(addr(3, 0), 1));
		Assert.assertEquals(addr(13, 9), space.subtract(addr(13, 5), -4));
		try {
			Assert.assertEquals(addr(0, 0), space.subtract(addr(0, 0), 0x100000));
			Assert.fail();
		}
		catch (AddressOutOfBoundsException e) {
		}

		try {
			Assert.assertEquals(addr(0, 2), space.subtractNoWrap(addr(0, 5), 3));

			Assert.assertEquals(addr(3, 9), space.subtractNoWrap(addr(3, 5), -4));
		}
		catch (AddressOverflowException e) {
			Assert.fail(e.getMessage());
		}

		try {
			space.subtractNoWrap(addr(0, 5), 0x10000);
			Assert.fail("Should not have gotten a value!");
		}
		catch (AddressOverflowException e) {
		}

	}

@Test
    public void testAdd() {

		Assert.assertEquals(addr(0, 8), space.add(addr(0, 5), 3));
		Assert.assertEquals(addr(10, 1), space.add(addr(10, 5), -4));
		Assert.assertEquals(addr(0xffff, 0xffff), space.add(addr(0, 0), 0x10FFEF));

		try {
			space.add(addr(0, 1), 0x10FFEF);
			Assert.fail();
		}
		catch (AddressOutOfBoundsException e) {
		}

		try {
			Assert.assertEquals(addr(2, 8), space.addNoWrap(addr(2, 5), 3));
			Assert.assertEquals(addr(0, 1), space.addNoWrap(addr(0, 5), -4));
		}
		catch (AddressOverflowException e) {
			Assert.fail(e.getMessage());
		}

		try {
			space.addNoWrap(addr(0xffff, 5), 0x10000);
			Assert.fail("Should not have gotten a value!");
		}
		catch (AddressOverflowException e) {
		}

	}

@Test
    public void testIsSuccessor() {

		assertTrue(space.isSuccessor(addr(3, 4), addr(3, 5)));
		assertTrue(space.isSuccessor(addr(0, 0xffff), addr(0x1000, 0)));
		assertTrue(space.isSuccessor(addr(0x1000, 0x2345), addr(0x1200, 0x0346)));

		assertTrue(!space.isSuccessor(addr(3, 5), addr(3, 4)));
		assertTrue(!space.isSuccessor(addr(3, 4), addr(3, 6)));
		assertTrue(!space.isSuccessor(addr(2, 5), addr(3, 5)));
		assertTrue(!space.isSuccessor(addr(2, 5), addr(3, 6)));

		Address a = new SegmentedAddress(space, 0, 0);
		Address b = new SegmentedAddress(space, 1, 0);
		assertTrue(!space.isSuccessor(a, b));

	}

@Test
    public void testCompareTo() {
		AddressSpace sp2 = new SegmentedAddressSpace("AnotherSpace", 3);
		assertTrue(space.compareTo(space) == 0);
		assertTrue(space.compareTo(sp2) < 0);

		sp2 = new GenericAddressSpace("Test", 16, AddressSpace.TYPE_RAM, 0);
		assertTrue(space.compareTo(sp2) > 0);

		sp2 = new GenericAddressSpace("Test", 20, AddressSpace.TYPE_RAM, 1);
		assertTrue(space.compareTo(sp2) < 0);

		sp2 = new SegmentedAddressSpace("Test", 0);
		assertTrue(space.compareTo(sp2) == 0);

	}

@Test
    public void testEquals() {
		AddressSpace sp2 = new GenericAddressSpace("AnotherSpace", 8, AddressSpace.TYPE_RAM, 1);
		assertTrue(!space.equals(sp2));

		assertTrue(space.equals(space));

		sp2 = new GenericAddressSpace("Test", 16, AddressSpace.TYPE_RAM, 2);
		assertTrue(!space.equals(sp2));

		sp2 = new GenericAddressSpace("Test", 20, AddressSpace.TYPE_RAM, 3);
		assertTrue(!space.equals(sp2));

		sp2 = new SegmentedAddressSpace("Test", 0);
		assertTrue(space.equals(sp2));

	}

}
