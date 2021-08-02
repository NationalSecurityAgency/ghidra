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

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.DuplicateNameException;

public class GenericAddressTest extends AbstractGenericTest {

	private AddressSpace space;
	private AddressSpace space2;
	private AddressSpace wordSpace;
	private AddressSpace regSpace;
	private AddressSpace stackSpace;
	private AddressFactory factory;

	@Before
	public void setUp() {
		space = new GenericAddressSpace("Test1", 8, AddressSpace.TYPE_RAM, 0);
		space2 = new GenericAddressSpace("Test2", 8, AddressSpace.TYPE_RAM, 1);
		wordSpace = new GenericAddressSpace("Test3", 16, 2, AddressSpace.TYPE_RAM, 1);
		regSpace = new GenericAddressSpace("Register", 8, AddressSpace.TYPE_REGISTER, 0);
		stackSpace = new GenericAddressSpace("stack", 8, AddressSpace.TYPE_STACK, 0);
		factory =
			new TestAddressFactory(new AddressSpace[] { space, space2, regSpace }, stackSpace);
		space = factory.getAddressSpace(space.getName());
		space2 = factory.getAddressSpace(space2.getName());
		regSpace = factory.getAddressSpace(regSpace.getName());
		stackSpace = factory.getAddressSpace(stackSpace.getName());
	}

	private static class TestAddressFactory extends DefaultAddressFactory {
		TestAddressFactory(AddressSpace[] deviceSpaces, AddressSpace stackSpace) {
			super(deviceSpaces);
			try {
				addAddressSpace(stackSpace);
			}
			catch (DuplicateNameException e) {
				e.printStackTrace();
				Assert.fail("Unexpected Error: " + e.toString());
			}
		}
	}

	@Test
	public void testCreateMemAddress() {

		GenericAddress addr = new GenericAddress(space, 5);
		Assert.assertEquals(5, addr.getOffset());

		try {
			addr = new GenericAddress(space, 257);
			Assert.fail("Should not have created address!");
		}
		catch (AddressOutOfBoundsException e) {
		}
		try {
			addr = new GenericAddress(space, -300);
			Assert.fail("Should not have created address!");
		}
		catch (AddressOutOfBoundsException e) {
		}
	}

	@Test
	public void testCreateWordMemAddress() throws Exception {

		Address addr = wordSpace.getAddress("0x0010.1");
		Assert.assertEquals(0x21, addr.getOffset());
		Assert.assertEquals("0x0010.1", addr.toString("0x"));

		addr = wordSpace.getAddress("0x10");
		Assert.assertEquals(0x20, addr.getOffset());
		Assert.assertEquals("0x0010", addr.toString("0x"));

		addr = wordSpace.getAddress("0xffff.1");
		Assert.assertEquals(0x1ffff, addr.getOffset());
		Assert.assertEquals("0xffff.1", addr.toString("0x"));

		try {
			addr.add(1).getOffset();
			Assert.fail();
		}
		catch (AddressOutOfBoundsException e) {
		}

		Assert.assertEquals(0, addr.addWrap(1).getOffset());

	}

	@Test
	public void testCreateRegAddress() {

		GenericAddress addr = new GenericAddress(regSpace, 5);
		Assert.assertEquals(5, addr.getOffset());

		addr = new GenericAddress(regSpace, -5);
		Assert.assertEquals(-5L & 0x0ffL, addr.getOffset());

		try {
			addr = new GenericAddress(regSpace, 1024);
			Assert.fail("Should not have created address!");
		}
		catch (AddressOutOfBoundsException e) {
		}
		try {
			addr = new GenericAddress(regSpace, -257);
			Assert.fail("Should not have created address!");
		}
		catch (AddressOutOfBoundsException e) {
		}
	}

	@Test
	public void testCreateStackAddress() {

		GenericAddress addr = new GenericAddress(stackSpace, 5);
		Assert.assertEquals(5, addr.getOffset());

		addr = new GenericAddress(stackSpace, -5);
		Assert.assertEquals(-5, addr.getOffset());

		try {
			addr = new GenericAddress(stackSpace, 256);
			Assert.fail("Should not have created address!");
		}
		catch (AddressOutOfBoundsException e) {
		}
		try {
			addr = new GenericAddress(stackSpace, -129);
			Assert.fail("Should not have created address!");
		}
		catch (AddressOutOfBoundsException e) {
		}
	}

	@Test
	public void testGetAddress() {
		GenericAddress addr = new GenericAddress(space, 5);
		Address addr2 = addr.getNewAddress(10);
		assertTrue(addr.getAddressSpace() == addr2.getAddressSpace());
		Assert.assertEquals(10, addr2.getOffset());

		addr = new GenericAddress(regSpace, 5);
		addr2 = addr.getNewAddress(-5);
		assertTrue(addr.getAddressSpace() == addr2.getAddressSpace());
		Assert.assertEquals(-5L & 0x0ffL, addr2.getOffset());
	}

	@Test
	public void testCompareTo() {
		Address addr1 = new GenericAddress(space, 10);
		Address addr2 = addr1.getNewAddress(20);
		Address addr3 = addr1.getNewAddress(10);

		assertTrue(addr1.compareTo(addr2) < 0);

		assertTrue(addr2.compareTo(addr1) > 0);

		assertTrue(addr1.compareTo(addr3) == 0);

		Address addr4 = new GenericAddress(space, 10);
		assertTrue(addr1.compareTo(addr4) == 0);

		AddressSpace sp = new GenericAddressSpace("AnotherTest", 8, AddressSpace.TYPE_RAM, 1);
		Address addr5 = new GenericAddress(sp, 30);
		assertTrue(addr5.compareTo(addr1) > 0);

	}

	@Test
	public void testCompareToWithUnSigned32AddressSpace() {
		AddressSpace space32Unsigned =
			new GenericAddressSpace("test", 32, AddressSpace.TYPE_CODE, 0);

		Address addr0 = new GenericAddress(space32Unsigned, 0);
		Address addrMax = space32Unsigned.getMaxAddress();
		Address addrPositive = new GenericAddress(space32Unsigned, 1);
		// this will not be negative, but instead will be large positive
		Address addrLargePositive = new GenericAddress(space32Unsigned, -2);

		// test both directions for all combinations of the 4 addresses
		assertEquals(-1, addr0.compareTo(addrMax));
		assertEquals(1, addrMax.compareTo(addr0));

		assertEquals(-1, addr0.compareTo(addrPositive));
		assertEquals(1, addrPositive.compareTo(addr0));

		assertEquals(-1, addr0.compareTo(addrLargePositive));
		assertEquals(1, addrLargePositive.compareTo(addr0));

		assertEquals(1, addrMax.compareTo(addrPositive));
		assertEquals(-1, addrPositive.compareTo(addrMax));

		assertEquals(1, addrMax.compareTo(addrLargePositive));
		assertEquals(-1, addrLargePositive.compareTo(addrMax));

		assertEquals(-1, addrPositive.compareTo(addrLargePositive));
		assertEquals(1, addrLargePositive.compareTo(addrPositive));
	}

	@Test
	public void testCompareToWithSigned32AddressSpace() {
		AddressSpace space32Signed =
			new GenericAddressSpace("test", 32, AddressSpace.TYPE_STACK, 0);
		Address addr0 = new GenericAddress(space32Signed, 0);
		Address addrMax = space32Signed.getMaxAddress();
		Address addrPositive = new GenericAddress(space32Signed, 1);
		Address addrNegative = new GenericAddress(space32Signed, -2);

		// test both directions for all combinations of the 4 addresses
		assertEquals(-1, addr0.compareTo(addrMax));
		assertEquals(1, addrMax.compareTo(addr0));

		assertEquals(-1, addr0.compareTo(addrPositive));
		assertEquals(1, addrPositive.compareTo(addr0));

		assertEquals(1, addr0.compareTo(addrNegative));
		assertEquals(-1, addrNegative.compareTo(addr0));

		assertEquals(1, addrMax.compareTo(addrPositive));
		assertEquals(-1, addrPositive.compareTo(addrMax));

		assertEquals(1, addrMax.compareTo(addrNegative));
		assertEquals(-1, addrNegative.compareTo(addrMax));

		assertEquals(1, addrPositive.compareTo(addrNegative));
		assertEquals(-1, addrNegative.compareTo(addrPositive));
	}

	@Test
	public void testCompareWithSigned64BitAddressSpace() {
		AddressSpace space64Signed =
			new GenericAddressSpace("test", 64, AddressSpace.TYPE_STACK, 0);

		Address addr0 = new GenericAddress(space64Signed, 0);
		Address addrMax = space64Signed.getMaxAddress();
		Address addrPositive = new GenericAddress(space64Signed, 1);
		Address addrNegative = new GenericAddress(space64Signed, -2);

		// test both directions for all combinations of the 4 addresses
		assertEquals(-1, addr0.compareTo(addrMax));
		assertEquals(1, addrMax.compareTo(addr0));

		assertEquals(-1, addr0.compareTo(addrPositive));
		assertEquals(1, addrPositive.compareTo(addr0));

		assertEquals(1, addr0.compareTo(addrNegative));
		assertEquals(-1, addrNegative.compareTo(addr0));

		assertEquals(1, addrMax.compareTo(addrPositive));
		assertEquals(-1, addrPositive.compareTo(addrMax));

		assertEquals(1, addrMax.compareTo(addrNegative));
		assertEquals(-1, addrNegative.compareTo(addrMax));

		assertEquals(1, addrPositive.compareTo(addrNegative));
		assertEquals(-1, addrNegative.compareTo(addrPositive));
	}

	@Test
	public void testCompareWithUnSigned64BitAddressSpace() {
		AddressSpace space64Signed = new GenericAddressSpace("test", 64, AddressSpace.TYPE_CODE, 0);

		Address addr0 = new GenericAddress(space64Signed, 0);
		Address addrMax = space64Signed.getMaxAddress();
		Address addrPositive = new GenericAddress(space64Signed, 1);
		// since this is unsigned space the following will actually be a large positive value
		Address addrLarge = new GenericAddress(space64Signed, -2);

		assertEquals(-1, addr0.compareTo(addrMax));
		assertEquals(1, addrMax.compareTo(addr0));

		assertEquals(-1, addr0.compareTo(addrPositive));
		assertEquals(1, addrPositive.compareTo(addr0));

		assertEquals(-1, addr0.compareTo(addrLarge));
		assertEquals(1, addrLarge.compareTo(addr0));

		assertEquals(1, addrMax.compareTo(addrPositive));
		assertEquals(-1, addrPositive.compareTo(addrMax));

		assertEquals(1, addrMax.compareTo(addrLarge));
		assertEquals(-1, addrLarge.compareTo(addrMax));

		assertEquals(-1, addrPositive.compareTo(addrLarge));
		assertEquals(1, addrLarge.compareTo(addrPositive));
	}

	@Test
	public void testEquals() {
		Address addr1 = new GenericAddress(space, 10);
		Address addr2 = addr1.getNewAddress(20);
		Address addr3 = addr1.getNewAddress(10);

		assertTrue(!addr1.equals(addr2));

		assertTrue(!addr2.equals(addr1));

		assertTrue(addr1.equals(addr3));

		Address addr4 = new GenericAddress(space, 10);
		assertTrue(addr1.equals(addr4));

		AddressSpace sp = new GenericAddressSpace("AnotherTest", 8, AddressSpace.TYPE_RAM, 1);
		Address addr5 = new GenericAddress(sp, 10);
		assertTrue(!addr5.equals(addr1));

	}

	@Test
	public void testAddSubtract() {
		Address a1 = new GenericAddress(space, 10);
		Address b1 = new GenericAddress(space, 20);
		long diff = b1.subtract(a1);
		Assert.assertEquals(10, diff);
		Address a2 = new GenericAddress(space2, 10);
		Assert.assertEquals(new GenericAddress(space2, 20), a2.add(diff));
	}

	@Test
	public void testAddWrap() {
		Address a1 = new GenericAddress(space, 10);
		long offset = 0x100L;
		Address a2 = a1.addWrap(offset);
		Assert.assertEquals(10, a2.getOffset());
	}

	@Test
	public void testSubtractWrap() {
		Address a1 = new GenericAddress(space, 10);
		long offset = 0x100L;
		Address a2 = a1.subtractWrap(offset);
		Assert.assertEquals(10, a2.getOffset());
	}

	@Test
	public void testAddSubtractWrap() {
		Address a1 = new GenericAddress(space, 10);
		long offset = 0x7fffffffffL;
		Address a2 = a1.addWrap(offset);
		Address a3 = a2.subtractWrap(offset);
		Assert.assertEquals(a1, a3);
	}

	@Test
	public void testNext() {
		Address a1 = new GenericAddress(space, 0);
		Assert.assertEquals(new GenericAddress(space, 1), a1.next());
		assertNull(a1.previous());

		a1 = space.getMaxAddress();
		Assert.assertEquals(null, a1.next());

		a1 = space2.getMaxAddress();
		assertNull(a1.next());
		Assert.assertEquals(new GenericAddress(space2, space2.getMaxAddress().getOffset() - 1),
			a1.previous());
	}

}
