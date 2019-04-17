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

public class GenericAddressSpaceTest extends AbstractGenericTest {

	private GenericAddressSpace space;

	@Before
	public void setUp() {
		space = new GenericAddressSpace("Test", 8, AddressSpace.TYPE_RAM, 0);
	}

	@Test
	public void testCreateAddressSpace() {

		Assert.assertEquals("Test", space.getName());
		Assert.assertEquals(8, space.getSize());

	}

	@Test
	public void testGetAddress() {
		try {
			Address addr = space.getAddress("10");
			Assert.assertEquals(0x10, addr.getOffset());

			addr = space.getAddress("Test:20");
			Assert.assertEquals(0x20, addr.getOffset());

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
			space.getAddress("Test:256");
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
			space.getAddress("256");
			Assert.fail("Should not have given back an address!");
		}
		catch (AddressFormatException e) {
		}
	}

	private Address addr(long offset) {
		return new GenericAddress(space, offset);
	}

	@Test
	public void testSubtract() {

		Assert.assertEquals(16, space.subtract(addr(32), addr(16)));
		Assert.assertEquals(-16, space.subtract(addr(0), addr(16)));
		Assert.assertEquals(0, space.subtract(addr(16), addr(16)));

		AddressSpace sp2 = new GenericAddressSpace("SpaceTwo", 16, AddressSpace.TYPE_RAM, 0);
		Address addr2 = new GenericAddress(sp2, 16);

		try {
			space.subtract(addr(16), addr2);
			Assert.fail("Subtract should have failed!");
		}
		catch (IllegalArgumentException e) {
		}

		Assert.assertEquals(addr(2), space.subtractWrap(addr(5), 3));
		Assert.assertEquals(addr(251), space.subtractWrap(addr(5), 10));
		Assert.assertEquals(addr(9), space.subtractWrap(addr(5), -4));
		Assert.assertEquals(addr(5), space.subtractWrap(addr(5), -1024));
		Assert.assertEquals(addr(5), space.subtractWrap(addr(5), 1024));

		try {
			Assert.assertEquals(addr(2), space.subtractNoWrap(addr(5), 3));

			Assert.assertEquals(addr(9), space.subtractNoWrap(addr(5), -4));
		}
		catch (AddressOverflowException e) {
			Assert.fail(e.getMessage());
		}

		try {
			space.subtractNoWrap(addr(5), -1024);
			Assert.fail("Should not have gotten a value!");
		}
		catch (AddressOverflowException e) {
		}
		try {
			space.subtractNoWrap(addr(5), 1024);
			Assert.fail("Should not have gotten a value!");
		}
		catch (AddressOverflowException e) {
		}

	}

	@Test
	public void testAdd() {

		Assert.assertEquals(addr(8), space.addWrap(addr(5), 3));
		Assert.assertEquals(addr(1), space.addWrap(addr(5), -4));
		Assert.assertEquals(addr(5), space.addWrap(addr(5), -1024));
		Assert.assertEquals(addr(5), space.addWrap(addr(5), 1024));

		try {
			Assert.assertEquals(addr(8), space.addNoWrap(addr(5), 3));

			Assert.assertEquals(addr(1), space.addNoWrap(addr(5), -4));
		}
		catch (AddressOverflowException e) {
			Assert.fail(e.getMessage());
		}

		try {
			space.addNoWrap(addr(5), -1024);
			Assert.fail("Should not have gotten a value!");
		}
		catch (AddressOverflowException e) {
		}
		try {
			space.addNoWrap(addr(5), 1024);
			Assert.fail("Should not have gotten a value!");
		}
		catch (AddressOverflowException e) {
		}

	}

	@Test
	public void testIsSuccessor() {

		assertTrue(space.isSuccessor(addr(3), addr(4)));

		assertTrue(!space.isSuccessor(addr(4), addr(4)));
		assertTrue(!space.isSuccessor(addr(5), addr(4)));
		assertTrue(!space.isSuccessor(addr(0xff), addr(4)));

		AddressSpace sp2 = new GenericAddressSpace("AnotherSpace", 8, AddressSpace.TYPE_RAM, 1);

		Address a = new GenericAddress(sp2, 2);
		assertTrue(!space.isSuccessor(addr(1), a));

	}

	@Test
	public void testCompareTo() {
		AddressSpace sp2 = new GenericAddressSpace("AnotherSpace", 8, AddressSpace.TYPE_RAM, 1);
		Assert.assertEquals(0, space.compareTo(space));
		assertTrue(space.compareTo(sp2) < 0);

		sp2 = new GenericAddressSpace("Test", 16, AddressSpace.TYPE_RAM, 1);
		assertTrue(space.compareTo(sp2) == 0); // only name and type are considered

		sp2 = new GenericAddressSpace("Test", 8, AddressSpace.TYPE_RAM, 2);
		assertTrue(space.compareTo(sp2) == 0); // only name and type are considered

	}

	@Test
	public void testEquals() {
		AddressSpace sp2 = new GenericAddressSpace("AnotherSpace", 8, AddressSpace.TYPE_RAM, 1);
		assertTrue(!space.equals(sp2));

		assertTrue(space.equals(space));

		sp2 = new GenericAddressSpace("Test", 16, AddressSpace.TYPE_RAM, 1);
		assertTrue(!space.equals(sp2));

		sp2 = new GenericAddressSpace("Test", 8, AddressSpace.TYPE_RAM, 2);
		assertTrue(space.equals(sp2));

	}

	@Test
	public void testAddressTruncation() throws Exception {

		AddressSpace space1 = new GenericAddressSpace("space1", 31, 2, AddressSpace.TYPE_RAM, 0);
		AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] { space1 });
		space1 = factory.getAddressSpace(space1.getName());

		assertEquals(0x25, space1.truncateOffset(0x25));
		assertEquals(0x25, space1.truncateOffset(0x200000025L));

		assertEquals(0x15, space1.truncateAddressableWordOffset(0x15));
		assertEquals(0x15, space1.truncateAddressableWordOffset(0x80000015));

		Address addr = space1.getTruncatedAddress(0x200000025L, false);
		assertEquals(space1, addr.getAddressSpace());
		assertEquals(0x25, addr.getOffset());

		addr = space1.getTruncatedAddress(0x80000015L, true);
		assertEquals(space1, addr.getAddressSpace());
		assertEquals(0x15, addr.getAddressableWordOffset());
	}

	@Test
	public void testWrapUnsigned() {
		AddressSpace sp2 = new GenericAddressSpace("AnotherSpace", 8, AddressSpace.TYPE_RAM, 1);

		Assert.assertEquals(0x1, sp2.truncateOffset(0x1));
		Assert.assertEquals(0x7f, sp2.truncateOffset(0x7f));
		Assert.assertEquals(0xff, sp2.truncateOffset(0xff));
		Assert.assertEquals(0x0, sp2.truncateOffset(0x100));
		Assert.assertEquals(0x7f, sp2.truncateOffset(0x17f));
		Assert.assertEquals(0x80, sp2.truncateOffset(0x180));
		Assert.assertEquals(0xff, sp2.truncateOffset(-0x1));
		Assert.assertEquals(0x81, sp2.truncateOffset(-0x7f));
		Assert.assertEquals(0x80, sp2.truncateOffset(-0x80));
		Assert.assertEquals(0x7f, sp2.truncateOffset(-0x81));
		Assert.assertEquals(0x80, sp2.truncateOffset(-0x180));
	}

	@Test
	public void testWrapSigned() {
		AddressSpace sp2 =
			new GenericAddressSpace("AnotherSpace", 8, AddressSpace.TYPE_CONSTANT, 1);

		Assert.assertEquals(0x1, sp2.truncateOffset(0x1));
		Assert.assertEquals(0x7f, sp2.truncateOffset(0x7f));
		Assert.assertEquals(-0x1, sp2.truncateOffset(0xff));
		Assert.assertEquals(0x0, sp2.truncateOffset(0x100));
		Assert.assertEquals(0x7f, sp2.truncateOffset(0x17f));
		Assert.assertEquals(-0x80, sp2.truncateOffset(0x180));
		Assert.assertEquals(-0x1, sp2.truncateOffset(-0x1));
		Assert.assertEquals(-0x7f, sp2.truncateOffset(-0x7f));
		Assert.assertEquals(-0x80, sp2.truncateOffset(-0x80));
		Assert.assertEquals(0x7f, sp2.truncateOffset(-0x81));
		Assert.assertEquals(-0x80, sp2.truncateOffset(-0x180));
	}

	@Test
	public void testGetAddressableWordOffset() {
		AddressSpace sp1 = new GenericAddressSpace("AnotherSpace", 64, AddressSpace.TYPE_CODE, 1);
		AddressSpace sp2 =
			new GenericAddressSpace("AnotherSpace", 63, 2, AddressSpace.TYPE_CODE, 2);
		AddressSpace sp3 =
			new GenericAddressSpace("AnotherSpace", 62, 3, AddressSpace.TYPE_CODE, 3);

		Assert.assertEquals(Long.MIN_VALUE, sp1.getAddressableWordOffset(Long.MIN_VALUE));
		Assert.assertEquals(Long.MIN_VALUE + 1, sp1.getAddressableWordOffset(Long.MIN_VALUE + 1));
		Assert.assertEquals(-1, sp1.getAddressableWordOffset(-1));
		Assert.assertEquals(-2, sp1.getAddressableWordOffset(-2));
		Assert.assertEquals(0, sp1.getAddressableWordOffset(0));
		Assert.assertEquals(1, sp1.getAddressableWordOffset(1));
		Assert.assertEquals(Long.MAX_VALUE - 1, sp1.getAddressableWordOffset(Long.MAX_VALUE - 1));
		Assert.assertEquals(Long.MAX_VALUE, sp1.getAddressableWordOffset(Long.MAX_VALUE));

		Assert.assertEquals(Long.MIN_VALUE >>> 1, sp2.getAddressableWordOffset(Long.MIN_VALUE));
		Assert.assertEquals(Long.MIN_VALUE >>> 1, sp2.getAddressableWordOffset(Long.MIN_VALUE + 1));
		Assert.assertEquals(0x7fffffffffffffffL, sp2.getAddressableWordOffset(-1));
		Assert.assertEquals(0x7fffffffffffffffL, sp2.getAddressableWordOffset(-2));
		Assert.assertEquals(0x7ffffffffffffffeL, sp2.getAddressableWordOffset(-3));
		Assert.assertEquals(0x7ffffffffffffffeL, sp2.getAddressableWordOffset(-4));
		Assert.assertEquals(0, sp2.getAddressableWordOffset(0));
		Assert.assertEquals(0, sp2.getAddressableWordOffset(1));
		Assert.assertEquals(Long.MAX_VALUE >>> 1, sp2.getAddressableWordOffset(Long.MAX_VALUE - 1));
		Assert.assertEquals(Long.MAX_VALUE >>> 1, sp2.getAddressableWordOffset(Long.MAX_VALUE));

		Assert.assertEquals(0x3fffffffffffffffL, sp3.getAddressableWordOffset(0xbfffffffffffffffL));
		Assert.assertEquals(0x3fffffffffffffffL, sp3.getAddressableWordOffset(0xbffffffffffffffeL));
		Assert.assertEquals(0x3fffffffffffffffL, sp3.getAddressableWordOffset(0xbffffffffffffffdL));
		Assert.assertEquals(0x3ffffffffffffffeL, sp3.getAddressableWordOffset(0xbffffffffffffffcL));
		Assert.assertEquals(0x3ffffffffffffffeL, sp3.getAddressableWordOffset(0xbffffffffffffffbL));
		Assert.assertEquals(0x3ffffffffffffffeL, sp3.getAddressableWordOffset(0xbffffffffffffffaL));
		Assert.assertEquals(0, sp3.getAddressableWordOffset(0));
		Assert.assertEquals(0, sp3.getAddressableWordOffset(1));
		Assert.assertEquals(0, sp3.getAddressableWordOffset(2));
		Assert.assertEquals(1, sp3.getAddressableWordOffset(3));
		Assert.assertEquals(1, sp3.getAddressableWordOffset(4));
		Assert.assertEquals(1, sp3.getAddressableWordOffset(5));
		Assert.assertEquals(0x2aaaaaaaaaaaaaaaL, sp3.getAddressableWordOffset(0x8000000000000000L));
		Assert.assertEquals(0x2aaaaaaaaaaaaaaaL, sp3.getAddressableWordOffset(0x7fffffffffffffffL));
		Assert.assertEquals(0x2aaaaaaaaaaaaaaaL, sp3.getAddressableWordOffset(0x7ffffffffffffffeL));
		Assert.assertEquals(0x2aaaaaaaaaaaaaa9L, sp3.getAddressableWordOffset(0x7ffffffffffffffdL));
		Assert.assertEquals(0x2aaaaaaaaaaaaaa9L, sp3.getAddressableWordOffset(0x7ffffffffffffffcL));
		Assert.assertEquals(0x2aaaaaaaaaaaaaa9L, sp3.getAddressableWordOffset(0x7ffffffffffffffbL));
	}

}
