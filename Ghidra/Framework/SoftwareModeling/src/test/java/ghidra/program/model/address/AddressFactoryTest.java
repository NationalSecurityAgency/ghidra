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

public class AddressFactoryTest extends AbstractGenericTest {
	AddressSpace space = null;
	AddressFactory factory = null;
	boolean isValidAddress = false;
	final int ADDRESSES = 14;
	final int PHYSICAL_ADDRESS_SPACES = 5; // first 5 in spaces and ADDRESS_SPACE_NAMES

	final String[] ADDRESS_SPACE_NAMES =
		{ "ONE", "TWO", "THREE", "SegSpaceOne", "SegSpaceTwo", "register", "const", "unique" };

	AddressSpace[] spaces = new AddressSpace[ADDRESS_SPACE_NAMES.length];
	Address[] addrs = new Address[ADDRESSES];

	////////////////////////////////////////////////////////////////////////////////////
	@Before
	public void setUp() {
		spaces[0] = new GenericAddressSpace(ADDRESS_SPACE_NAMES[0], 8, AddressSpace.TYPE_RAM, 0);
		spaces[1] = new GenericAddressSpace(ADDRESS_SPACE_NAMES[1], 16, AddressSpace.TYPE_RAM, 1);
		spaces[2] = new GenericAddressSpace(ADDRESS_SPACE_NAMES[2], 32, AddressSpace.TYPE_RAM, 2);

		spaces[3] = new SegmentedAddressSpace(ADDRESS_SPACE_NAMES[3], 3);
		spaces[4] = new SegmentedAddressSpace(ADDRESS_SPACE_NAMES[4], 4);

		spaces[5] = new GenericAddressSpace("register", 32, AddressSpace.TYPE_REGISTER, 0); // not physical
		spaces[6] = new GenericAddressSpace("const", 32, AddressSpace.TYPE_CONSTANT, 0); // not physical
		spaces[7] = new GenericAddressSpace("unique", 32, AddressSpace.TYPE_UNIQUE, 0); // not physical

		factory = new DefaultAddressFactory(spaces);
	}

	////////////////////////////////////////////////////////////////////////////////////
	@Test
	public void testSetProgram() {

		space = new GenericAddressSpace("Test", 16, AddressSpace.TYPE_RAM, 0);

	}

	////////////////////////////////////////////////////////////////////////////////////
	@Test
	public void testIsValidAddress() {
		space = new GenericAddressSpace("Test", 16, AddressSpace.TYPE_RAM, 0);

		isValidAddress = factory.isValidAddress(new GenericAddress(space, 0));
		assertTrue(!isValidAddress);

		for (AddressSpace element : spaces) {
			isValidAddress = factory.isValidAddress(new GenericAddress(element, 0));
			assertTrue(isValidAddress);
		}

	}

	//	/////////////////////////////////////////////////////////////////////////////////
	@Test
	public void testGenericAddress() throws Exception {

		addrs[0] = new GenericAddress(spaces[0], 255);
		try {
			new GenericAddress(spaces[0], 256);
			Assert.fail("Should have gotten IllegalArgumentException");
		}
		catch (AddressOutOfBoundsException e) {
		}
		Assert.assertEquals(new GenericAddress(spaces[0], 0xff), new GenericAddress(spaces[0], -1));

		addrs[0] = new GenericAddress(spaces[0], 0);
		addrs[1] = new SegmentedAddress((SegmentedAddressSpace) spaces[3], 0xf000, 0xffff);

	}

	//	//////////////////////////////////////////////////////////////////////////////////
	@Test
	public void testGetAllAddresses() {

		// Limited to memory address spaces only

		Address[] addresses;

		addresses = factory.getAllAddresses("SegSpace*:0");
		assertEquals(0, addresses.length);

		addresses = factory.getAllAddresses("SegSpaceOne:0");
		assertEquals(1, addresses.length);

		addresses = factory.getAllAddresses("segspaceOne:0");
		assertEquals(0, addresses.length);

		addresses = factory.getAllAddresses("0");
		assertEquals(5, addresses.length);
		assertEquals("ONE:00", addresses[0].toString());
		assertEquals("TWO:0000", addresses[1].toString());
		assertEquals("THREE:00000000", addresses[2].toString());
		assertEquals("SegSpaceOne:0000:0000", addresses[3].toString());
		assertEquals("SegSpaceTwo:0000:0000", addresses[4].toString());

	}

	@Test
	public void testGetAllAddressesCaseInsensitive() {
		Address[] addresses;

		addresses = factory.getAllAddresses("SegSpace*:0", false);
		assertEquals(0, addresses.length);

		addresses = factory.getAllAddresses("SegSpaceOne:0", false);
		assertEquals(1, addresses.length);

		addresses = factory.getAllAddresses("segspaceOne:0", false);
		assertEquals(1, addresses.length);

		addresses = factory.getAllAddresses("0", false);
		assertEquals(5, addresses.length);
		assertEquals("ONE:00", addresses[0].toString());
		assertEquals("TWO:0000", addresses[1].toString());
		assertEquals("THREE:00000000", addresses[2].toString());
		assertEquals("SegSpaceOne:0000:0000", addresses[3].toString());
		assertEquals("SegSpaceTwo:0000:0000", addresses[4].toString());

	}

	////////////////////////////////////////////////////////////////////////////////////

	@Test
	public void testGetAddressSpace() {
		space = factory.getAddressSpace(ADDRESS_SPACE_NAMES[0]);
		space = factory.getAddressSpace("xyz");

		AddressSpace[] as = factory.getAddressSpaces();

		assertEquals(PHYSICAL_ADDRESS_SPACES, as.length);
		assertEquals(PHYSICAL_ADDRESS_SPACES, factory.getNumAddressSpaces());

		for (int i = 0; i < as.length; i++) {
			Assert.assertEquals(ADDRESS_SPACE_NAMES[i], as[i].getName());
			Assert.assertTrue(spaces[i] == as[i]);
		}

	}
	//////////////////////////////////////////////////////////////////////////////////

	@Test
	public void testGetDefaultAddressSpace() {
		AddressSpace defASP = factory.getDefaultAddressSpace();
		Assert.assertEquals(defASP.getName(), spaces[0].getName());

	}
	////////////////////////////////////////////////////////////////////////////////////

	@Test
	public void testGetAddress() {
		createAddresses();

		assertNull(factory.getAddress("ONE,,0"));
		assertNull(factory.getAddress("ONE:100"));

		Assert.assertEquals(addrs[0], factory.getAddress("ONE:0"));
		Assert.assertEquals(addrs[1], factory.getAddress("ONE:FF"));

		Assert.assertEquals(addrs[3], factory.getAddress("TWO:0"));

		Assert.assertEquals(addrs[4], factory.getAddress("THREE:FFFFFFFF"));

		Assert.assertEquals(addrs[5], factory.getAddress("SegSpaceOne:0"));

		Assert.assertEquals(addrs[6], factory.getAddress("1:0"));
		Assert.assertEquals(addrs[7], factory.getAddress("1:50"));

		Assert.assertEquals(addrs[8], factory.getAddress("SegSpaceTwo:0"));
		Assert.assertEquals(addrs[9], factory.getAddress("SegSpaceTwo:ffff"));

		Assert.assertEquals(addrs[10], factory.getAddress("f000:ffff"));

		Assert.assertEquals(addrs[11], factory.getAddress("unique:0100"));

		Assert.assertEquals(addrs[12], factory.getAddress("const:0200"));

		Assert.assertEquals(addrs[13], factory.getAddress("register:0300"));

	}

	////////////////////////////////////////////////////////////////////////
	private void createAddresses() {
		addrs[0] = new GenericAddress(spaces[0], 0);
		addrs[1] = new GenericAddress(spaces[0], 255);

		addrs[2] = new GenericAddress(spaces[1], 512);
		addrs[3] = new GenericAddress(spaces[1], 0);

		addrs[4] = new GenericAddress(spaces[2], 0xFFFFFFFFL);

		addrs[5] = new SegmentedAddress((SegmentedAddressSpace) spaces[3], 0, 0);
		addrs[6] = new SegmentedAddress((SegmentedAddressSpace) spaces[3], 1, 0);
		addrs[7] = new SegmentedAddress((SegmentedAddressSpace) spaces[3], 1, 0x50);

		addrs[8] = new SegmentedAddress((SegmentedAddressSpace) spaces[4], 0, 0);
		addrs[9] = new SegmentedAddress((SegmentedAddressSpace) spaces[4], 0, 0xffff);

		addrs[10] = new SegmentedAddress((SegmentedAddressSpace) spaces[3], 0xf000, 0xffff);

		addrs[11] = factory.getAddressSpace("unique").getAddress(0x100);
		addrs[12] = factory.getAddressSpace("const").getAddress(0x200);
		addrs[13] = factory.getAddressSpace("register").getAddress(0x300);

	}

}
