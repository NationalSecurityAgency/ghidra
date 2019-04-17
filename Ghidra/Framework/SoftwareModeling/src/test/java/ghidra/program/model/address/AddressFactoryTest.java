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

public class AddressFactoryTest extends AbstractGenericTest {
	AddressSpace space = null;
	AddressFactory factory = null;
	boolean isValidAddress = false;
	final int ADDRESS_SPACES = 5;
	final int ADDRESSES = 13;

	AddressSpace[] spaces = new AddressSpace[ADDRESS_SPACES];
	Address[] addrs = new Address[ADDRESSES];

	final String[] spaceName = { "ONE", "TWO", "THREE", "SegSpaceOne", "SegSpaceTwo" };

	////////////////////////////////////////////////////////////////////////////////////
	@Before
	public void setUp() {
		spaces[0] = new GenericAddressSpace(spaceName[0], 8, AddressSpace.TYPE_RAM, 0);
		spaces[1] = new GenericAddressSpace(spaceName[1], 16, AddressSpace.TYPE_RAM, 1);
		spaces[2] = new GenericAddressSpace(spaceName[2], 32, AddressSpace.TYPE_RAM, 2);

		spaces[3] = new SegmentedAddressSpace(spaceName[3], 3);
		spaces[4] = new SegmentedAddressSpace(spaceName[4], 4);

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

		for (int i = 0; i < ADDRESS_SPACES; i++) {
			isValidAddress = factory.isValidAddress(new GenericAddress(spaces[i], 0));
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
		Address[] addresses;

		addresses = factory.getAllAddresses("SegSpace*:0");
		Assert.assertEquals(addresses.length, 0);

		addresses = factory.getAllAddresses("SegSpaceOne:0");
		Assert.assertEquals(addresses.length, 1);

	}

	////////////////////////////////////////////////////////////////////////////////////

	@Test
	public void testGetAddressSpce() {
		space = factory.getAddressSpace(spaceName[0]);
		space = factory.getAddressSpace("xyz");

		AddressSpace[] as = factory.getAddressSpaces();

		assertTrue(as.length == ADDRESS_SPACES);
		assertTrue(as.length == factory.getNumAddressSpaces());

		for (int i = 0; i < as.length; i++) {
			Assert.assertEquals(spaceName[i], as[i].getName());
		}

	}
	//////////////////////////////////////////////////////////////////////////////////

	@Test
	public void testGetDefaultAddressSpce() {
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

	}

}
