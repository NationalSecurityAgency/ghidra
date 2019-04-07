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

import java.util.Arrays;

import org.junit.*;

import generic.test.AbstractGenericTest;

public class AddressSpaceTest extends AbstractGenericTest {

	AddressSpace space1;
	AddressSpace space1overlay1;
	AddressSpace space1overlay2;
	AddressSpace space1overlay3;
	AddressSpace space2;
	AddressSpace space2overlay1;
	AddressSpace space2overlay2;
	AddressSpace space2overlay3;
	AddressSpace space3;

	public AddressSpaceTest() {
		super();
	}

	@Before
	public void setUp() {
		space1 = new GenericAddressSpace("Test1", 8, AddressSpace.TYPE_RAM, 0);
		space2 = new GenericAddressSpace("Test2", 8, AddressSpace.TYPE_RAM, 1);
		space1overlay1 = new OverlayAddressSpace("Test1overlay1", space1, 3, 0x20, 0x30);
		space1overlay2 = new OverlayAddressSpace("Test1overlay2", space1, 4, 0x10, 0x20);
		space1overlay3 = new OverlayAddressSpace("Test1overlay", space1, 7, 0x10, 0x50); // dup min offset
		space2overlay1 = new OverlayAddressSpace("Test2overlay1", space2, 5, 0x20, 0x30);
		space2overlay2 = new OverlayAddressSpace("Test2overlay2", space2, 2, 0x10, 0x20);
		space2overlay3 = new OverlayAddressSpace("Test2overlay", space2, 6, 0x10, 0x50); // dup min offset
	}

	@Test
	public void testCompareTo() {
		AddressSpace[] spaces =
			new AddressSpace[] { space1, space2, space1overlay1, space2overlay1, space1overlay2,
				space2overlay2, space1overlay3, space2overlay3, space1, space2, space1overlay1,
				space2overlay1, space1overlay2, space2overlay2, space1overlay3, space2overlay3, };
		Arrays.sort(spaces);
		Assert.assertEquals(space1, spaces[0]);
		Assert.assertEquals(space1, spaces[1]);
		Assert.assertEquals(space2, spaces[2]);
		Assert.assertEquals(space2, spaces[3]);
		Assert.assertEquals(space1overlay3, spaces[4]);
		Assert.assertEquals(space1overlay3, spaces[5]);
		Assert.assertEquals(space1overlay2, spaces[6]);
		Assert.assertEquals(space1overlay2, spaces[7]);
		Assert.assertEquals(space1overlay1, spaces[8]);
		Assert.assertEquals(space1overlay1, spaces[9]);
		Assert.assertEquals(space2overlay3, spaces[10]);
		Assert.assertEquals(space2overlay3, spaces[11]);
		Assert.assertEquals(space2overlay2, spaces[12]);
		Assert.assertEquals(space2overlay2, spaces[13]);
		Assert.assertEquals(space2overlay1, spaces[14]);
		Assert.assertEquals(space2overlay1, spaces[15]);
	}

	@Test
	public void testEquals() {
		AddressSpace space1a = new GenericAddressSpace("Test1", 8, AddressSpace.TYPE_RAM, 0);
		AddressSpace space2a = new GenericAddressSpace("Test2", 8, AddressSpace.TYPE_RAM, 1);
		AddressSpace space1overlay1a =
			new OverlayAddressSpace("Test1overlay1", space1, 13, 0x20, 0x30);
		AddressSpace space1overlay2a =
			new OverlayAddressSpace("Test1overlay2", space1, 14, 0x10, 0x20);
		AddressSpace space1overlay3a =
			new OverlayAddressSpace("Test1overlay", space1, 17, 0x10, 0x50); // dup min offset
		AddressSpace space2overlay1a =
			new OverlayAddressSpace("Test2overlay1", space2, 15, 0x20, 0x30);
		AddressSpace space2overlay2a =
			new OverlayAddressSpace("Test2overlay2", space2, 12, 0x10, 0x20);
		AddressSpace space2overlay3a =
			new OverlayAddressSpace("Test2overlay", space2, 16, 0x10, 0x50); // dup min offset

		assertTrue(space1a.equals(space1));
		assertTrue(space2a.equals(space2));
		assertTrue(space1overlay1a.equals(space1overlay1));
		assertTrue(space1overlay2a.equals(space1overlay2));
		assertTrue(space1overlay3a.equals(space1overlay3));
		assertTrue(space2overlay1a.equals(space2overlay1));
		assertTrue(space2overlay2a.equals(space2overlay2));
		assertTrue(space2overlay3a.equals(space2overlay3));

		assertTrue(!space1a.equals(space2));
		assertTrue(!space2a.equals(space1));

		assertTrue(!space1overlay1a.equals(space1overlay2));
		assertTrue(!space1overlay1a.equals(space1overlay3));
		assertTrue(!space1overlay1a.equals(space2overlay1));

	}

}
