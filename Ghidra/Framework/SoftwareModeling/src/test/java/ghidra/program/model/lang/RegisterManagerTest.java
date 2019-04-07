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
package ghidra.program.model.lang;

import static org.junit.Assert.assertNull;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;

public class RegisterManagerTest extends AbstractGenericTest {

	private RegisterManager registerManager;

	public RegisterManagerTest() {
		super();

	}

	private Address addr(long offset) {
		return AddressSpace.DEFAULT_REGISTER_SPACE.getAddress(offset);
	}

	@Before
	public void setUp() throws Exception {
		RegisterBuilder builder = new RegisterBuilder();
		builder.addRegister("L_0_8", "", addr(0), 8, false, 0);
		builder.addRegister("L_0_4", "", addr(0), 4, false, 0);
		builder.addRegister("L_4_4", "", addr(4), 4, false, 0);
		builder.addRegister("L_0_2", "", addr(0), 2, false, 0);
		builder.addRegister("L_2_2", "", addr(2), 2, false, 0);

		builder.addRegister("B_10_8", "", addr(0x10), 8, true, 0);
		builder.addRegister("B_10_4", "", addr(0x10), 4, true, 0);
		builder.addRegister("B_14_4", "", addr(0x14), 4, true, 0);
		builder.addRegister("B_16_2", "", addr(0x16), 2, true, 0);
		builder.addRegister("B_12_2", "", addr(0x12), 2, true, 0);

		registerManager = builder.getRegisterManager();
	}

	@Test
	public void testLittle() {
		RegisterBuilder builder = new RegisterBuilder();
		builder.addRegister("L_0_8", "", addr(0), 8, false, 0);
		builder.addRegister("L_0_4", "", addr(0), 4, false, 0);
		builder.addRegister("L_4_4", "", addr(4), 4, false, 0);
		builder.addRegister("L_0_2", "", addr(0), 2, false, 0);
		builder.addRegister("L_2_2", "", addr(2), 2, false, 0);

		registerManager = builder.getRegisterManager();

		Assert.assertEquals("L_0_8", registerManager.getRegister(addr(0), 8).getName());
		Assert.assertEquals("L_0_8", registerManager.getRegister(addr(0), 7).getName());
		Assert.assertEquals("L_0_8", registerManager.getRegister(addr(0), 6).getName());
		Assert.assertEquals("L_0_8", registerManager.getRegister(addr(0), 5).getName());
		Assert.assertEquals("L_0_4", registerManager.getRegister(addr(0), 4).getName());
		Assert.assertEquals("L_0_4", registerManager.getRegister(addr(0), 3).getName());
		Assert.assertEquals("L_0_2", registerManager.getRegister(addr(0), 2).getName());
		Assert.assertEquals("L_0_2", registerManager.getRegister(addr(0), 1).getName());
		Assert.assertEquals("L_0_8", registerManager.getRegister(addr(0), 0).getName());

		assertNull(registerManager.getRegister(addr(1), 8));
		assertNull(registerManager.getRegister(addr(1), 7));
		assertNull(registerManager.getRegister(addr(1), 6));
		assertNull(registerManager.getRegister(addr(1), 5));
		assertNull(registerManager.getRegister(addr(1), 4));
		assertNull(registerManager.getRegister(addr(1), 3));
		assertNull(registerManager.getRegister(addr(1), 2));
		assertNull(registerManager.getRegister(addr(1), 1));
		assertNull(registerManager.getRegister(addr(1), 0));

		assertNull(registerManager.getRegister(addr(2), 8));
		assertNull(registerManager.getRegister(addr(2), 7));
		assertNull(registerManager.getRegister(addr(2), 6));
		assertNull(registerManager.getRegister(addr(2), 5));
		assertNull(registerManager.getRegister(addr(2), 4));
		assertNull(registerManager.getRegister(addr(2), 3));
		Assert.assertEquals("L_2_2", registerManager.getRegister(addr(2), 2).getName());
		Assert.assertEquals("L_2_2", registerManager.getRegister(addr(2), 1).getName());
		Assert.assertEquals("L_2_2", registerManager.getRegister(addr(2), 0).getName());

		assertNull(registerManager.getRegister(addr(3), 8));
		assertNull(registerManager.getRegister(addr(3), 7));
		assertNull(registerManager.getRegister(addr(3), 6));
		assertNull(registerManager.getRegister(addr(3), 5));
		assertNull(registerManager.getRegister(addr(3), 4));
		assertNull(registerManager.getRegister(addr(3), 3));
		assertNull(registerManager.getRegister(addr(3), 2));
		assertNull(registerManager.getRegister(addr(3), 1));
		assertNull(registerManager.getRegister(addr(3), 0));

		assertNull(registerManager.getRegister(addr(4), 8));
		assertNull(registerManager.getRegister(addr(4), 7));
		assertNull(registerManager.getRegister(addr(4), 6));
		assertNull(registerManager.getRegister(addr(4), 5));
		Assert.assertEquals("L_4_4", registerManager.getRegister(addr(4), 4).getName());
		Assert.assertEquals("L_4_4", registerManager.getRegister(addr(4), 3).getName());
		Assert.assertEquals("L_4_4", registerManager.getRegister(addr(4), 2).getName());
		Assert.assertEquals("L_4_4", registerManager.getRegister(addr(4), 1).getName());
		Assert.assertEquals("L_4_4", registerManager.getRegister(addr(4), 0).getName());

	}

	@Test
	public void testBig() {
		RegisterBuilder builder = new RegisterBuilder();

		builder.addRegister("B_0_8", "", addr(0), 8, true, 0);
		builder.addRegister("B_0_4", "", addr(0), 4, true, 0);
		builder.addRegister("B_4_4", "", addr(4), 4, true, 0);
		builder.addRegister("B_6_2", "", addr(6), 2, true, 0);
		builder.addRegister("B_2_2", "", addr(2), 2, true, 0);

		registerManager = builder.getRegisterManager();

		Assert.assertEquals("B_0_8", registerManager.getRegister(addr(0), 8).getName());
		assertNull(registerManager.getRegister(addr(0), 7));
		assertNull(registerManager.getRegister(addr(0), 6));
		assertNull(registerManager.getRegister(addr(0), 5));
		Assert.assertEquals("B_0_4", registerManager.getRegister(addr(0), 4).getName());
		assertNull(registerManager.getRegister(addr(0), 3));
		assertNull(registerManager.getRegister(addr(0), 2));
		assertNull(registerManager.getRegister(addr(0), 1));
		Assert.assertEquals("B_0_8", registerManager.getRegister(addr(0), 0).getName());

		assertNull(registerManager.getRegister(addr(1), 8));
		Assert.assertEquals("B_0_8", registerManager.getRegister(addr(1), 7).getName());
		assertNull(registerManager.getRegister(addr(1), 6));
		assertNull(registerManager.getRegister(addr(1), 5));
		assertNull(registerManager.getRegister(addr(1), 4));
		Assert.assertEquals("B_0_4", registerManager.getRegister(addr(1), 3).getName());
		assertNull(registerManager.getRegister(addr(1), 2));
		assertNull(registerManager.getRegister(addr(1), 1));
		assertNull(registerManager.getRegister(addr(1), 0));

		assertNull(registerManager.getRegister(addr(2), 8));
		assertNull(registerManager.getRegister(addr(2), 7));
		Assert.assertEquals("B_0_8", registerManager.getRegister(addr(2), 6).getName());
		assertNull(registerManager.getRegister(addr(2), 5));
		assertNull(registerManager.getRegister(addr(2), 4));
		assertNull(registerManager.getRegister(addr(2), 3));
		Assert.assertEquals("B_2_2", registerManager.getRegister(addr(2), 2).getName());
		assertNull(registerManager.getRegister(addr(2), 1));
		Assert.assertEquals("B_2_2", registerManager.getRegister(addr(2), 0).getName());

		assertNull(registerManager.getRegister(addr(3), 8));
		assertNull(registerManager.getRegister(addr(3), 7));
		assertNull(registerManager.getRegister(addr(3), 6));
		Assert.assertEquals("B_0_8", registerManager.getRegister(addr(3), 5).getName());
		assertNull(registerManager.getRegister(addr(3), 4));
		assertNull(registerManager.getRegister(addr(3), 3));
		assertNull(registerManager.getRegister(addr(3), 2));
		Assert.assertEquals("B_2_2", registerManager.getRegister(addr(3), 1).getName());
		assertNull(registerManager.getRegister(addr(3), 0));

		assertNull(registerManager.getRegister(addr(4), 8));
		assertNull(registerManager.getRegister(addr(4), 7));
		assertNull(registerManager.getRegister(addr(4), 6));
		assertNull(registerManager.getRegister(addr(4), 5));
		Assert.assertEquals("B_4_4", registerManager.getRegister(addr(4), 4).getName());
		assertNull(registerManager.getRegister(addr(4), 3));
		assertNull(registerManager.getRegister(addr(4), 2));
		assertNull(registerManager.getRegister(addr(4), 1));
		Assert.assertEquals("B_4_4", registerManager.getRegister(addr(4), 0).getName());

		assertNull(registerManager.getRegister(addr(5), 8));
		assertNull(registerManager.getRegister(addr(5), 7));
		assertNull(registerManager.getRegister(addr(5), 6));
		assertNull(registerManager.getRegister(addr(5), 5));
		assertNull(registerManager.getRegister(addr(5), 4));
		Assert.assertEquals("B_4_4", registerManager.getRegister(addr(5), 3).getName());
		assertNull(registerManager.getRegister(addr(5), 2));
		assertNull(registerManager.getRegister(addr(5), 1));
		assertNull(registerManager.getRegister(addr(5), 0));

		assertNull(registerManager.getRegister(addr(6), 8));
		assertNull(registerManager.getRegister(addr(6), 7));
		assertNull(registerManager.getRegister(addr(6), 6));
		assertNull(registerManager.getRegister(addr(6), 5));
		assertNull(registerManager.getRegister(addr(6), 4));
		assertNull(registerManager.getRegister(addr(6), 3));
		Assert.assertEquals("B_6_2", registerManager.getRegister(addr(6), 2).getName());
		assertNull(registerManager.getRegister(addr(6), 1));
		Assert.assertEquals("B_6_2", registerManager.getRegister(addr(6), 0).getName());

		assertNull(registerManager.getRegister(addr(7), 8));
		assertNull(registerManager.getRegister(addr(7), 7));
		assertNull(registerManager.getRegister(addr(7), 6));
		assertNull(registerManager.getRegister(addr(7), 5));
		assertNull(registerManager.getRegister(addr(7), 4));
		assertNull(registerManager.getRegister(addr(7), 3));
		assertNull(registerManager.getRegister(addr(7), 2));
		Assert.assertEquals("B_6_2", registerManager.getRegister(addr(7), 1).getName());
		assertNull(registerManager.getRegister(addr(7), 0));

	}

}
