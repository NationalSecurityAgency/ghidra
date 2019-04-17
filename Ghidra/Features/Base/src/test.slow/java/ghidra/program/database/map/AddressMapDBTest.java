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
package ghidra.program.database.map;

import static org.junit.Assert.assertEquals;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

public class AddressMapDBTest extends AbstractGhidraHeadedIntegrationTest {
	private AddressMap addrMap;
	private Program p;

	public AddressMapDBTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ProgramBuilder builder = new ProgramBuilder(testName.getMethodName(), ProgramBuilder._TOY);
		p = builder.getProgram();

		addrMap = (AddressMap) getInstanceField("addrMap", p.getMemory());
	}

	@Test
    public void testRegisterAddress() {
		AddressSpace regSpace = p.getAddressFactory().getRegisterSpace();
		Address a = regSpace.getAddress(0);
		long key = addrMap.getKey(a, false);
		assertEquals(0x3000000000000000l, key);
		Address b = addrMap.decodeAddress(key);
		assertEquals(a, b);

		a = regSpace.getAddress(10);
		key = addrMap.getKey(a, false);
		assertEquals(0x300000000000000al, key);
		b = addrMap.decodeAddress(key);
		assertEquals(a, b);
	}

	@Test
    public void testStackAddress() {
		AddressSpace stackSpace = p.getAddressFactory().getStackSpace();
		Address a = stackSpace.getAddress(0);
		long key = addrMap.getKey(a, false);
		assertEquals(0x4000000000000000l, key);
		Address b = addrMap.decodeAddress(key);
		assertEquals(a, b);

		a = stackSpace.getAddress(10);
		key = addrMap.getKey(a, false);
		assertEquals(0x400000000000000al, key);
		b = addrMap.decodeAddress(key);
		assertEquals(a, b);
	}

	@Test
    public void testMaxRegisterAddress() {
		AddressSpace regSpace = p.getAddressFactory().getRegisterSpace();
		Address a = regSpace.getAddress(-1);
		long key = addrMap.getKey(a, false);
		assertEquals(0x300000000000ffffl, key);
		Address b = addrMap.decodeAddress(key);
		assertEquals(a, b);
		assertEquals(regSpace.getAddress(0xffffL), b);

	}

	@Test
    public void testStackAddressNegative() {
		AddressSpace stackSpace = p.getAddressFactory().getStackSpace();
		Address a = stackSpace.getAddress(-1);
		long key = addrMap.getKey(a, false);
		assertEquals(0x40000000ffffffffl, key);
		Address b = addrMap.decodeAddress(key);
		assertEquals(a, b);

	}

}
