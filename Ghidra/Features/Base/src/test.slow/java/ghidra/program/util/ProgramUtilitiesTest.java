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
package ghidra.program.util;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ProgramUtilitiesTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramBuilder builder;
	private TestEnv env;

	public ProgramUtilitiesTest() {
		super();
	}

    @Before
	public void setUp() throws Exception {
		env = new TestEnv();
		builder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
	}

    @After
    public void tearDown() {
		env.dispose();
		builder.dispose();
	}

@Test
    public void testParseAddress() throws Exception {
		Program p = builder.getProgram();
		Address addr = ProgramUtilities.parseAddress(p, "Stack[54]");
		assertEquals(p.getAddressFactory().getStackSpace(), addr.getAddressSpace());
		assertEquals(54, addr.getOffset());

		addr = ProgramUtilities.parseAddress(p, "Stack[0x54]");
		assertEquals(p.getAddressFactory().getStackSpace(), addr.getAddressSpace());
		assertEquals(0x54, addr.getOffset());

		addr = ProgramUtilities.parseAddress(p, "Stack[-54]");
		assertEquals(p.getAddressFactory().getStackSpace(), addr.getAddressSpace());
		assertEquals(-54, addr.getOffset());

		addr = ProgramUtilities.parseAddress(p, "Stack[-0x54]");
		assertEquals(p.getAddressFactory().getStackSpace(), addr.getAddressSpace());
		assertEquals(-0x54, addr.getOffset());
	}

}
