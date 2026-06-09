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

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
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

		p.withTransaction("Add Overlay Block", () -> {
			Address addr = ProgramUtilities.parseAddress(p, "100");
			p.getMemory().createUninitializedBlock("OVLY", addr, 0x100, true);
		});

		AddressFactory addressFactory = p.getAddressFactory();

		// Verify that special spaces were defined for TOY language
		assertNotNull(addressFactory.getAddressSpace("const"));
		assertNotNull(addressFactory.getAddressSpace("unique"));
		assertNotNull(addressFactory.getAddressSpace("register"));

		//
		// Stack addresses (signed decimal and hex offsets)
		//

		Address addr = ProgramUtilities.parseAddress(p, "Stack[54]");
		assertEquals(addressFactory.getStackSpace(), addr.getAddressSpace());
		assertEquals(54, addr.getOffset());

		addr = ProgramUtilities.parseAddress(p, "Stack[0x54]");
		assertEquals(addressFactory.getStackSpace(), addr.getAddressSpace());
		assertEquals(0x54, addr.getOffset());

		addr = ProgramUtilities.parseAddress(p, "Stack[-54]");
		assertEquals(addressFactory.getStackSpace(), addr.getAddressSpace());
		assertEquals(-54, addr.getOffset());

		addr = ProgramUtilities.parseAddress(p, "Stack[-0x54]");
		assertEquals(addressFactory.getStackSpace(), addr.getAddressSpace());
		assertEquals(-0x54, addr.getOffset());

		//
		// Memory address
		//

		addr = ProgramUtilities.parseAddress(p, "ram:00001234");
		assertEquals(addressFactory.getAddressSpace("ram"), addr.getAddressSpace());
		assertEquals(0x1234, addr.getOffset());

		//
		// Overlay address
		//

		addr = ProgramUtilities.parseAddress(p, "OVLY::0x010");
		assertEquals(addressFactory.getAddressSpace("OVLY"), addr.getAddressSpace());
		assertEquals(0x10, addr.getOffset());
		assertTrue(addr.getAddressSpace().isOverlaySpace());

		addr = ProgramUtilities.parseAddress(p, "OVLY::0x2000"); // outside overlay block range
		assertEquals(addressFactory.getAddressSpace("OVLY"), addr.getAddressSpace());
		assertEquals(0x2000, addr.getOffset());
		assertTrue(addr.getAddressSpace().isOverlaySpace());

		//
		// External address
		//

		addr = ProgramUtilities.parseAddress(p, "EXTERNAL:00001234");
		assertEquals(AddressSpace.EXTERNAL_SPACE, addr.getAddressSpace());
		assertEquals(0x1234, addr.getOffset());

		//
		// Block-name style address (Not supported)
		// 

		assertNull(ProgramUtilities.parseAddress(p, "test1:00001001000"));
		assertNull(ProgramUtilities.parseAddress(p, "test1:00001234"));

		//
		// Special spaces (Not supported)
		//

		assertNull(ProgramUtilities.parseAddress(p, "register:00000000"));
		assertNull(ProgramUtilities.parseAddress(p, "const:00000000"));
		assertNull(ProgramUtilities.parseAddress(p, "unique:00000000"));
	}

}
