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
package ghidra.program.database.mem;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class MemoryWriteCheckTest extends AbstractGhidraHeadedIntegrationTest {

	private AddressSpace space;
	private MemoryBlock block;
	private Memory memory;
	private Program program;
	private int transactionID;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY64_LE, this);
		memory = program.getMemory();

		byte[] bytes = new byte[0x100];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) i;
		}
		space = program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");

		block = memory.createInitializedBlock("BYTE_BLOCK", space.getAddress(0), bytes.length,
			(byte) 0, TaskMonitor.DUMMY, false);
		memory.setBytes(block.getStart(), bytes);
	}

	@After
	public void tearDown() {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testByteMappedMemoryCheck() throws Exception {

		AddressSet set = new AddressSet(addr(0), addr(0xd7));
		DisassembleCommand cmd = new DisassembleCommand(set, set);
		cmd.applyTo(program); // range 0x0000 to 0x00d7 disassembled

		MemoryBlock byteMappedBlock = memory.createByteMappedBlock("test", addr(0x1000), addr(0x80),
			0x100, new ByteMappingScheme(2, 4), true);

		AddressSpace testSpace = program.getAddressFactory().getAddressSpace("test");

		try {
			byteMappedBlock.putByte(testSpace.getAddress(0x1000), (byte) 1);
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			assertEquals("Memory change conflicts with instruction at 00000080", e.getMessage());
		}

		try {
			byteMappedBlock.putBytes(testSpace.getAddress(0x1002), new byte[] { 1, 2 });
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			assertEquals("Memory change conflicts with instruction at 00000084", e.getMessage());
		}

		program.getListing().clearCodeUnits(addr(0), addr(0xd7), true);

		byteMappedBlock.putByte(testSpace.getAddress(0x1000), (byte) 1);
		assertEquals(1, byteMappedBlock.getByte(testSpace.getAddress(0x1000)));

		byteMappedBlock.putBytes(testSpace.getAddress(0x1002), new byte[] { 1, 2 });
		byte[] data = new byte[2];
		assertEquals(2, byteMappedBlock.getBytes(testSpace.getAddress(0x1002), data));
		assertArrayEquals(new byte[] { 1, 2 }, data);

	}

	@Test
	public void testByteMappedMemoryCheck1() throws Exception {

		// NOTE: disassembling in a 2:4 byte-mapped block is rather inappropriate and may be disallowed in the future

		MemoryBlock byteMappedBlock = memory.createByteMappedBlock("test", addr(0x1000), addr(0x80),
			0x100, new ByteMappingScheme(2, 4), true);

		AddressSpace testSpace = program.getAddressFactory().getAddressSpace("test");

		AddressSet set = new AddressSet(testSpace.getAddress(0x1000), testSpace.getAddress(0x1011));
		DisassembleCommand cmd = new DisassembleCommand(set, set);
		cmd.applyTo(program); // range test:0x1000 to test::0x1011 disassembled

		try {
			block.putByte(addr(0x80), (byte) 1);
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			assertEquals("Memory change conflicts with instruction at test::00001000",
				e.getMessage());
		}

		// small modification within filler byte region for mapped block allowed 
		block.putBytes(addr(0x82), new byte[] { 1, 2 });
		byte[] data = new byte[2];
		assertEquals(2, block.getBytes(addr(0x82), data));
		assertArrayEquals(new byte[] { 1, 2 }, data);

		try {
			block.putBytes(addr(0x84), new byte[] { 1, 2 });
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			assertEquals("Memory change conflicts with instruction at test::00001002",
				e.getMessage());
		}

		program.getListing().clearCodeUnits(set.getMinAddress(), set.getMaxAddress(), true);

		block.putByte(addr(0x80), (byte) 1);
		assertEquals(1, byteMappedBlock.getByte(testSpace.getAddress(0x1000)));

		block.putBytes(addr(0x84), new byte[] { 1, 2 });
		assertEquals(2, byteMappedBlock.getBytes(testSpace.getAddress(0x1002), data));
		assertArrayEquals(new byte[] { 1, 2 }, data);

	}

	@Test
	public void testBitMappedMemoryCheck() throws Exception {

		AddressSet set = new AddressSet(addr(0), addr(0xd7));
		DisassembleCommand cmd = new DisassembleCommand(set, set);
		cmd.applyTo(program); // range 0x0000 to 0x00d7 disassembled

		MemoryBlock bitMappedBlock =
			memory.createBitMappedBlock("test", addr(0x1000), addr(0x80), 0x100, true);

		AddressSpace testSpace = program.getAddressFactory().getAddressSpace("test");

		try {
			bitMappedBlock.putByte(testSpace.getAddress(0x1000), (byte) 1);
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			assertEquals("Memory change conflicts with instruction at 00000080", e.getMessage());
		}

		try {
			bitMappedBlock.putBytes(testSpace.getAddress(0x1010), new byte[] { 1, 0, 1, 0 });
			fail("expected MemoryAccessException");
		}
		catch (MemoryAccessException e) {
			assertEquals("Memory change conflicts with instruction at 00000082", e.getMessage());
		}

		program.getListing().clearCodeUnits(addr(0), addr(0xd7), true);

		bitMappedBlock.putByte(testSpace.getAddress(0x1000), (byte) 1);
		assertEquals(1, bitMappedBlock.getByte(testSpace.getAddress(0x1000)));

		bitMappedBlock.putBytes(testSpace.getAddress(0x1010), new byte[] { 1, 0, 1, 0 });
		byte[] data = new byte[4];
		assertEquals(4, bitMappedBlock.getBytes(testSpace.getAddress(0x1010), data));
		assertArrayEquals(new byte[] { 1, 0, 1, 0 }, data);

	}
}
