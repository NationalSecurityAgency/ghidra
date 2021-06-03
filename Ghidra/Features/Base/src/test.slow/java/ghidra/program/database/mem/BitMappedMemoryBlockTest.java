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

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test for the BitMemoryBlock for the database implementation.
 */
public class BitMappedMemoryBlockTest extends AbstractGhidraHeadedIntegrationTest {
	private AddressSpace byteSpace;
	private AddressSpace bitSpace;
	private MemoryBlock block;
	private Memory memory;
	private Program program;
	private int transactionID;

	/**
	 * Constructor for BitMemoryBlockTest.
	 * @param name
	 */
	public BitMappedMemoryBlockTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._8051, this);
		memory = program.getMemory();

		byte[] bytes = new byte[64 * 1024];
		for (int i = 0; i < 64 * 1024; i++) {
			bytes[i] = (byte) 0xaa;
		}
		byteSpace = program.getAddressFactory().getAddressSpace("CODE");
		bitSpace = program.getAddressFactory().getAddressSpace("BITS");
		transactionID = program.startTransaction("Test");

		block = memory.createInitializedBlock("BYTE_BLOCK", byteSpace.getAddress(0), bytes.length,
			(byte) 0, TaskMonitorAdapter.DUMMY_MONITOR, false);
		memory.setBytes(block.getStart(), bytes);
	}

	@After
	public void tearDown() {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testCreateNewBlock() throws Exception {
		memory.createBitMappedBlock("BIT_BLOCK", bitSpace.getAddress(0), bitSpace.getAddress(0x20),
			0x20, false);
		Address newStart = bitSpace.getAddress(0x40);

		MemoryBlock newblock =
			memory.createBitMappedBlock("BitTest", newStart, bitSpace.getAddress(0x20), 0x50,
				false);
		assertNotNull(newblock);
		assertEquals(newStart, newblock.getStart());
	}

	@Test
	public void testNoUnderlyingMemory() throws Exception {
		MemoryBlock bitBlock = memory.createBitMappedBlock("BIT_BLOCK", bitSpace.getAddress(0),
			bitSpace.getAddress(0x20), 0x20, false);

		Address addr = bitSpace.getAddress(0x40);
		MemoryBlock newblock = memory.createBlock(bitBlock, "BitTest", addr, 0x50);
		try {
			newblock.getByte(addr);
			Assert.fail("Should not have gotten a byte");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}

	@Test
	public void testGetByte() throws Exception {
		MemoryBlock bitBlock = memory.createBitMappedBlock("BIT_BLOCK", bitSpace.getAddress(0),
			byteSpace.getAddress(0x20), 256, false);

		for (int i = 0; i < 256; i += 2) {
			assertEquals(0, bitBlock.getByte(bitSpace.getAddress(i)));
			assertEquals(1, bitBlock.getByte(bitSpace.getAddress(i + 1)));
		}

	}

	@Test
	public void testPutByte() throws Exception {
		MemoryBlock bitBlock = memory.createBitMappedBlock("BIT_BLOCK", bitSpace.getAddress(0),
			byteSpace.getAddress(0x20), 256, false);
		for (int i = 0; i < 256; i += 2) {
			bitBlock.putByte(bitSpace.getAddress(i), (byte) 1);
			bitBlock.putByte(bitSpace.getAddress(i + 1), (byte) 0);
		}
		for (int i = 0; i < 256; i += 2) {
			assertEquals(1, bitBlock.getByte(bitSpace.getAddress(i)));
			assertEquals(0, bitBlock.getByte(bitSpace.getAddress(i + 1)));
		}

	}

}
