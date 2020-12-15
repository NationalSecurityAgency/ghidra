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
package ghidra.app.util;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;

import org.junit.*;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

public class MemoryBlockUtilTest extends AbstractGhidraHeadedIntegrationTest {
	private Object consumer = new Object();
	private Program prog;
	private int id;
	private AddressSpace space;
	private MessageLog log;

	public MemoryBlockUtilTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		log = new MessageLog();
		prog = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, consumer);

		id = prog.startTransaction("test");
		space = prog.getAddressFactory().getDefaultAddressSpace();
	}

	@After
	public void tearDown() throws Exception {

		if (prog != null) {
			prog.endTransaction(id, false);
			prog.release(consumer);
		}
	}

	@Test
	public void testInitializedConflict() throws Exception {
		byte[] data = new byte[1000];
		Arrays.fill(data, (byte) 0xa);
		InputStream is = new ByteArrayInputStream(data);
		MemoryBlockUtils.createInitializedBlock(prog, false, "a", space.getAddress(3000), is, 1000,
			"aaaa", "a a a", true, true, true, log, TaskMonitor.DUMMY);

		Arrays.fill(data, (byte) 0xb);
		is = new ByteArrayInputStream(data);
		MemoryBlockUtils.createInitializedBlock(prog, false, "b", space.getAddress(3500), is, 1000,
			"bbbb", "b b b", false, false, false, log, TaskMonitor.DUMMY);

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(2, blocks.length);
		assertEquals("a", blocks[0].getName());
		assertEquals("b", blocks[1].getName());
		assertEquals(1000, blocks[0].getSize());
		assertEquals(1000, blocks[1].getSize());

		for (int i = 0; i < 1000; ++i) {
			assertEquals(0xa, blocks[0].getByte(blocks[0].getStart().add(i)));
		}
		for (int i = 0; i < 1000; ++i) {
			assertEquals(0xb, blocks[1].getByte(blocks[1].getStart().add(i)));
		}
	}

	@Test
	public void testGetByteOnUnitializedBlock() {
		MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(prog, false, "a",
			space.getAddress(3000), 1000, "Acomment", "Asource", true, true, true, log);
		try {
			block.getByte(space.getAddress(3000));
			Assert.fail("Got byte from uninitialized block");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}

	@Test
	public void testUninitializedConflictMiddle() throws Exception {
		MemoryBlockUtils.createUninitializedBlock(prog, false, "a", space.getAddress(3000), 3000,
			"Acomment", "Asource", true, true, true, log);

		byte[] cdata = new byte[1000];
		Arrays.fill(cdata, (byte) 0xc);
		MemoryBlockUtils.createInitializedBlock(prog, false, "c", space.getAddress(4000),
			new ByteArrayInputStream(cdata), 1000, "Ccomment", "Csource", false, false, false, log,
			TaskMonitor.DUMMY);

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(2, blocks.length);

		assertEquals("a", blocks[0].getName());
		assertEquals("c", blocks[1].getName());

		assertEquals(3000, blocks[0].getSize());
		assertEquals(1000, blocks[1].getSize());

		assertTrue(!blocks[0].isInitialized());
		assertTrue(blocks[1].isInitialized());
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testDuplicateHandling() throws Exception {
		ByteProvider byteProvider = new ByteArrayProvider(new byte[1000]);
		FileBytes fileBytes =
			MemoryBlockUtils.createFileBytes(prog, byteProvider, TaskMonitor.DUMMY);

		MemoryBlockUtils.createInitializedBlock(prog, true, "test", addr(0), fileBytes, 0, 10, "",
			"", true, true, true, new MessageLog());
		MemoryBlockUtils.createInitializedBlock(prog, true, "test", addr(0), fileBytes, 0, 10, "",
			"", true, true, true, new MessageLog());
		MemoryBlockUtils.createInitializedBlock(prog, true, "test", addr(0), fileBytes, 0, 10, "",
			"", true, true, true, new MessageLog());

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(3, blocks.length);

		assertEquals("test", blocks[0].getName());
		assertEquals("test", blocks[1].getName());
		assertEquals("test", blocks[2].getName());

		assertEquals("test", blocks[0].getStart().getAddressSpace().getName());
		assertEquals("test.1", blocks[1].getStart().getAddressSpace().getName());
		assertEquals("test.2", blocks[2].getStart().getAddressSpace().getName());

	}

}
