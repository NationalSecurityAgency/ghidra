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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Arrays;

import org.junit.*;

import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

public class MemoryBlockUtilTest extends AbstractGhidraHeadedIntegrationTest {
	private Object consumer = new Object();
	private Program prog;
	private int id;
	private AddressSpace space;
	private MemoryBlockUtil mbu;

	public MemoryBlockUtilTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		prog = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, consumer);

		id = prog.startTransaction("test");
		space = prog.getAddressFactory().getDefaultAddressSpace();
		mbu = new MemoryBlockUtil(prog, MemoryConflictHandler.ALWAYS_OVERWRITE);
	}

	@After
	public void tearDown() throws Exception {

		if (prog != null) {
			prog.endTransaction(id, false);
			prog.release(consumer);
		}
		if (mbu != null) {
			mbu.dispose();
		}
	}

	@Test
	public void testInitializedConflict() throws Exception {
		byte[] data = new byte[1000];
		Arrays.fill(data, (byte) 0xa);
		InputStream is = new ByteArrayInputStream(data);
		mbu.createInitializedBlock("a", space.getAddress(3000), is, 1000, "aaaa", "a a a", true,
			true, true, TaskMonitorAdapter.DUMMY_MONITOR);

		Arrays.fill(data, (byte) 0xb);
		is = new ByteArrayInputStream(data);
		mbu.createInitializedBlock("b", space.getAddress(3500), is, 1000, "bbbb", "b b b", false,
			false, false, TaskMonitorAdapter.DUMMY_MONITOR);

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(2, blocks.length);
		assertEquals("a", blocks[0].getName());
		assertEquals("b", blocks[1].getName());
		assertEquals(1000, blocks[0].getSize());
		assertEquals(500, blocks[1].getSize());

		for (int i = 0; i < 500; ++i) {
			assertEquals(0xa, blocks[0].getByte(blocks[0].getStart().add(i)));
		}
		for (int i = 500; i < 1000; ++i) {
			assertEquals(0xb, blocks[0].getByte(blocks[0].getStart().add(i)));
		}
		for (int i = 0; i < 500; ++i) {
			assertEquals(0xb, blocks[1].getByte(blocks[1].getStart().add(i)));
		}
	}

	@Test
	public void testGetByteOnUnitializedBlock() {
		MemoryBlock block = mbu.createUninitializedBlock(false, "a", space.getAddress(3000), 1000,
			"Acomment", "Asource", true, true, true);
		try {
			block.getByte(space.getAddress(3000));
			Assert.fail("Got byte from uninitialized block");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}

	/**
	 * This method tests removing the 
	 * 2nd half of one uninitialized block and the 
	 * 1st half of another uninitialized block.
	 * @throws Exception
	 */
	@Test
	public void testUninitializedConflict() throws Exception {
		mbu.createUninitializedBlock(false, "a", space.getAddress(3000), 1000, "Acomment",
			"Asource", true, true, true);
		mbu.createUninitializedBlock(false, "b", space.getAddress(4000), 1000, "Bcomment",
			"Bsource", true, true, true);

		byte[] cdata = new byte[1000];
		Arrays.fill(cdata, (byte) 0xc);
		mbu.createInitializedBlock("c", space.getAddress(3500), new ByteArrayInputStream(cdata),
			1000, "Ccomment", "Csource", false, false, false, TaskMonitorAdapter.DUMMY_MONITOR);

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(3, blocks.length);

		assertEquals("a", blocks[0].getName());
		assertEquals("c", blocks[1].getName());
		assertEquals("b", blocks[2].getName());

		assertEquals(500, blocks[0].getSize());
		assertEquals(1000, blocks[1].getSize());
		assertEquals(500, blocks[2].getSize());

		assertTrue(!blocks[0].isInitialized());
		assertTrue(blocks[1].isInitialized());
		assertTrue(!blocks[2].isInitialized());
	}

	@Test
	public void testUninitializedConflictWhole() throws Exception {
		mbu.createUninitializedBlock(false, "a", space.getAddress(3000), 1000, "Acomment",
			"Asource", true, true, true);

		byte[] cdata = new byte[1000];
		Arrays.fill(cdata, (byte) 0xc);
		mbu.createInitializedBlock("c", space.getAddress(3000), new ByteArrayInputStream(cdata),
			1000, "Ccomment", "Csource", false, false, false, TaskMonitorAdapter.DUMMY_MONITOR);

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(1, blocks.length);
		assertEquals("c", blocks[0].getName());
		assertEquals(1000, blocks[0].getSize());
		assertTrue(blocks[0].isInitialized());
	}

	@Test
	public void testUninitializedConflictMiddle() throws Exception {
		mbu.createUninitializedBlock(false, "a", space.getAddress(3000), 3000, "Acomment",
			"Asource", true, true, true);

		byte[] cdata = new byte[1000];
		Arrays.fill(cdata, (byte) 0xc);
		mbu.createInitializedBlock("c", space.getAddress(4000), new ByteArrayInputStream(cdata),
			1000, "Ccomment", "Csource", false, false, false, TaskMonitorAdapter.DUMMY_MONITOR);

		MemoryBlock[] blocks = prog.getMemory().getBlocks();
		assertEquals(3, blocks.length);

		assertEquals("a", blocks[0].getName());
		assertEquals("c", blocks[1].getName());
		assertEquals("a", blocks[2].getName());

		assertEquals(1000, blocks[0].getSize());
		assertEquals(1000, blocks[1].getSize());
		assertEquals(1000, blocks[2].getSize());

		assertTrue(!blocks[0].isInitialized());
		assertTrue(blocks[1].isInitialized());
		assertTrue(!blocks[2].isInitialized());
	}

	//TODO test bit blocks and code unit clearing...
}
