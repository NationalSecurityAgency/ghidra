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
package ghidra.program.database;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitorAdapter;

public class ProgramOverlaysTest extends AbstractGenericTest {

	private Program p;
	private Memory memory;
	private AddressSpace defaultSpace;

	byte[] fillB = new byte[] { 6, 7, 8, 9 };
	byte[] fillA = new byte[] { 1, 2, 3, 4 };

	public ProgramOverlaysTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		p = builder.getProgram();
		memory = p.getMemory();
		defaultSpace = p.getAddressFactory().getDefaultAddressSpace();
		p.addConsumer(this);
		builder.dispose();
	}

	@After
	public void tearDown() throws Exception {
		p.release(this);
	}

	private AddressSpace initOverlay() throws Exception {

		assertEquals(2, p.getAddressFactory().getNumAddressSpaces()); // ram, OTHER

		int id = p.startTransaction("");
		memory.createInitializedBlock("RAM", defaultSpace.getAddress(0x100), 1000, (byte) 0, null,
			false);
		memory.setBytes(defaultSpace.getAddress(0x100), fillA);
		memory.createInitializedBlock("OV1", defaultSpace.getAddress(0x100), 1000, (byte) 0, null,
			true);
		assertEquals(3, p.getAddressFactory().getNumAddressSpaces()); // ram, OTHER, OV1
		AddressSpace space = p.getAddressFactory().getAddressSpace("OV1");
		assertNotNull(space);
		memory.setBytes(space.getAddress(0x100), fillB);
		p.getReferenceManager().addMemoryReference(addr(p, "0x1001003"), addr(p, "OV1:0x100"),
			RefType.DATA, SourceType.USER_DEFINED, 0);
		p.endTransaction(id, true);

		return space;
	}

	@Test
	public void testAddOverlay() throws Exception {

		AddressSpace space = initOverlay();

		assertTrue(space.isOverlaySpace());
		assertEquals(space, p.getAddressFactory().getAddressSpace("OV1"));

		MemoryBlock block = memory.getBlock("OV1");
		assertNotNull(block);

		Reference[] refs = p.getReferenceManager().getReferencesFrom(addr(p, "0x1001003"));
		assertEquals(1, refs.length);
		assertEquals("OV1::00000100", refs[0].getToAddress().toString());

		byte[] bytes = new byte[4];

		Address addr = defaultSpace.getAddress(0x100);
		assertFalse(block.contains(addr));
		assertEquals("ram:00000100", addr.toString(true));
		memory.getBytes(addr, bytes);
		assertTrue(Arrays.equals(fillA, bytes));

		addr = space.getAddress(0x100);
		assertTrue(block.contains(addr));
		assertEquals("OV1::00000100", addr.toString());
		memory.getBytes(addr, bytes);
		assertTrue(Arrays.equals(fillB, bytes));
		block.getByte(addr);
		assertTrue(Arrays.equals(fillB, bytes));
	}

	@Test
	public void testRemoveOverlay() throws Exception {

		initOverlay();

		MemoryBlock block = memory.getBlock("OV1");
		assertNotNull(block);

		int id = p.startTransaction("");
		memory.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);
		p.endTransaction(id, true);

		assertEquals(2, p.getAddressFactory().getNumAddressSpaces()); // ram, OTHER
		assertNull(p.getAddressFactory().getAddressSpace("OV1"));

		Reference[] refs = p.getReferenceManager().getReferencesFrom(addr(p, "0x1001003"));
		assertEquals(1, refs.length);
		assertEquals("Deleted_OV1:00000100", refs[0].getToAddress().toString());

	}

	@Test
	public void testRenameOverlay() throws Exception {

		AddressSpace space = initOverlay();

		MemoryBlock block = memory.getBlock("OV1");
		assertNotNull(block);

		int id = p.startTransaction("");
		block.setName("BOB");
		p.endTransaction(id, true);

		assertEquals("BOB", block.getName());
		assertEquals(block, memory.getBlock("BOB"));

		assertEquals("BOB", space.getName());
		assertEquals(space, p.getAddressFactory().getAddressSpace("BOB"));

		Reference[] refs = p.getReferenceManager().getReferencesFrom(addr(p, "0x1001003"));
		assertEquals(1, refs.length);
		assertEquals("BOB::00000100", refs[0].getToAddress().toString());

	}

	Address addr(Program p, String addrString) {
		AddressFactory af = p.getAddressFactory();
		return af.getAddress(addrString);
	}
}
