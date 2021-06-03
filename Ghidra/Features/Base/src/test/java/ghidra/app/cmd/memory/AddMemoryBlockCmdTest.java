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
package ghidra.app.cmd.memory;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.framework.cmd.Command;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.mem.ByteMappingScheme;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.util.exception.RollbackException;

/**
 * Test for the add memory block command.
 */
public class AddMemoryBlockCmdTest extends AbstractGenericTest {
	private Program notepad;
	private Program x08;
	private Command command;

	public AddMemoryBlockCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		ProgramBuilder notepadBuilder = new ProgramBuilder("notepad", ProgramBuilder._TOY);
		notepadBuilder.createMemory("test2", "0x1001010", 100);
		notepad = notepadBuilder.getProgram();

		ProgramBuilder x08Builder = new ProgramBuilder("x08", ProgramBuilder._8051);
		x08Builder.createMemory("test1", "0x0", 400);

		x08 = x08Builder.getProgram();
	}

	@Test
	public void testAddBlock() throws Exception {
		command = new AddInitializedMemoryBlockCmd(".test", "A Test", "new block",
			getNotepadAddr(0x100), 100, true, true, true, false, (byte) 0xa, false);
		assertTrue(applyCmd(notepad, command));
		MemoryBlock block = notepad.getMemory().getBlock(getNotepadAddr(0x100));
		assertNotNull(block);
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertFalse(block.isOverlay());
		byte b = block.getByte(getNotepadAddr(0x100));
		assertEquals((byte) 0xa, b);

		// get the fragment for this block
		Listing listing = notepad.getListing();
		String[] treeNames = listing.getTreeNames();
		ProgramFragment f = listing.getFragment(treeNames[0], getNotepadAddr(0x100));
		assertNotNull(f);
		assertEquals(block.getName(), f.getName());
	}

	private boolean applyCmd(Program p, Command c) {
		int txId = p.startTransaction(c.getName());
		boolean commit = true;
		try {
			return c.applyTo(p);
		}
		catch (RollbackException e) {
			commit = false;
			throw e;
		}
		finally {
			p.endTransaction(txId, commit);
		}
	}

	@Test
	public void testOverlap() {
		command = new AddInitializedMemoryBlockCmd(".test", "A Test", "new block",
			getNotepadAddr(0x1001010), 100, true, true, true, false, (byte) 0xa, false);
		try {
			applyCmd(notepad, command);
			Assert.fail("Should have gotten exception");
		}
		catch (RollbackException e) {
			// good
		}
		assertTrue(command.getStatusMsg().length() > 0);
	}

	@Test
	public void testAddBitBlock() {
		Address addr = getX08Addr(0x3000);
		command = new AddBitMappedMemoryBlockCmd(".testBit", "A Test", "new block", addr, 100, true,
			true, true, false, getX08Addr(0), false);
		assertTrue(applyCmd(x08, command));
		// map 100 byte block from source of 12-bytes (96 bits) + partial byte (4 bits)
		MemoryBlock block = x08.getMemory().getBlock(addr);
		assertNotNull(block);
		assertEquals(100, block.getSize());
		assertEquals(getX08Addr(0x3000), block.getStart());
		assertEquals(getX08Addr(0x3063), block.getEnd());
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		AddressRange mappedRange = info.getMappedRange().get();
		assertEquals(13, mappedRange.getLength());
		assertEquals(getX08Addr(0), mappedRange.getMinAddress());
		assertEquals(getX08Addr(12), mappedRange.getMaxAddress());
		assertEquals(MemoryBlockType.BIT_MAPPED, block.getType());
		assertFalse(block.isOverlay());
	}

	@Test
	public void testAddBitOverlayBlock() {
		Address addr = getX08Addr(0x3000);
		command = new AddBitMappedMemoryBlockCmd(".testBit", "A Test", "new block", addr, 100, true,
			true, true, false, getX08Addr(0), true);
		assertTrue(applyCmd(x08, command));

		MemoryBlock block = x08.getMemory().getBlock(addr);
		assertNull(block);
		block = x08.getMemory().getBlock(".testBit");
		assertNotNull(block);
		assertEquals(100, block.getSize());
		AddressSpace space = x08.getAddressFactory().getAddressSpace(".testBit");
		assertNotNull(space);
		assertTrue(space.isOverlaySpace());
		assertEquals(space.getAddress(0x3000), block.getStart());
		assertEquals(space.getAddress(0x3063), block.getEnd());
		assertEquals(block.getStart(), space.getMinAddress());
		assertEquals(block.getEnd(), space.getMaxAddress());
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		AddressRange mappedRange = info.getMappedRange().get();
		assertEquals(13, mappedRange.getLength());
		assertEquals(getX08Addr(0), mappedRange.getMinAddress());
		assertEquals(getX08Addr(12), mappedRange.getMaxAddress());
		assertEquals(MemoryBlockType.BIT_MAPPED, block.getType());
		assertTrue(block.isOverlay());
	}

	@Test
	public void testAddByteBlock() {
		Address addr = getX08Addr(0x3000);
		command = new AddByteMappedMemoryBlockCmd(".testByte", "A Test", "new block", addr, 100,
			true, true, true, false, getX08Addr(0), false);
		assertTrue(applyCmd(x08, command));

		MemoryBlock block = x08.getMemory().getBlock(addr);
		assertNotNull(block);
		assertEquals(100, block.getSize());
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		assertEquals(getX08Addr(0), info.getMappedRange().get().getMinAddress());
		assertEquals(getX08Addr(99), info.getMappedRange().get().getMaxAddress());
		assertEquals(MemoryBlockType.BYTE_MAPPED, block.getType());
		assertFalse(block.isOverlay());
	}

	@Test
	public void testAddByteBlockWithScheme() {
		Address addr = getX08Addr(0x3000);
		command = new AddByteMappedMemoryBlockCmd(".testByte", "A Test", "new block", addr, 100,
			true, true, true, false, getX08Addr(0), new ByteMappingScheme(2, 4), false);
		assertTrue(applyCmd(x08, command));

		MemoryBlock block = x08.getMemory().getBlock(addr);
		assertNotNull(block);
		assertEquals(100, block.getSize());
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		assertEquals(getX08Addr(0), info.getMappedRange().get().getMinAddress());
		assertEquals(getX08Addr(197), info.getMappedRange().get().getMaxAddress());
		assertEquals(MemoryBlockType.BYTE_MAPPED, block.getType());
		assertFalse(block.isOverlay());
	}

	@Test
	public void testAddByteOverlayBlock() {
		Address addr = getX08Addr(0x3000);
		command = new AddByteMappedMemoryBlockCmd(".testByte", "A Test", "new block", addr, 100,
			true, true, true, false, getX08Addr(0), true);
		assertTrue(applyCmd(x08, command));

		MemoryBlock block = x08.getMemory().getBlock(addr);
		assertNull(block);
		block = x08.getMemory().getBlock(".testByte");
		assertNotNull(block);
		assertEquals(100, block.getSize());
		AddressSpace space = x08.getAddressFactory().getAddressSpace(".testByte");
		assertNotNull(space);
		assertTrue(space.isOverlaySpace());
		assertEquals(space.getAddress(0x3000), block.getStart());
		assertEquals(space.getAddress(0x3063), block.getEnd());
		assertEquals(block.getStart(), space.getMinAddress());
		assertEquals(block.getEnd(), space.getMaxAddress());
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		AddressRange mappedRange = info.getMappedRange().get();
		assertEquals(100, mappedRange.getLength());
		assertEquals(getX08Addr(0), mappedRange.getMinAddress());
		assertEquals(getX08Addr(99), mappedRange.getMaxAddress());
		assertEquals(MemoryBlockType.BYTE_MAPPED, block.getType());
		assertTrue(block.isOverlay());
	}

	@Test
	public void testAddByteOverlayBlockWithScheme() {
		Address addr = getX08Addr(0x3000);
		command = new AddByteMappedMemoryBlockCmd(".testByte", "A Test", "new block", addr, 100,
			true, true, true, false, getX08Addr(0), new ByteMappingScheme(2, 4), true);
		assertTrue(applyCmd(x08, command));

		MemoryBlock block = x08.getMemory().getBlock(addr);
		assertNull(block);
		block = x08.getMemory().getBlock(".testByte");
		assertNotNull(block);
		assertEquals(100, block.getSize());
		AddressSpace space = x08.getAddressFactory().getAddressSpace(".testByte");
		assertNotNull(space);
		assertTrue(space.isOverlaySpace());
		assertEquals(space.getAddress(0x3000), block.getStart());
		assertEquals(space.getAddress(0x3063), block.getEnd());
		assertEquals(block.getStart(), space.getMinAddress());
		assertEquals(block.getEnd(), space.getMaxAddress());
		MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
		AddressRange mappedRange = info.getMappedRange().get();
		assertEquals(198, mappedRange.getLength());
		assertEquals(getX08Addr(0), mappedRange.getMinAddress());
		assertEquals(getX08Addr(197), mappedRange.getMaxAddress());
		assertEquals(MemoryBlockType.BYTE_MAPPED, block.getType());
		assertTrue(block.isOverlay());
	}

	@Test
	public void testAddOverlayBlock() throws Exception {
		Address addr = getX08Addr(0x3000);
		command = new AddInitializedMemoryBlockCmd(".overlay", "A Test", "new block", addr, 100,
			true, true, true, false, (byte) 0xa, true);
		assertTrue(applyCmd(x08, command));

		MemoryBlock block = null;
		MemoryBlock[] blocks = x08.getMemory().getBlocks();
		for (MemoryBlock block2 : blocks) {
			if (block2.getName().equals(".overlay")) {
				block = block2;
				break;
			}
		}
		assertNotNull(block);
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isOverlay());
		byte b = block.getByte(block.getStart().getNewAddress(0x3000));
		assertEquals((byte) 0xa, b);
	}

	private Address getX08Addr(int offset) {
		return x08.getMinAddress().getNewAddress(offset);
	}

	private Address getNotepadAddr(int offset) {
		return notepad.getMinAddress().getNewAddress(offset);
	}
}
