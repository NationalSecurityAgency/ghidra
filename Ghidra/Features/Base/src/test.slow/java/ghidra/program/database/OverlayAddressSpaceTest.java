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

import org.junit.*;

import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.task.TaskMonitor;

public class OverlayAddressSpaceTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private ProgramDB program;

	public OverlayAddressSpaceTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
	}

	@After
	public void tearDown() throws Exception {

		if (program != null) {
			env.release(program);
		}
		env.dispose();
	}

	@Test
	public void testOverlaySpace() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY, this);
		program = builder.getProgram();

		doTest();

		int transactionID = program.startTransaction(testName.getMethodName());
		try {

			AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

			Memory memory = program.getMemory();
			MemoryBlock ramBlock = memory.createInitializedBlock("ram",
				defaultSpace.getAddress("0F80"), 0x100, (byte) 0, null, false);
			for (int i = 0; i < 0x100; i++) {
				memory.setByte(defaultSpace.getAddress(0xf80 + i), (byte) i);
			}

			AddressSpace overlaySpace = program.getAddressFactory().getAddressSpace(".overlay1");
			assertNotNull(overlaySpace);

			MemoryBlock overlayBlock = memory.getBlock(".overlay1");// 1000-10ff
			assertNotNull(overlayBlock);

			try {
				ramBlock.putByte(overlaySpace.getAddressInThisSpaceOnly(0xfa0), (byte) 0x12);
				Assert.fail("Expected MemoryAccessException");
			}
			catch (MemoryAccessException e) {
				// expected
			}

			try {
				overlayBlock.putByte(overlaySpace.getAddressInThisSpaceOnly(0xfa0), (byte) 0x12);
				Assert.fail("Expected MemoryAccessException");
			}
			catch (MemoryAccessException e) {
				// expected
			}

			for (int i = 0; i < 0x100; i++) {
				memory.setByte(overlaySpace.getAddress(0x1000 + i), (byte) i);
			}

			for (int i = 0; i < 0x100; i++) {
				assertEquals((byte) i, ramBlock.getByte(defaultSpace.getAddress(0xf80 + i)));
			}

			for (int i = 0; i < 0x100; i++) {
				assertEquals((byte) i, overlayBlock.getByte(overlaySpace.getAddress(0x1000 + i)));
			}

			for (int i = 0; i < 0x80; i++) {
				assertEquals((byte) (0x80 + i),
					memory.getByte(overlaySpace.getAddress(0x1000 + i).getPhysicalAddress()));
			}

			try {
				memory.getByte(overlaySpace.getAddress(0x1F0).getPhysicalAddress());
				Assert.fail("Expected MemoryAccessException");
			}
			catch (MemoryAccessException e) {
				// expected
			}

		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	@Test
	public void testAddSubtractAddressFromOverlayAndNonOverlaySpaces() throws Exception {

		AddressSpace space1 = new GenericAddressSpace("space1", 32, AddressSpace.TYPE_RAM, 0);
		AddressSpace space3 = new GenericAddressSpace("space3", 32, AddressSpace.TYPE_RAM, 3);
		AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] { space1, space3 });
		space1 = factory.getAddressSpace(space1.getName());
		space3 = factory.getAddressSpace(space3.getName());

		OverlayAddressSpace space1Overlay =
			new OverlayAddressSpace("Overlay1", space1, 4, 0x20, 0x30);

		Address space1Address = space1.getAddress(0x20);
		Address space1OverlayAddress = space1Overlay.getAddress(0x22);
		Address space3Address = space3.getAddress(0x70);

		try {
			space1Address.subtract(space1OverlayAddress);
		}
		catch (IllegalArgumentException iae) {
			Assert.fail("Received unexpected exceptions during subtraction of addresses from " +
				"similar spaces");
		}

		try {
			space1OverlayAddress.subtract(space1Address);
		}
		catch (IllegalArgumentException iae) {
			Assert.fail("Received unexpected exceptions during subtraction of addresses from " +
				"similar spaces");
		}

		try {
			space3Address.subtract(space1OverlayAddress);
			Assert.fail("Did not receive expected exception");
		}
		catch (IllegalArgumentException iae) {
			// expected
		}

		try {
			space1OverlayAddress.subtract(space3Address);
			Assert.fail("Did not receive expected exception");
		}
		catch (IllegalArgumentException iae) {
			// expected
		}

		AddressSpace overlaySpace = space1OverlayAddress.getAddressSpace();
		Assert.assertNotEquals(space1, overlaySpace);

		AddressSpace nonOverlaySpace = space3Address.getAddressSpace();
		Assert.assertNotEquals(overlaySpace, nonOverlaySpace);

		int overlayBaseID = ((OverlayAddressSpace) overlaySpace).getBaseSpaceID();
		int spaceBaseID = space1.getSpaceID();
		assertEquals(overlayBaseID, spaceBaseID);

		int nonBaseID = nonOverlaySpace.getSpaceID();
		Assert.assertNotEquals(overlayBaseID, nonBaseID);
	}

	@Test
	public void testOverlayAddressTruncation() throws Exception {

		// TODO: This really belongs in an Impl test - not ProgramDB

		AddressSpace space1 = new GenericAddressSpace("space1", 31, 2, AddressSpace.TYPE_RAM, 0);
		AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] { space1 });
		space1 = factory.getAddressSpace(space1.getName());

		OverlayAddressSpace space1Overlay =
			new OverlayAddressSpace("Overlay1", space1, 4, 0x20, 0x30);

		assertEquals(0x25, space1Overlay.truncateOffset(0x25));
		assertEquals(0x40, space1Overlay.truncateOffset(0x40));
		assertEquals(0x40, space1Overlay.truncateOffset(0x200000040L));
		assertEquals(0x25, space1Overlay.truncateOffset(0x200000025L));

		assertEquals(0x15, space1Overlay.truncateAddressableWordOffset(0x15));
		assertEquals(0x20, space1Overlay.truncateAddressableWordOffset(0x20));
		assertEquals(0x15, space1Overlay.truncateAddressableWordOffset(0x80000015));
		assertEquals(0x20, space1Overlay.truncateAddressableWordOffset(0x80000020));

		Address addr = space1Overlay.getTruncatedAddress(0x200000025L, false);
		assertEquals(space1Overlay, addr.getAddressSpace());
		assertEquals(0x25, addr.getOffset());

		addr = space1Overlay.getTruncatedAddress(0x200000040L, false);
		assertEquals(space1Overlay.getPhysicalSpace(), addr.getAddressSpace());
		assertEquals(0x40, addr.getOffset());

		addr = space1Overlay.getTruncatedAddress(0x80000015L, true);
		assertEquals(space1Overlay, addr.getAddressSpace());
		assertEquals(0x15, addr.getAddressableWordOffset());

		addr = space1Overlay.getTruncatedAddress(0x80000025L, true);
		assertEquals(space1Overlay.getPhysicalSpace(), addr.getAddressSpace());
		assertEquals(0x25, addr.getAddressableWordOffset());

	}

	@Test
	public void testOverlayRename() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY, this);
		program = builder.getProgram();

		AddressFactory af = program.getAddressFactory();

		int transactionID = program.startTransaction(testName.getMethodName());
		try {
			MemoryBlock overlayBlock1 = program.getMemory()
					.createInitializedBlock("my overlay x", af.getAddress("1000"), 0x100,
						(byte) 0x11, TaskMonitor.DUMMY, true);
			MemoryBlock overlayBlock2 = program.getMemory()
					.createInitializedBlock("my overlay:x", af.getAddress("1000"), 0x100,
						(byte) 0x11, TaskMonitor.DUMMY, true);

			assertEquals("my_overlay_x", overlayBlock1.getStart().getAddressSpace().getName());
			assertEquals("my_overlay_x.1", overlayBlock2.getStart().getAddressSpace().getName());

			overlayBlock1.setName("my new name");
			assertEquals("my new name", overlayBlock1.getName());
			assertEquals("my_new_name", overlayBlock1.getStart().getAddressSpace().getName());
			assertNull(af.getAddressSpace("my_overlay_x"));
			assertNotNull(af.getAddressSpace("my_new_name"));

			overlayBlock2.setName("my new name");
			assertEquals("my new name", overlayBlock2.getName());
			assertEquals("my_new_name.1", overlayBlock2.getStart().getAddressSpace().getName());
			assertNull(af.getAddressSpace("my_overlay_x.1"));
			assertNotNull(af.getAddressSpace("my_new_name.1"));

		}
		finally {
			program.endTransaction(transactionID, true);
		}

	}

	private void doTest() throws Exception {
		AddressFactory af = program.getAddressFactory();

		int origSpaceCount = af.getNumAddressSpaces();
		int origBlockCount = program.getMemory().getBlocks().length;

		int transactionID = program.startTransaction(testName.getMethodName());
		MemoryBlock overlayBlock1 = null;
		try {
			overlayBlock1 = program.getMemory().createInitializedBlock(".overlay1",
				af.getAddress("1000"), 0x100, (byte) 0x11, TaskMonitor.DUMMY, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertNotNull(overlayBlock1);
		assertEquals(origSpaceCount + 1, af.getNumAddressSpaces());
		assertTrue(af.getAddressSpaces()[af.getNumAddressSpaces() - 1].isOverlaySpace());
		program.undo();
		assertEquals(origSpaceCount, af.getNumAddressSpaces());
		program.redo();
		assertEquals(origSpaceCount + 1, af.getNumAddressSpaces());

		transactionID = program.startTransaction(testName.getMethodName());
		try {
			overlayBlock1 = program.getMemory().getBlock(overlayBlock1.getName());
			program.getMemory().removeBlock(overlayBlock1, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertEquals(origSpaceCount, af.getNumAddressSpaces());
		program.undo();
		assertEquals(origSpaceCount + 1, af.getNumAddressSpaces());
		program.redo();
		assertEquals(origSpaceCount, af.getNumAddressSpaces());
		program.undo();
		assertEquals(origSpaceCount + 1, af.getNumAddressSpaces());

		transactionID = program.startTransaction(testName.getMethodName());
		MemoryBlock overlayBlock2 = null;
		MemoryBlock overlayBlock3 = null;
		MemoryBlock overlayBlock4 = null;
		try {
			overlayBlock2 = program.getMemory().createInitializedBlock(".overlay2",
				af.getAddress("2000"), 0x200, (byte) 0x22, TaskMonitor.DUMMY, true);
			overlayBlock3 = program.getMemory()
					.createInitializedBlock("my_overlay_x",
						af.getAddress("3000"), 0x300, (byte) 0x33, TaskMonitor.DUMMY, true);
			overlayBlock4 = program.getMemory()
					.createInitializedBlock("my overlay:x",
						af.getAddress("4000"), 0x400, (byte) 0x44, TaskMonitor.DUMMY, true);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertEquals(origSpaceCount + 4, af.getNumAddressSpaces());
		MemoryBlock[] blocks = program.getMemory().getBlocks();
		assertEquals(".overlay1", blocks[origBlockCount + 0].getName());
		assertEquals(".overlay2", blocks[origBlockCount + 1].getName());
		assertEquals("my_overlay_x", blocks[origBlockCount + 2].getName());
		assertEquals("my_overlay_x",
			blocks[origBlockCount + 2].getStart().getAddressSpace().getName());
		assertEquals("my overlay:x", blocks[origBlockCount + 3].getName());
		assertEquals("my_overlay_x.1",
			blocks[origBlockCount + 3].getStart().getAddressSpace().getName());

		AddressSpace ovSpace3 = program.getAddressFactory().getAddressSpace("my_overlay_x");
		assertNotNull(ovSpace3);

		AddressSpace ovSpace4 = program.getAddressFactory().getAddressSpace("my_overlay_x.1");
		assertNotNull(ovSpace4);

		transactionID = program.startTransaction(testName.getMethodName());
		try {
			program.getMemory().removeBlock(overlayBlock2, TaskMonitor.DUMMY);
			program.getMemory().removeBlock(overlayBlock3, TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
		assertEquals(origSpaceCount + 2, af.getNumAddressSpaces());
		blocks = program.getMemory().getBlocks();
		assertEquals(overlayBlock1.getName(), blocks[origBlockCount + 0].getName());
		assertEquals(overlayBlock4.getName(), blocks[origBlockCount + 1].getName());

		ovSpace3 = program.getAddressFactory().getAddressSpace("my_overlay_x");
		assertNull(ovSpace3);

		ovSpace4 = program.getAddressFactory().getAddressSpace("my_overlay_x.1");
		assertNotNull(ovSpace4);

		program.undo();
		assertEquals(origSpaceCount + 4, af.getNumAddressSpaces());
		blocks = program.getMemory().getBlocks();
		overlayBlock1 = program.getMemory().getBlock(overlayBlock1.getName());
		overlayBlock2 = program.getMemory().getBlock(overlayBlock2.getName());
		overlayBlock3 = program.getMemory().getBlock(overlayBlock3.getName());
		overlayBlock4 = program.getMemory().getBlock(overlayBlock4.getName());
		assertEquals(overlayBlock1.getName(), blocks[origBlockCount + 0].getName());
		assertEquals(overlayBlock2.getName(), blocks[origBlockCount + 1].getName());
		assertEquals(overlayBlock3.getName(), blocks[origBlockCount + 2].getName());
		assertEquals(overlayBlock4.getName(), blocks[origBlockCount + 3].getName());

		ovSpace3 = program.getAddressFactory().getAddressSpace("my_overlay_x");
		assertNotNull(ovSpace3);

		ovSpace4 = program.getAddressFactory().getAddressSpace("my_overlay_x.1");
		assertNotNull(ovSpace4);

		program.redo();
		assertEquals(origSpaceCount + 2, af.getNumAddressSpaces());
		blocks = program.getMemory().getBlocks();
		overlayBlock1 = program.getMemory().getBlock(overlayBlock1.getName());
		overlayBlock2 = program.getMemory().getBlock(overlayBlock2.getName());
		overlayBlock3 = program.getMemory().getBlock(overlayBlock3.getName());
		overlayBlock4 = program.getMemory().getBlock(overlayBlock4.getName());
		assertEquals(overlayBlock1.getName(), blocks[origBlockCount + 0].getName());
		assertEquals(overlayBlock4.getName(), blocks[origBlockCount + 1].getName());

	}
}
