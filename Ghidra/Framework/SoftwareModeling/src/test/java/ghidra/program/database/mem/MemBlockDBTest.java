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

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.*;

import db.DBConstants;
import db.DBHandle;
import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.framework.Application;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.Lock;
import ghidra.util.task.TaskMonitor;

public class MemBlockDBTest extends AbstractGenericTest {
	private static final long MAX_SUB_BLOCK_SIZE = 16;
	private MemoryMapDB mem;
	private long txID;
	private DBHandle handle;
	private AddressFactory addressFactory;
	private ProgramDB program;
	private int ptxID;

	@Before
	public void setUp() throws Exception {
		Language language = getLanguage("Toy:BE:64:default");
		CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
		program = new ProgramDB("Test", language, compilerSpec, this);
		ptxID = program.startTransaction("test");

		handle = new DBHandle();

		txID = handle.startTransaction();

		addressFactory = language.getAddressFactory();
		AddressMapDB addrMap = (AddressMapDB) program.getAddressMap();
		Lock lock = new Lock("Test");
		int openMode = DBConstants.CREATE;
		mem = new MemoryMapDB(handle, addrMap, openMode, true, lock);

		MemoryMapDBAdapter adapter =
			new MemoryMapDBAdapterV3(handle, mem, MAX_SUB_BLOCK_SIZE, true);
		FileBytesAdapter fileBytesAdapter = new FileBytesAdapterV0(handle, true);

		mem.init(adapter, fileBytesAdapter);
		mem.setProgram(program);

	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(ptxID, true);
		handle.endTransaction(txID, true);
		handle.close();
		program.release(this);
	}

	@Test
	public void testCreateInitializedBlock() throws Exception {
		MemoryBlock block =
			mem.createInitializedBlock("test", addr(0), 10, (byte) 1, TaskMonitor.DUMMY, false);

		assertEquals(10, block.getSize());
		assertEquals("test", block.getName());
		assertEquals(addr(0), block.getStart());
		assertEquals(addr(9), block.getEnd());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertEquals(true, block.isInitialized());
		assertEquals(false, block.isMapped());
		assertNull(block.getComment());
		assertNull(block.getSourceName());
		assertEquals(MemoryBlock.READ, block.getPermissions());

		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();

		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(10, info.getLength());
		assertEquals(addr(0), info.getMinAddress());
		assertEquals(addr(9), info.getMaxAddress());
		for (int i = 0; i < 10; i++) {
			assertEquals(1, block.getByte(addr(i)));
		}
	}

	@Test
	public void testCreateUninitializedBlock() throws Exception {
		MemoryBlock block = mem.createUninitializedBlock("test", addr(0), 10, false);

		assertEquals(10, block.getSize());
		assertEquals("test", block.getName());
		assertEquals(addr(0), block.getStart());
		assertEquals(addr(9), block.getEnd());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(10, info.getLength());
		assertEquals(addr(0), info.getMinAddress());
		assertEquals(addr(9), info.getMaxAddress());
		try {
			block.getByte(addr(0));
			fail("expected exception trying to read bytes on unitialized block");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}

	@Test
	public void testCreateUnitializedOverlayBlock() throws Exception {
		MemoryBlock block = mem.createUninitializedBlock("test", addr(0), 10, true);

		assertEquals(10, block.getSize());
		assertEquals("test", block.getName());
		assertNotEquals(addr(0), block.getStart());  // block should be in overlay space
		assertEquals(0, block.getStart().getOffset());
		assertEquals(9, block.getEnd().getOffset());
		assertTrue(block.getStart().getAddressSpace().isOverlaySpace());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isOverlay());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(10, info.getLength());
		try {
			block.getByte(block.getStart());
			fail("expected exception trying to read bytes on unitialized block");
		}
		catch (MemoryAccessException e) {
			// expected
		}
	}

	@Test
	public void testCreateInitializedOverlayBlock() throws Exception {
		MemoryBlock block =
			mem.createInitializedBlock("test", addr(0), 10, (byte) 1, TaskMonitor.DUMMY, true);

		assertEquals(10, block.getSize());
		assertEquals("test", block.getName());
		assertNotEquals(addr(0), block.getStart());  // block should be in overlay space
		assertEquals(0, block.getStart().getOffset());
		assertEquals(9, block.getEnd().getOffset());
		assertTrue(block.getStart().getAddressSpace().isOverlaySpace());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isOverlay());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(10, info.getLength());
		for (int i = 0; i < 10; i++) {
			assertEquals(1, block.getByte(block.getStart().add(i)));
		}
	}

	@Test
	public void testCreateByteMappedBlock() throws Exception {
		mem.createInitializedBlock("test1", addr(0), 50, (byte) 1, TaskMonitor.DUMMY, false);
		mem.createUninitializedBlock("test2", addr(50), 50, false);
		MemoryBlock block = mem.createByteMappedBlock("mapped", addr(1000), addr(40), 20, false);

		assertEquals(20, block.getSize());
		assertEquals("mapped", block.getName());
		assertEquals(addr(1000), block.getStart());
		assertEquals(addr(1019), block.getEnd());
		assertEquals(MemoryBlockType.BYTE_MAPPED, block.getType());
		assertEquals(false, block.isInitialized());
		assertEquals(true, block.isMapped());
		assertNull(block.getComment());
		assertNull(block.getSourceName());
		assertEquals(MemoryBlock.READ, block.getPermissions());

		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();

		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(20, info.getLength());
		assertEquals(new AddressRangeImpl(addr(40), addr(59)), info.getMappedRange().get());

		for (int i = 0; i < 10; i++) {
			assertEquals(1, mem.getByte(block.getStart().add(i)));
		}
		try {
			mem.getByte(block.getStart().add(10));
			fail("expected exception trying to read bytes on mapped unitialized block");
		}
		catch (MemoryAccessException e) {
			// expected 
		}
	}

	@Test
	public void testCreateBitMappedBlock() throws Exception {
		mem.createInitializedBlock("test1", addr(0), 50, (byte) 1, TaskMonitor.DUMMY, false);
		mem.createUninitializedBlock("test2", addr(50), 50, false);
		MemoryBlock block = mem.createBitMappedBlock("mapped", addr(1000), addr(49), 16, false);

		assertEquals(16, block.getSize());
		assertEquals("mapped", block.getName());
		assertEquals(addr(1000), block.getStart());
		assertEquals(addr(1015), block.getEnd());
		assertEquals(MemoryBlockType.BIT_MAPPED, block.getType());
		assertEquals(false, block.isInitialized());
		assertEquals(true, block.isMapped());
		assertNull(block.getComment());
		assertNull(block.getSourceName());
		assertEquals(MemoryBlock.READ, block.getPermissions());

		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();

		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(16, info.getLength());
		assertEquals(new AddressRangeImpl(addr(49), addr(50)), info.getMappedRange().get());

		assertEquals(1, mem.getByte(block.getStart()));
		for (int i = 1; i < 8; i++) {
			assertEquals(0, mem.getByte(block.getStart().add(i)));
		}
		try {
			mem.getByte(block.getStart().add(8));
			fail("expected exception trying to read bytes on mapped unitialized block");
		}
		catch (MemoryAccessException e) {
			// expected 
		}
	}

	@Test
	public void testCreateFileBytesBlock() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block = mem.createInitializedBlock("test", addr(100), fileBytes, 10, 50, false);

		assertEquals(50, block.getSize());
		assertEquals("test", block.getName());
		assertEquals(addr(100), block.getStart());
		assertEquals(addr(149), block.getEnd());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertEquals(true, block.isInitialized());
		assertEquals(false, block.isMapped());
		assertNull(block.getComment());
		assertNull(block.getSourceName());
		assertEquals(MemoryBlock.READ, block.getPermissions());

		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();

		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo info = sourceInfos.get(0);
		assertEquals(50, info.getLength());
		assertEquals(addr(100), info.getMinAddress());
		assertEquals(addr(149), info.getMaxAddress());

		for (int i = 0; i < block.getSize(); i++) {
			assertEquals(i + 10, block.getByte(addr(100 + i)));
		}
	}

	@Test
	public void testCreateFileBytesBlockOutSideRange() throws Exception {
		byte[] bytes = new byte[256];
		FileBytes fileBytes =
			mem.createFileBytes("test", 0, 100, new ByteArrayInputStream(bytes), TaskMonitor.DUMMY);
		try {
			mem.createInitializedBlock("test", addr(100), fileBytes, 10, 100, false);
			fail(
				"Expected create filebytes block to fail because the offset+blockLength > fileBytesLength");
		}
		catch (IndexOutOfBoundsException e) {
			// expected
		}
	}

	@Test
	public void testGetAddressForFileBytesAndOffset() throws Exception {
		FileBytes fileBytes = createFileBytes();
		mem.createInitializedBlock("test1", addr(100), fileBytes, 10, 50, false);
		mem.createInitializedBlock("test2", addr(200), fileBytes, 40, 50, false);

		List<Address> addresses = mem.locateAddressesForFileBytesOffset(fileBytes, 0);
		assertTrue(addresses.isEmpty());

		addresses = mem.locateAddressesForFileBytesOffset(fileBytes, 10);
		assertEquals(1, addresses.size());
		assertEquals(addr(100), addresses.get(0));

		addresses = mem.locateAddressesForFileBytesOffset(fileBytes, 40);
		assertEquals(2, addresses.size());
		assertTrue(addresses.contains(addr(130)));
		assertTrue(addresses.contains(addr(200)));

	}

	@Test
	public void testInitializedBlockAcrossSubBlocks() throws Exception {
		mem.createInitializedBlock("test", addr(0), 100, (byte) 1, TaskMonitor.DUMMY, false);
		assertEquals(0x0101010101010101L, mem.getLong(addr(MAX_SUB_BLOCK_SIZE - 1)));
	}

	@Test
	public void testInitializedBlockAcrossMutlitipleSubBlocks() throws Exception {
		byte[] bytes = new byte[256];
		for (int i = 0; i < 256; i++) {
			bytes[i] = (byte) i;
		}
		mem.createInitializedBlock("test", addr(0), new ByteArrayInputStream(bytes), 256,
			TaskMonitor.DUMMY, false);
		byte[] b = new byte[100];
		assertEquals(100, mem.getBytes(addr(10), b));
		for (int i = 0; i < 100; i++) {
			assertEquals(i + 10, b[i]);
		}
	}

	@Test
	public void testWriteBytesAcrossSubBlocks() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(10), 25, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes, addr(20), 50, 10);
		mem.join(block1, block2);
		byte[] bytes = createBytes(20);
		mem.setBytes(addr(10), bytes);
		byte[] readBytes = new byte[20];
		mem.getBytes(addr(10), readBytes);
		assertTrue(Arrays.equals(bytes, readBytes));
	}

	private byte[] createBytes(int size) {
		byte[] bytes = new byte[size];
		for (int i = 0; i < size; i++) {
			bytes[i] = (byte) i;
		}
		return bytes;
	}

	@Test
	public void testJoinFileBytes() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(10), 25, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes, addr(20), 35, 10);
		MemoryBlock block = mem.join(block1, block2);
		assertEquals(1, mem.getBlocks().length);
		assertEquals(20, block.getSize());
		assertEquals(addr(10), block.getStart());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);
		assertEquals(fileBytes, sourceInfo.getFileBytes().get());
		assertEquals(25, sourceInfo.getFileBytesOffset());
		byte[] bytes = new byte[30];
		assertEquals(20, block.getBytes(addr(10), bytes));
		for (int i = 0; i < 20; i++) {
			assertEquals(i + 25, bytes[i]);
		}
	}

	@Test
	public void testJoinNonConsecutiveFileBytes() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(10), 25, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes, addr(20), 70, 10);

		MemoryBlock block = mem.join(block1, block2);
		assertEquals(1, mem.getBlocks().length);
		assertEquals(20, block.getSize());
		assertEquals(addr(10), block.getStart());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(2, sourceInfos.size());
		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);
		assertEquals(fileBytes, sourceInfo.getFileBytes().get());
		assertEquals(25, sourceInfo.getFileBytesOffset());
		assertEquals(10, sourceInfo.getLength());

		sourceInfo = sourceInfos.get(1);
		assertEquals(fileBytes, sourceInfo.getFileBytes().get());
		assertEquals(70, sourceInfo.getFileBytesOffset());
		assertEquals(10, sourceInfo.getLength());
	}

	@Test
	public void testJoinNonConsecutiveBlocks() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(0), 25, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes, addr(20), 70, 10);
		MemoryBlock block3 = createFileBytesBlock(fileBytes, addr(10), 0, 10);

		MemoryBlock block = mem.join(block1, block3);
		block = mem.join(block1, block2);
		assertEquals(1, mem.getBlocks().length);
		assertEquals(30, block.getSize());
		assertEquals(addr(0), block.getStart());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(3, sourceInfos.size());

		for (int i = 0; i < block.getSize(); i++) {
			mem.getByte(addr(i));
		}
	}

	@Test
	public void testJoinFileBytesBlockAndBufferBlock() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(10), 25, 10);
		MemoryBlock block2 =
			mem.createInitializedBlock("test", addr(20), 10, (byte) 1, TaskMonitor.DUMMY, false);

		MemoryBlock block = mem.join(block1, block2);
		assertEquals(1, mem.getBlocks().length);
		assertEquals(20, block.getSize());
		assertEquals(addr(10), block.getStart());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(2, sourceInfos.size());
		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);
		assertEquals(fileBytes, sourceInfo.getFileBytes().get());
		assertEquals(25, sourceInfo.getFileBytesOffset());
		assertEquals(10, sourceInfo.getLength());

		MemoryBlockSourceInfo sourceInfo2 = sourceInfos.get(1);
		assertEquals(10, sourceInfo2.getLength());
	}

	@Test
	public void testJoinBlocksFromDifferentFileBytes() throws Exception {
		FileBytes fileBytes1 = createFileBytes();
		FileBytes fileBytes2 = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes1, addr(10), 25, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes2, addr(20), 35, 10);

		MemoryBlock block = mem.join(block1, block2);
		assertEquals(1, mem.getBlocks().length);
		assertEquals(20, block.getSize());
		assertEquals(addr(10), block.getStart());
		List<MemoryBlockSourceInfo> sourceInfos = block.getSourceInfos();
		assertEquals(2, sourceInfos.size());

		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);
		assertEquals(fileBytes1, sourceInfo.getFileBytes().get());
		assertEquals(25, sourceInfo.getFileBytesOffset());
		assertEquals(10, sourceInfo.getLength());

		sourceInfo = sourceInfos.get(1);
		assertEquals(fileBytes2, sourceInfo.getFileBytes().get());
		assertEquals(35, sourceInfo.getFileBytesOffset());
		assertEquals(10, sourceInfo.getLength());
	}

	@Test
	public void testSplitAfterExpand() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock block2 = mem.createBlock(block1, block1.getName() + ".exp", addr(50), 50);
		MemoryBlock expandedBlock = mem.join(block1, block2);
		mem.split(expandedBlock, addr(50));
		assertEquals(0, mem.getByte(addr(50)));
	}

	@Test
	public void testSplitFileBytes() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(10), 25, 50);
		mem.split(block1, addr(30));

		MemoryBlock[] blocks = mem.getBlocks();
		assertEquals(2, blocks.length);

		assertEquals(20, blocks[0].getSize());
		assertEquals(30, blocks[1].getSize());

		assertEquals(addr(10), blocks[0].getStart());
		assertEquals(addr(30), blocks[1].getStart());

		List<MemoryBlockSourceInfo> sourceInfos = blocks[0].getSourceInfos();
		assertEquals(1, sourceInfos.size());
		MemoryBlockSourceInfo sourceInfo = sourceInfos.get(0);
		assertEquals(fileBytes, sourceInfo.getFileBytes().get());
		assertEquals(25, sourceInfo.getFileBytesOffset());

		sourceInfos = blocks[1].getSourceInfos();
		assertEquals(1, sourceInfos.size());
		sourceInfo = sourceInfos.get(0);
		assertEquals(fileBytes, sourceInfo.getFileBytes().get());
		assertEquals(45, sourceInfo.getFileBytesOffset());

	}

	@Test
	public void testDeleteFileBytesBlock() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(10), 25, 50);
		mem.removeBlock(block1, TaskMonitor.DUMMY);
		assertEquals(0, mem.getBlocks().length);
	}

	@Test
	public void testPutByteToFileBytesBlockAndGetBothChangedAndOriginalValues() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block = createFileBytesBlock(fileBytes, addr(0), 0, 50);
		byte[] bytes = new byte[20];
		block.getBytes(addr(0), bytes);
		checkBytes(bytes, 0);
		block.getBytes(addr(20), bytes);
		checkBytes(bytes, 20);

		block.putBytes(addr(0), bytes);
		block.getBytes(addr(0), bytes);
		checkBytes(bytes, 20);
		fileBytes.getOriginalBytes(0, bytes);
		checkBytes(bytes, 0);

	}

	@Test
	public void testSplitAndJoinUnitializedBlock() throws Exception {
		MemoryBlock block = mem.createUninitializedBlock("test", addr(0), 40, false);
		mem.split(block, addr(10));
		MemoryBlock[] blocks = mem.getBlocks();
		assertEquals(2, blocks.length);
		assertEquals(addr(0), blocks[0].getStart());
		assertEquals(addr(10), blocks[1].getStart());
		assertEquals(10, blocks[0].getSize());
		assertEquals(30, blocks[1].getSize());
		assertTrue(!blocks[0].isInitialized());
		assertTrue(!blocks[1].isInitialized());

		mem.join(blocks[0], blocks[1]);
		blocks = mem.getBlocks();
		assertEquals(1, blocks.length);
		assertEquals(addr(0), blocks[0].getStart());
		assertEquals(40, blocks[0].getSize());
		List<MemoryBlockSourceInfo> sourceInfos = blocks[0].getSourceInfos();
		assertEquals(1, sourceInfos.size()); 	// make sure the sub blocks were merged
	}

	private void checkBytes(byte[] bytes, int startingValue) {
		for (int i = 0; i < bytes.length; i++) {
			assertEquals(startingValue + i, bytes[i]);
		}
	}

	@Test
	public void testPutBytesToFileBytesBlockAndGetBothChangedAndOriginalValues() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block = createFileBytesBlock(fileBytes, addr(0), 0, 50);
		assertEquals(0, block.getByte(addr(0)));
		block.putByte(addr(0), (byte) 55);
		assertEquals(55, block.getByte(addr(0)));
		assertEquals(0, fileBytes.getOriginalByte(0));
	}

	@Test
	public void testSplitOnSubBlockBoundary() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(0), 0, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes, addr(10), 30, 10);
		mem.join(block1, block2);
		MemoryBlock[] blocks = mem.getBlocks();
		assertEquals(1, blocks.length);
		mem.split(blocks[0], addr(10));
		blocks = mem.getBlocks();
		assertEquals(2, blocks.length);
		assertEquals(1, blocks[0].getSourceInfos().size());
		assertEquals(1, blocks[1].getSourceInfos().size());
	}

	@Test
	public void testByteMappedGetPutByte() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(0), 0, 10);
		MemoryBlock mappedBlock =
			mem.createByteMappedBlock("mapped", addr(100), addr(0), 20, false);
		assertEquals(5, mappedBlock.getByte(addr(105)));
		assertEquals(5, block1.getByte(addr(5)));
		mappedBlock.putByte(addr(105), (byte) 87);
		assertEquals(87, block1.getByte(addr(5)));
	}

	@Test
	public void testByteMappedGetPutBytes() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock =
			mem.createByteMappedBlock("mapped", addr(100), addr(0), 20, false);
		byte[] bytes = new byte[10];
		mappedBlock.getBytes(addr(100), bytes);
		checkBytes(bytes, 0);

		mappedBlock.putBytes(addr(105), bytes);
		block1.getBytes(addr(5), bytes);
		checkBytes(bytes, 0);
	}

	@Test
	public void testByteMappedJoin() throws Exception {
		FileBytes fileBytes = createFileBytes();
		createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock1 =
			mem.createByteMappedBlock("mapped1", addr(100), addr(0), 10, false);
		MemoryBlock mappedBlock2 =
			mem.createByteMappedBlock("mapped2", addr(110), addr(10), 10, false);
		try {
			mem.join(mappedBlock1, mappedBlock2);
			fail("Expected exception when joining byte mapped blocks");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testByteMappedSplit() throws Exception {
		FileBytes fileBytes = createFileBytes();
		createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock1 =
			mem.createByteMappedBlock("mapped1", addr(100), addr(0), 20, false);
		mem.split(mappedBlock1, addr(110));
		MemoryBlock[] blocks = mem.getBlocks();
		assertEquals(3, blocks.length);
		assertEquals(addr(110), blocks[2].getStart());
	}

	@Test
	public void testBitMappedGetPutByte() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block = createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock =
			mem.createBitMappedBlock("mapped1", addr(100), addr(0), 20, false);

		assertEquals(0, mappedBlock.getByte(addr(100)));
		assertEquals(0, mappedBlock.getByte(addr(101)));
		assertEquals(0, mappedBlock.getByte(addr(114)));
		assertEquals(1, mappedBlock.getByte(addr(108)));
		assertEquals(0, mappedBlock.getByte(addr(116)));

		mappedBlock.putByte(addr(100), (byte) 4);
		assertEquals(1, block.getByte(addr(0)));
	}

	@Test
	public void testBitMappedGetPutBytes() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block = createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock =
			mem.createBitMappedBlock("mapped1", addr(100), addr(0), 50, false);

		byte[] bytes = new byte[8];

		mappedBlock.getBytes(addr(108), bytes);
		assertEquals(1, bytes[0]);
		for (int i = 1; i < 8; i++) {
			assertEquals(0, bytes[i]);
		}
		for (int i = 0; i < 8; i++) {
			bytes[i] = 1;
		}
		mappedBlock.putBytes(addr(100), bytes);
		assertEquals(-1, block.getByte(addr(0)));
	}

	@Test
	public void testSetBytesInSubBlocks() throws Exception {
		FileBytes fileBytes = createFileBytes();
		MemoryBlock block1 = createFileBytesBlock(fileBytes, addr(0), 0, 10);
		MemoryBlock block2 = createFileBytesBlock(fileBytes, addr(10), 20, 10);
		mem.join(block1, block2);
		assertEquals(20, mem.getByte(addr(10)));
		mem.setByte(addr(10), (byte) 0);
		assertEquals(0, mem.getByte(addr(10)));
	}

	@Test
	public void testBitMappedJoin() throws Exception {
		FileBytes fileBytes = createFileBytes();
		createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock1 =
			mem.createBitMappedBlock("mapped1", addr(100), addr(0), 16, false);
		MemoryBlock mappedBlock2 =
			mem.createBitMappedBlock("mapped2", addr(116), addr(2), 16, false);
		try {
			mem.join(mappedBlock1, mappedBlock2);
			fail("Expected exception when joining bit mapped blocks");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testBitMappedSplit() throws Exception {
		FileBytes fileBytes = createFileBytes();
		createFileBytesBlock(fileBytes, addr(0), 0, 50);
		MemoryBlock mappedBlock1 =
			mem.createBitMappedBlock("mapped1", addr(100), addr(0), 16, false);
		try {
			mem.split(mappedBlock1, addr(108));
			fail("Expected exception when joining bit mapped blocks");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

//	@Test
//	public void testGetByteSourceSetForFileBytesBlock() throws Exception {
//		FileBytes fileBytes = createFileBytes();
//		MemoryBlockDB block = (MemoryBlockDB) createFileBytesBlock(fileBytes, addr(0), 10, 50);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(5), 10);
//
//		// we expect to get a single range ByteSourceSet pointing into the filebytes at offset
//		// 15 (10 because block was created at filebytes:10 and 5 because we start at the 5th byte
//		// in the block)
//
//		assertEquals(1, ranges.getRangeCount());
//		assertEquals(10, ranges.get(0).getSize());
//		assertEquals(5, ranges.get(0).getStart().getOffset());
//		assertEquals(14, ranges.get(0).getEnd().getOffset());
//		assertEquals(fileBytes.getId(), ranges.get(0).getSourceId());
//		assertEquals(15, ranges.get(0).getOffset());
//	}

//	@Test
//	public void testGetByteSourceSetForBufferBlock() throws Exception {
//		MemoryBlockDB block = (MemoryBlockDB) mem.createInitializedBlock("test", addr(0), 30,
//			(byte) 1, TaskMonitor.DUMMY, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(10), 10);
//
//		// We expect to get to ranges because we made the buffer size small (16) so when we
//		// created a 30 size block, it had to make two separate sub blocks each with its own
//		// DBBuffer.  The first range should contain the first 6 bytes of the requested range
//		// and the second buffer should contain the last 4 bytes of request range.
//
//		assertEquals(2, ranges.getRangeCount());  // we have two sublocks so two distinct ranges
//		assertEquals(10, ranges.get(0).getSize() + ranges.get(1).getSize());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(10, range.getStart().getOffset());
//		assertEquals(15, range.getEnd().getOffset());
//		assertEquals(6, range.getSize());
//		assertEquals(10, range.getOffset());
//
//		range = ranges.get(1);
//		assertEquals(16, range.getStart().getOffset());
//		assertEquals(19, range.getEnd().getOffset());
//		assertEquals(4, range.getSize());
//		assertEquals(0, range.getOffset());
//
//	}
//
//	@Test
//	public void testGetByteSourceForUndefinedBlock() throws Exception {
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createUninitializedBlock("test", addr(0), 30, false);
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(10), 10);
//		// undefined blocks have no source bytes
//		assertTrue(ranges.isEmpty());
//
//	}
//
//	@Test
//	public void testGetByteSourceForByteMappedBlock() throws Exception {
//		mem.createInitializedBlock("test1", addr(0), 15, (byte) 1, TaskMonitor.DUMMY, false);
//		mem.createUninitializedBlock("test2", addr(15), 20, false);
//		mem.createInitializedBlock("test3", addr(35), 15, (byte) 1, TaskMonitor.DUMMY, false);
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createByteMappedBlock("mapped", addr(1000), addr(5), 40, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(1005), 30); // 5, 20, 5
//
//		// Uninitialized blocks don't contribute, so we should have 10 address (5 from first and last blocks each).
//		assertEquals(2, ranges.getRangeCount());
//		assertEquals(10, ranges.get(0).getSize() + ranges.get(1).getSize());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(1005), range.getStart());
//		assertEquals(addr(1009), range.getEnd());
//		assertEquals(5, range.getSize());
//		assertEquals(10, range.getOffset());
//
//		range = ranges.get(1);
//		assertEquals(addr(1030), range.getStart());
//		assertEquals(addr(1034), range.getEnd());
//		assertEquals(5, range.getSize());
//		assertEquals(0, range.getOffset());
//	}
//
//	@Test
//	public void testGetByteSourceForByteMappedBlockWithScheme() throws Exception {
//		mem.createInitializedBlock("test1", addr(0), 15, (byte) 1, TaskMonitor.DUMMY, false); // mapped bytes: 5, 6, .. 9, 10, .. 13, (14
//		mem.createUninitializedBlock("test2", addr(15), 20, false); // mapped bytes: 17, 18, 21, 22, 25, 26, 29, 30, 33, 34
//		mem.createInitializedBlock("test3", addr(35), 15, (byte) 1, TaskMonitor.DUMMY, false); // mapped bytes: .. 37, 38, .. 41, 42), .. 45, 46, .. 49, 50 ...
//		MemoryBlockDB block = (MemoryBlockDB) mem.createByteMappedBlock("mapped", addr(1000),
//			addr(5), 40, new ByteMappingScheme(2, 4), false);
//
//		// NOTE: source range includes skipped bytes within mapped range
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(1005), 15);
//// FIXME XXX Expected something different than previous test !!
//		// Uninitialized blocks don't contribute, so we should have 16 address (1 from first and 4 from last block each, plus 4 skipped bytes in last block).
////		assertEquals(2, ranges.getRangeCount());
////		assertEquals(8, ranges.get(0).getSize() + ranges.get(1).getSize());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(1005), range.getStart());
//		assertEquals(addr(1005), range.getEnd());
//		assertEquals(1, range.getSize());
//		assertEquals(14, range.getOffset());
//
//		range = ranges.get(1);
//		assertEquals(addr(1016), range.getStart());
//		assertEquals(addr(1019), range.getEnd());
//		assertEquals(5, range.getSize());
//		assertEquals(0, range.getOffset());
//	}
//
//	@Test
//	public void testGetByteSourceForBitMappedBlock() throws Exception {
//		FileBytes fileBytes = createFileBytes();
//		createFileBytesBlock(fileBytes, addr(0), 0, 50);
//
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createBitMappedBlock("mapped", addr(0x1000), addr(5), 0x14, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(0x1000), 0x14);
//
//		assertEquals(1, ranges.getRangeCount());
//		assertEquals(3, ranges.get(0).getSize());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(0x1000), range.getStart());
//		assertEquals(addr(0x1017), range.getEnd());
//		assertEquals(3, range.getSize());
//		assertEquals(5, range.getOffset());
//	}
//
//	@Test
//	public void testGetByteSourceForBitMappedBlockOffcutStart() throws Exception {
//		FileBytes fileBytes = createFileBytes();
//		createFileBytesBlock(fileBytes, addr(0), 0, 50);
//
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createBitMappedBlock("mapped", addr(0x1000), addr(5), 0x14, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(0x1005), 8);
//
//		assertEquals(1, ranges.getRangeCount());
//		assertEquals(2, ranges.get(0).getSize());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(0x1000), range.getStart());
//		assertEquals(addr(0x100f), range.getEnd());
//		assertEquals(2, range.getSize());
//		assertEquals(5, range.getOffset());
//	}
//
//	@Test
//	public void testGetByteSourceForBitMappedBlockOffcutStartNotAtStart() throws Exception {
//		FileBytes fileBytes = createFileBytes();
//		createFileBytesBlock(fileBytes, addr(0), 0, 50);
//
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createBitMappedBlock("mapped", addr(0x1000), addr(5), 0x44, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(0x1015), 8);
//
//		assertEquals(1, ranges.getRangeCount());
//		assertEquals(2, ranges.get(0).getSize());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(0x1010), range.getStart());
//		assertEquals(addr(0x101f), range.getEnd());
//		assertEquals(2, range.getSize());
//		assertEquals(7, range.getOffset());
//	}
//
//	@Test
//	public void testGetByteSourceForBitMappedBlock2() throws Exception {
//		mem.createInitializedBlock("test1", addr(0), 4, (byte) 1, TaskMonitor.DUMMY, false);
//		mem.createUninitializedBlock("test2", addr(0x4), 4, false);
//		mem.createInitializedBlock("test3", addr(0x8), 4, (byte) 1, TaskMonitor.DUMMY, false);
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createBitMappedBlock("mapped", addr(0x1000), addr(2), 0x40, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(0x1008), 0x30);
//
//		assertEquals(2, ranges.getRangeCount());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(0x1008), range.getStart());
//		assertEquals(addr(0x100f), range.getEnd());
//		assertEquals(1, range.getSize());
//		assertEquals(3, range.getOffset());
//
//		range = ranges.get(1);
//		assertEquals(addr(0x1030), range.getStart());
//		assertEquals(addr(0x1037), range.getEnd());
//		assertEquals(1, range.getSize());
//		assertEquals(0, range.getOffset());
//	}
//
//	@Test
//	public void testGetByteSourceForBitMappedBlock2Offcut() throws Exception {
//		mem.createInitializedBlock("test1", addr(0), 4, (byte) 1, TaskMonitor.DUMMY, false);
//		mem.createUninitializedBlock("test2", addr(0x4), 4, false);
//		mem.createInitializedBlock("test3", addr(0x8), 4, (byte) 1, TaskMonitor.DUMMY, false);
//		MemoryBlockDB block =
//			(MemoryBlockDB) mem.createBitMappedBlock("mapped", addr(0x1000), addr(2), 0x40, false);
//
//		ByteSourceRangeList ranges = block.getByteSourceRangeList(addr(0x1006), 0x34);
//
//		assertEquals(2, ranges.getRangeCount());
//
//		ByteSourceRange range = ranges.get(0);
//		assertEquals(addr(0x1000), range.getStart());
//		assertEquals(addr(0x100f), range.getEnd());
//		assertEquals(2, range.getSize());
//		assertEquals(2, range.getOffset());
//
//		range = ranges.get(1);
//		assertEquals(addr(0x1030), range.getStart());
//		assertEquals(addr(0x103f), range.getEnd());
//		assertEquals(2, range.getSize());
//		assertEquals(0, range.getOffset());
//	}

	@Test
	public void testAddressSourceInfoForFileBytesBlock() throws Exception {
		FileBytes fileBytes = createFileBytes();
		mem.createInitializedBlock("block", addr(100), fileBytes, 10, 50, false);

		AddressSourceInfo info = mem.getAddressSourceInfo(addr(100));
		assertEquals(addr(100), info.getAddress());
		assertEquals("test", info.getFileName());
		assertEquals(10, info.getFileOffset());
		assertEquals(10, info.getOriginalValue());

		info = mem.getAddressSourceInfo(addr(110));
		assertEquals(addr(110), info.getAddress());
		assertEquals("test", info.getFileName());
		assertEquals(20, info.getFileOffset());
		assertEquals(20, info.getOriginalValue());
	}

	@Test
	public void testAddressSourceInfoForBufferBlock() throws Exception {
		mem.createInitializedBlock("test", addr(0), 10, (byte) 1, TaskMonitor.DUMMY, false);

		AddressSourceInfo info = mem.getAddressSourceInfo(addr(0));
		assertEquals(addr(0), info.getAddress());
		assertNull(info.getFileName());
		assertEquals(-1, info.getFileOffset());
		assertEquals(0, info.getOriginalValue());

	}

	@Test
	public void testAddressSourceInfoForUnitialized() throws Exception {
		mem.createUninitializedBlock("test", addr(0), 10, false);

		AddressSourceInfo info = mem.getAddressSourceInfo(addr(0));
		assertEquals(addr(0), info.getAddress());
		assertNull(info.getFileName());
		assertEquals(-1, info.getFileOffset());
		assertEquals(0, info.getOriginalValue());

	}

	@Test
	public void testAddressSourceInfoForMappedBlock() throws Exception {
		FileBytes fileBytes = createFileBytes();
		mem.createInitializedBlock("block", addr(0), fileBytes, 10, 50, false);
		mem.createByteMappedBlock("mapped", addr(1000), addr(0), 20, false);

		AddressSourceInfo info = mem.getAddressSourceInfo(addr(1000));
		assertEquals(addr(1000), info.getAddress());
		assertEquals("test", info.getFileName());
		assertEquals(10, info.getFileOffset());
		assertEquals(10, info.getOriginalValue());

	}

	private MemoryBlock createFileBytesBlock(FileBytes fileBytes, Address addr, int offset,
			int length) throws Exception {
		return mem.createInitializedBlock("test" + addr.toString(), addr, fileBytes, offset, length,
			false);
	}

	private FileBytes createFileBytes() throws Exception {
		byte[] bytes = new byte[256];
		for (int i = 0; i < 256; i++) {
			bytes[i] = (byte) i;
		}
		FileBytes fileBytes =
			mem.createFileBytes("test", 0, 100, new ByteArrayInputStream(bytes), TaskMonitor.DUMMY);
		return fileBytes;
	}

	private Address addr(long offset) {
		return addressFactory.getDefaultAddressSpace().getAddress(offset);
	}

	private Language getLanguage(String languageName) throws Exception {

		ResourceFile ldefFile = Application.getModuleDataFile("Toy", "languages/toy.ldefs");
		if (ldefFile != null) {
			LanguageService languageService = DefaultLanguageService.getLanguageService(ldefFile);
			Language language = languageService.getLanguage(new LanguageID(languageName));
			return language;
		}
		throw new LanguageNotFoundException("Unsupported test language: " + languageName);
	}
}
