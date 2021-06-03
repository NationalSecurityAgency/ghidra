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

import java.util.Iterator;

import org.junit.*;

import ghidra.app.plugin.core.memory.UninitializedBlockCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the memory implementation for a database.
 *
 *
 */
public class MemoryManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private Memory mem;
	private int transactionID;
	private ToyProgramBuilder builder;

	/**
	 * Constructor for MemoryManagerTest.
	 * @param arg0
	 */
	public MemoryManagerTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		builder = new ToyProgramBuilder(testName.getMethodName(), false, this);
		program = builder.getProgram();
		space = program.getAddressFactory().getDefaultAddressSpace();
		mem = program.getMemory();
		transactionID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testBigEndian() {
		assertTrue(!mem.isBigEndian());
	}

	@Test
	public void testCreateInitializedBlock() throws Exception {
		MemoryBlock block = createBlock("Test", addr(0), 100);
		assertNotNull(block);
		assertEquals("Test", block.getName());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isInitialized());
		assertEquals(100, block.getSize());

		try {
			createBlock("A", addr(0), 100);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		catch (AddressOverflowException e) {
			Assert.fail();
		}

		try {
			createBlock("A", addr(99), 100);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		catch (AddressOverflowException e) {
			Assert.fail();
		}
		block = createBlock("A", addr(1000), 10);
		assertNotNull(block);
		assertEquals("A", block.getName());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isInitialized());
		assertEquals(10, block.getSize());
		try {
			createBlock("B", addr(990), 11);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		try {
			createBlock("C", addr(990), 100);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		createBlock("D", addr(100), 900);
	}

	@Test
	public void testCreateBlock() throws Exception {

		MemoryBlock block = createBlock("Test", addr(0), 100);
		assertTrue(block.isInitialized());

		// need to create a buffer with junk and free it
		// to verify that clean buffer is later produced
		MemoryBlock block2 = createBlock("Test2", addr(0x1000), 0x1000);
		assertTrue(block.isInitialized());
		for (int i = 0; i < 0x1000; i++) {
			block2.putByte(addr(0x1000 + i), (byte) 0xff);
		}
		mem.removeBlock(block2, TaskMonitor.DUMMY);

		// Verify buffer
		block2 = mem.createBlock(block, "Test2", addr(0x1000), 0x1000);
		assertEquals(0x1000, block2.getSize());
		for (int i = 0; i < 0x1000; i++) {
			assertEquals(0, block2.getByte(addr(0x1000 + i)));
		}
	}

	@Test
	public void testSetGetFromBlock() throws Exception {
		MemoryBlock block = createBlock("Test", addr(0), 100);
		block.putByte(addr(0), (byte) 'a');
		assertEquals((byte) 'a', block.getByte(addr(0)));

		block.putBytes(addr(50), new byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5 });
		byte[] bb = new byte[5];
		block.getBytes(addr(50), bb);
		for (int i = 0; i < bb.length; i++) {
			assertEquals(i + 1, bb[i]);
		}

		bb = new byte[5];
		block.getBytes(addr(52), bb, 2, 3);
		assertEquals((byte) 3, bb[2]);
		assertEquals((byte) 4, bb[3]);
		assertEquals((byte) 5, bb[4]);
	}

	@Test
	public void testGetAtBadAddress() throws Exception {
		createBlock("Test", addr(100), 100);
		try {
			mem.getByte(addr(0));
			Assert.fail("Should not have gotten byte!");
		}
		catch (MemoryAccessException e) {
		}
	}

	@Test
	public void testCreateUninitializedBlock() throws Exception {
		MemoryBlock block = createBlock("Test", addr(0), 100);
		try {
			mem.createUninitializedBlock("A", addr(99), 10, false);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		catch (AddressOverflowException e) {
			Assert.fail();
		}

		block = mem.createUninitializedBlock("A", addr(1000), 10, false);
		assertNotNull(block);
		assertEquals("A", block.getName());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(!block.isInitialized());
		assertEquals(10, block.getSize());
		try {
			mem.createUninitializedBlock("B", addr(990), 11, false);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		try {
			mem.createUninitializedBlock("C", addr(990), 100, false);
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		block = mem.createUninitializedBlock("D", addr(100), 900, false);
		assertNotNull(block);
		assertEquals("D", block.getName());
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(!block.isInitialized());
		assertEquals(900, block.getSize());
	}

	@Test
	public void testCreateBitBlock() throws Exception {
		createBlock("Test", addr(0), 100);
		createBlock("Test", addr(500), 100);
		MemoryBlock bitBlock = mem.createBitMappedBlock("BitBlock", addr(600), addr(30), 20, false);
		MemoryBlock block = mem.getBlock(addr(610));
		assertNotNull(block);
		assertEquals(bitBlock, block);
	}

	@Test
	public void testBlockChanges() throws Exception {
		MemoryBlock block1 = createBlock("Test1", addr(0), 100);
		MemoryBlock block2 = createBlock("Test2", addr(500), 100);

		block1.setComment("Hello");
		assertEquals("Hello", block1.getComment());
		assertEquals(block1, mem.getBlock(addr(5)));

		block1.setVolatile(false);
		assertTrue(!block1.isVolatile());

		block1.setVolatile(true);
		assertTrue(block1.isVolatile());

		block1.setExecute(false);
		assertTrue(!block1.isExecute());

		block1.setExecute(true);
		assertTrue(block1.isExecute());

		block1.setRead(false);
		assertTrue(!block1.isRead());

		block1.setRead(true);
		assertTrue(block1.isRead());

		block1.setWrite(false);
		assertTrue(!block1.isWrite());

		block1.setWrite(true);
		assertTrue(block1.isWrite());

		block2.setSourceName("Test");
		assertEquals("Test", block2.getSourceName());
	}

	@Test
	public void testRemoveBlock() throws Exception {
		MemoryBlock block = mem.createInitializedBlock("Test", addr(0), 100, (byte) 0, null, false);
		mem.removeBlock(block, new TaskMonitorAdapter());
		assertNull(mem.getBlock(addr(50)));
	}

	@Test
	public void testGetBlockByAddress() throws Exception {
		createBlock("Test", addr(0), 100);
		MemoryBlock mb = mem.getBlock(addr(50));
		assertNotNull(mb);
		assertEquals(addr(0), mb.getStart());

		assertNull(mem.getBlock(addr(101)));
	}

	@Test
	public void testGetBlocks() throws Exception {
		MemoryBlock block1 = createBlock("Test1", addr(0), 100);
		MemoryBlock block2 = createBlock("Test2", addr(500), 100);
		MemoryBlock block3 = mem.createUninitializedBlock("Test3", addr(1500), 200, false);
		MemoryBlock block4 = mem.createUninitializedBlock("Test4", addr(2500), 100, false);
		mem.createBitMappedBlock("BitBlock", addr(3000), addr(550), 2000, false);

		MemoryBlock[] blocks = mem.getBlocks();
		assertEquals(5, blocks.length);
		assertEquals(block1, blocks[0]);
		assertEquals(block2, blocks[1]);
		assertEquals(block3, blocks[2]);
		assertEquals(block4, blocks[3]);

	}

	@Test
	public void testCopyBlock() throws Exception {
		MemoryBlock block1 = createBlock("Test1", addr(100), 100);

		MemoryBlock newBlock = mem.createBlock(block1, "CopiedBlock", addr(90), 10);

		assertEquals(addr(90), newBlock.getStart());
		assertEquals(10, newBlock.getSize());

		mem.join(block1, newBlock);
		MemoryBlock block = mem.getBlock(addr(95));
		assertEquals(newBlock, block);
	}
	
	@Test
	public void testGetBlockByName() throws Exception {
		
		MemoryBlock block1 = createBlock("Test1", addr(100), 100);
		MemoryBlock block2 = createBlock("Test2", addr(300), 100);
		
		MemoryBlock block = mem.getBlock("Test1");
		assertEquals("Test1", block.getName());
		assertEquals("get same block", block, block1);

		mem.split(block, addr(150));
		block = mem.getBlock("Test1");
		assertEquals("Test1",  block.getName());
		assertEquals(50, block.getSize());
		
		// non-existent block
		block = mem.getBlock("NoExist");
		assertNull(block);
		
		program.endTransaction(transactionID, true);
		transactionID = program.startTransaction("Test");	
		
		// now exists
		mem.getBlock("Test1").setName("NoExist");
		// Test1 no longer exists
		assertNull("block deleted", mem.getBlock("Test1"));
		block = mem.getBlock("NoExist");
		assertEquals("NoExist", block.getName());

		mem.removeBlock(block, new TaskMonitorAdapter());
		block = mem.getBlock("NoExist");
		assertNull("block should be deleted", block);
		
		// Test1 still doesn't exist
		block = mem.getBlock("Test1");
		assertNull("block deleted", block);
		
		block = mem.getBlock("Test2");
		assertEquals("Test2", block.getName());
		
		program.endTransaction(transactionID, true);
		
		program.undo();
		
		// Test1 still doesn't exist
		block = mem.getBlock("Test1");
		assertNotNull("Undo, Test1 exists again", block);
		
		transactionID = program.startTransaction("Test");
	}

	@Test
	public void testMemoryMapExecuteSet() throws Exception {
		
		AddressSetView executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty());
		MemoryBlock block1 = createBlock("Test1", addr(100), 100);
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty());
		MemoryBlock block2 = createBlock("Test2", addr(300), 100);
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty());

		MemoryBlock block = mem.getBlock("Test1");
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty());
		
		block.setExecute(false);
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty());

		block.setExecute(true);
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty() != true);
		Address start = block.getStart();
		Address end = block.getEnd();
		assertTrue(executeSet.contains(start,end));

		// non-existent block
		block = mem.getBlock("NoExist");
		assertNull(block);
		
		program.endTransaction(transactionID, true);
		transactionID = program.startTransaction("Test");	
		
		// now exists
		mem.getBlock("Test1").setName("NoExist");
		// Test1 no longer exists
		block = mem.getBlock("NoExist");
		executeSet = mem.getExecuteSet();
		start = block.getStart();
		end = block.getEnd();
		// should be same block
		assertTrue(executeSet.contains(start,end));
		block.setExecute(false);
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.contains(start,end) == false);
		
		block2.setExecute(true);
		Address start2 = block2.getStart();
		Address end2 = block2.getEnd();
		mem.removeBlock(block2, new TaskMonitorAdapter());
		
		program.endTransaction(transactionID, true);
		
		program.undo();
		
		transactionID = program.startTransaction("Test");

		// should be execute set on block2, deleted, then undone
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.contains(start2,end2) == false);
	
		// undid set execute block should now be contained
		block = mem.getBlock("Test1");
		start = block.getStart();
		end = block.getEnd();
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.contains(start,end));
		
		mem.split(block, addr(150));
		block = mem.getBlock("Test1");
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty() != true);
		assertTrue(executeSet.contains(block.getStart(), block.getEnd()));
		
		// remove block that was split, should still be executable memory
		start = block.getStart();
		end = block.getEnd();
		mem.removeBlock(block, new TaskMonitorAdapter());
		executeSet = mem.getExecuteSet();
		assertTrue(executeSet.isEmpty() != true);
		assertTrue(executeSet.contains(start, end) == false);
	}
	
	@Test
	public void testSave() throws Exception {
		MemoryBlock block1 = createBlock("Test1", addr(0), 100);
		MemoryBlock block2 = createBlock("Test2", addr(500), 100);
		MemoryBlock block3 = mem.createUninitializedBlock("Test3", addr(1500), 200, false);
		mem.createUninitializedBlock("Test4", addr(2500), 100, false);
		MemoryBlock block5 = mem.createBitMappedBlock("BitBlock", addr(3000), addr(550), 20, false);
		block1.setComment("Hello!");
		block2.setName("NewTest2");
		block3.setWrite(false);
		block5.setComment("I am a Bit Block");
	}

	@Test
	public void testAddBlockCopy() throws Exception {
		createBlock("Test", addr(0), 100);
		MemoryBlock block = mem.getBlock(addr(50));
		block.putByte(addr(50), (byte) 'a');
		MemoryBlock newBlock =
			mem.createBlock(block, block.getName() + ".copy", addr(500), block.getSize());
		assertNotNull(newBlock);
		assertEquals(block.getName() + ".copy", newBlock.getName());
		assertEquals(addr(500), newBlock.getStart());
		assertEquals(block.isVolatile(), newBlock.isVolatile());
		assertEquals(block.isExecute(), newBlock.isExecute());
		assertEquals(block.isRead(), newBlock.isRead());
		assertEquals(block.isWrite(), newBlock.isWrite());
	}

	@Test
	public void testLiveMemory() throws Exception {

		mem.createInitializedBlock("Test", addr(0), 0x1000, (byte) 0x55, null, false);

		LiveMemoryHandler testHandler = new LiveMemoryHandler() {
			@Override
			public void clearCache() {
			}

			@Override
			public byte getByte(Address addr) throws MemoryAccessException {
				return 0;
			}

			@Override
			public int getBytes(Address addr, byte[] dest, int dIndex, int size)
					throws MemoryAccessException {
				for (int i = 0; i < size; ++i) {
					dest[dIndex + i] = (byte) i;
				}
				return size;
			}

			@Override
			public void putByte(Address addr, byte value) {
			}

			@Override
			public int putBytes(Address address, byte[] source, int sIndex, int size)
					throws MemoryAccessException {
				return 0;
			}

			@Override
			public void addLiveMemoryListener(LiveMemoryListener listener) {
				// TODO Auto-generated method stub

			}

			@Override
			public void removeLiveMemoryListener(LiveMemoryListener listener) {
				// TODO Auto-generated method stub

			}
		};

		assertEquals((byte) 0x55, mem.getByte(addr(0x500)));

		mem.setLiveMemoryHandler(testHandler);

		byte[] bytes = new byte[5];
		mem.getBytes(addr(0x1000), bytes);

		for (int i = 0; i < bytes.length; ++i) {
			assertEquals(i, bytes[i]);
		}

		assertEquals((byte) 0, mem.getByte(addr(0x500)));

		mem.setLiveMemoryHandler(null);

		try {
			mem.getBytes(addr(0x1000), bytes);
			Assert.fail();
		}
		catch (MemoryAccessException e) {
		}

		assertEquals((byte) 0x55, mem.getByte(addr(0x500)));
	}

	@Test
	public void testSplitBlock() throws Exception {
		createBlock("Test", addr(0), 100);
		MemoryBlock mb = mem.getBlock(addr(0));
		mem.split(mb, addr(20));
		mb = mem.getBlock(addr(50));
		assertEquals(addr(20), mb.getStart());
		assertEquals(80, mb.getSize());

		assertEquals(2, mem.getBlocks().length);

		mb = mem.getBlock(addr(0));
		assertEquals("Test", mb.getName());
		assertEquals(20, mb.getSize());
	}

	@Test
	public void testGetByteAfterSplit() throws Exception {
		byte[] b = new byte[100];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) i;
		}
		createBlock("Test", addr(0), 100);
		mem.setBytes(addr(0), b);

		assertEquals(1, mem.getByte(addr(1)));
		assertEquals(20, mem.getByte(addr(20)));

		MemoryBlock mb = mem.getBlock(addr(0));
		mem.split(mb, addr(20));
		assertEquals(20, mem.getByte(addr(20)));
	}

	@Test
	public void testGetByteAfterMove() throws Exception {
		byte[] b = new byte[100];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) i;
		}

		createBlock("Test", addr(0), 100);
		mem.setBytes(addr(0), b);
		assertEquals(1, mem.getByte(addr(1)));
		assertEquals(20, mem.getByte(addr(20)));
		assertEquals(99, mem.getByte(addr(99)));

		MemoryBlock mb = mem.getBlock(addr(0));

		mem.moveBlock(mb, addr(300), new TaskMonitorAdapter());
		assertEquals(1, mem.getByte(addr(301)));
		assertEquals(20, mem.getByte(addr(320)));
		assertEquals(99, mem.getByte(addr(399)));
	}

	@Test
	public void testGetByteAfterJoin() throws Exception {
		createBlock("Test", addr(0), 100);
		byte[] b = new byte[100];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) i;
		}
		mem.setBytes(addr(0), b);

		assertEquals(1, mem.getByte(addr(1)));
		assertEquals(20, mem.getByte(addr(20)));
		assertEquals(99, mem.getByte(addr(99)));

		MemoryBlock mb = mem.getBlock(addr(0));

		MemoryBlock block2 = createBlock("Test2", addr(100), 50);

		b = new byte[50];
		for (int i = 0; i < b.length; i++) {
			b[i] = (byte) (100 + i);
		}
		mem.setBytes(addr(100), b);
		assertEquals(100, mem.getByte(addr(100)));
		assertEquals(120, mem.getByte(addr(120)));

		mem.join(mb, block2);
		assertEquals(100, mem.getByte(addr(100)));
		assertEquals(120, mem.getByte(addr(120)));
	}

	@Test
	public void testMoveBitBlock() throws Exception {
		createBlock("Test", addr(0), 100);

		MemoryBlock bitBlock = mem.createBitMappedBlock("BitBlock", addr(200), addr(50), 20, false);
		assertEquals(0, bitBlock.getByte(addr(200)));
		bitBlock.putByte(addr(200), (byte) 5);
		assertEquals(1, bitBlock.getByte(addr(200)));
	}

	@Test
	public void testConvertBlock() throws Exception {
		MemoryBlock block = mem.createUninitializedBlock("Uninitialized", addr(1000), 100, false);
		block = mem.convertToInitialized(block, (byte) 'a');
		assertNotNull(block);
		assertEquals((byte) 'a', block.getByte(addr(1000)));
	}

	@Test
	public void testUnconvertBlock() throws Exception {
		MemoryBlock block = mem.createInitializedBlock("Initialized", addr(1000), 100, (byte) 5,
			TaskMonitor.DUMMY, false);
		program.getSymbolTable().createLabel(addr(1001), "BOB", SourceType.USER_DEFINED);
		assertNotNull(program.getSymbolTable().getPrimarySymbol(addr(1001)));

		Data data = program.getListing().getDataAt(addr(1001));
		assertEquals("undefined", data.getDataType().getName());

		program.getListing().createData(addr(1001), new ByteDataType());
		data = program.getListing().getDataAt(addr(1001));
		assertEquals("byte", data.getDataType().getName());

		UninitializedBlockCmd cmd = new UninitializedBlockCmd(program, block);
		cmd.applyTo(program);

		assertNotNull(block);
		assertTrue("Expected block to be uninitialized", !block.isInitialized());
		try {
			block.getByte(addr(1000));
			Assert.fail("expected memory access exception");
		}
		catch (MemoryAccessException e) {
			// expected
		}
		assertNotNull(program.getSymbolTable().getPrimarySymbol(addr(1001)));
		data = program.getListing().getDataAt(addr(1001));
		assertEquals("undefined", data.getDataType().getName());
	}

	@Test
	public void testJoinBlocks() throws Exception {
		createBlock("Test", addr(0), 100);
		MemoryBlock mb = mem.getBlock(addr(0));
		MemoryBlock nmb = mem.createUninitializedBlock("A", addr(mb.getSize()), 10, false);
		// try to join different block types
		try {
			mem.join(mb, nmb);
			Assert.fail("Join should have failed!!!");
		}
		catch (MemoryBlockException e) {
			// expected
		}
		mem.removeBlock(nmb, new TaskMonitorAdapter());

		MemoryBlock mb2 = new MemoryBlockStub();
		// try to join mb2 that is not in memory
		try {
			mem.join(mb, mb2);
			Assert.fail("Join should have failed! -- not in memory!");
		}
		catch (Exception e) {
			// expected
		}

		mb2 = createBlock("Block2", addr(0x100), 20);
		// try to join non-contiguous blocks
		try {
			mem.join(mb, mb2);
			Assert.fail("Join should have failed!");
		}
		catch (MemoryBlockException e) {
		}

		// this one should succeed
		MemoryBlock bl = createBlock("joinee", addr(mb.getSize()), 20);
		assertEquals(3, mem.getBlocks().length);
		mem.join(mb, bl);
		bl = mem.getBlock(addr(119));
		assertNotNull(bl);
		assertEquals("Test", bl.getName());
		assertEquals(120, bl.getSize());
		assertEquals(2, mem.getBlocks().length);
	}

	@Test
	public void testMoveBlock() throws Exception {
		createBlock("Test", addr(0), 100);
		mem.setByte(addr(5), (byte) 5);
		MemoryBlock mb = mem.getBlock(addr(0));
		mem.moveBlock(mb, addr(500), new TaskMonitorAdapter());
		assertEquals(5, mem.getByte(addr(505)));

		mb = mem.getBlock(addr(500));
		assertNotNull(mb);
		assertEquals(addr(500), mb.getStart());
		mem.createUninitializedBlock("A", addr(1000), 10, false);
		try {
			mb = mem.getBlock(addr(500));
			mem.moveBlock(mb, addr(1001), new TaskMonitorAdapter());
			Assert.fail();
		}
		catch (MemoryConflictException e) {
		}
		MemoryBlock[] blocks = mem.getBlocks();
		assertEquals(2, blocks.length);
	}

	@Test
	public void testMoveBlockWithStuff() throws Exception {
		MemoryBlock block1 = createBlock("Test", addr(0), 0x636);
		Listing listing = program.getListing();
		// create data
		listing.createData(addr(0x20), new ByteDataType(), 1);
		ArrayDataType array = new ArrayDataType(new ByteDataType(), 0x10, 1);
		listing.createData(addr(0x21), array, 1);

		// create functions
		AddressSet set = new AddressSet();
		set.addRange(addr(0x40), addr(0x50));
		set.addRange(addr(0x100), addr(0x110));
		listing.createFunction("FunctionOne", addr(0x40), set, SourceType.USER_DEFINED);

		// create modules

		ProgramModule root = listing.createRootModule("Test");
		ProgramFragment frag = root.createFragment("fragTest");
		frag.move(addr(0x40), addr(0x50));

		ProgramFragment frag2 = root.createFragment("fragTest2");
		frag2.move(addr(0x100), addr(0x105));

		// move block to 0x2000
		mem.moveBlock(block1, addr(0x2000), new TaskMonitorAdapter());

		Data data = listing.getDataAt(addr(0x2020));
		assertNotNull(data);
		DataType dt = data.getDataType();
		assertNotNull(dt);
		assertTrue(dt.isEquivalent(new ByteDataType()));
		data = listing.getDataAt(addr(0x2021));
		assertNotNull(data);
		dt = data.getDataType();
		assertNotNull(dt);
		assertTrue(dt.isEquivalent(array));

		frag = listing.getFragment("Test", addr(0x2040));
		assertNotNull(frag);

		assertEquals("fragTest", frag.getName());

		frag2 = listing.getFragment("Test", addr(0x2102));
		assertNotNull(frag2);
		assertEquals("fragTest2", frag2.getName());

		Function f = listing.getFunctionAt(addr(0x2040));
		assertNotNull(f);

		AddressSetView view = f.getBody();
		assertEquals(2, view.getNumAddressRanges());
		Iterator<AddressRange> it = view.iterator();
		AddressRange r1 = it.next();
		AddressRange r2 = it.next();
		assertEquals(addr(0x2040), r1.getMinAddress());
		assertEquals(addr(0x2050), r1.getMaxAddress());
		assertEquals(addr(0x2100), r2.getMinAddress());
		assertEquals(addr(0x2110), r2.getMaxAddress());
	}

	@Test
	public void testMoveBlockWithReferences() throws Exception {

		builder.createMemory("Test", "0", 1000);
		builder.setBytes("0x20", "12 34 56 78");
		builder.applyDataType("0x20", new PointerDataType());
		builder.addBytesBranch("0", "0x40");
		builder.disassemble("0", 2);

		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();

		Reference[] refs = refMgr.getReferencesFrom(addr(0x20));
		assertEquals(1, refs.length);
		Address toAddr20 = refs[0].getToAddress();

		assertNotNull(listing.getCodeUnitAt(addr(0)));
		System.out.println("cu = " + listing.getCodeUnitAt(addr(0)));
		refs = refMgr.getReferencesFrom(addr(0));
		assertEquals(1, refs.length);
		Address toAddr0 = refs[0].getToAddress();

		// move block to 0x2000
		Memory memory = program.getMemory();
		MemoryBlock block1 = memory.getBlock(addr(0));
		memory.moveBlock(block1, addr(0x2000), new TaskMonitorAdapter());
		refs = refMgr.getReferencesFrom(addr(0x2020));
		assertEquals(1, refs.length);
		assertEquals(toAddr20, refs[0].getToAddress());
		refs = refMgr.getReferencesFrom(addr(0x2000));
		assertEquals(1, refs.length);
		assertEquals(toAddr0.add(0x2000), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr(0x20));
		assertEquals(0, refs.length);
		refs = refMgr.getReferencesFrom(addr(0x0));
		assertEquals(0, refs.length);

	}

	@Test
	public void testSet() throws Exception {
		createBlock("Test", addr(0), 100);
		mem.setLong(addr(0), 0x0001020304050607L, true);
		assertEquals(0x0001020304050607L, mem.getLong(addr(0), true));
		mem.setInt(addr(4), 0x01020304, true);
		assertEquals(0x0001020301020304L, mem.getLong(addr(0), true));

		MemoryBlock mb3 = createBlock("Block3", addr(100), 10);

		//no matter what the state of these attributes, the
		//bytes can be updated...
		mb3.setRead(true);
		mb3.setWrite(true);
		mb3.setExecute(true);

		mem.setShort(addr(99), (short) 0x0304);
		assertEquals(0x0304, mem.getShort(addr(99)));

		// this should fail since there is not any data
		// at address 0x6e
		try {
			mem.setInt(addr(0x6e), 0);
			Assert.fail();
		}
		catch (MemoryAccessException aoobe) {
		}

		mb3.setWrite(false);

		mem.setInt(addr(100), 0x107);
		assertEquals(0x107, mem.getInt(addr(100)));

		mb3.putByte(addr(100), (byte) 10);
		assertEquals(10, mem.getByte(addr(100)));
	}

	@Test
	public void testGetShort() throws Exception {
		setupGetTests();

		byte[] dest = new byte[8];
		int nbytes = mem.getBytes(addr(0x100), dest);
		assertEquals(8, nbytes);
		assertEquals(4, dest[4]);

		// test get short
		short s = mem.getShort(addr(0x100), true);
		assertEquals(1, s);

		s = mem.getShort(addr(0x100));
		assertEquals(0x100, s);

		s = mem.getShort(addr(0x101), true);
		assertEquals(0x102, s);

		s = mem.getShort(addr(0x101));
		assertEquals(0x0201, s);

		s = mem.getShort(addr(0x102), true);
		assertEquals(0x203, s);

		s = mem.getShort(addr(0x102));
		assertEquals(0x302, s);
	}

	@Test
	public void testGetInt() throws Exception {
		setupGetTests();
		// test get int
		int intValue = mem.getInt(addr(0x100));
		assertEquals(0x03020100, intValue);

		intValue = mem.getInt(addr(0x100), true);
		assertEquals(0x00010203, intValue);

		intValue = mem.getInt(addr(0x104));
		assertEquals(0x07060504, intValue);

		intValue = mem.getInt(addr(0x104), true);
		assertEquals(0x04050607, intValue);

		// test boundary crossing
		intValue = mem.getInt(addr(0x103), true);
		assertEquals(0x03040506, intValue);

		// test getting too big of a value at the end of memory
		try {
			intValue = mem.getInt(addr(0x106));
			Assert.fail("Should not have gotten int value!");
		}
		catch (MemoryAccessException e) {
		}

	}

	@Test
	public void testGetLong() throws Exception {
		setupGetTests();

		long longValue = mem.getLong(addr(0x100), true);
		assertEquals(0x0001020304050607L, longValue);

		longValue = mem.getLong(addr(0x100));
		assertEquals(0x0706050403020100L, longValue);

		// test getting too big of a value at the end of memory
		try {
			longValue = mem.getLong(addr(0x101));
			Assert.fail("Should not have gotten long value!");
		}
		catch (MemoryAccessException e) {
		}

	}

	@Test
	public void testFindBytes8051() throws Exception {

		// switch program
		program.endTransaction(transactionID, true);
		program.release(this);

		byte[] b = new byte[] { (byte) 0xc0, (byte) 0xd0, (byte) 0xc0, (byte) 0xe0 };
		byte[] masks = new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff };

		program = createDefaultProgram("8051", ProgramBuilder._8051, this);
		space = program.getAddressFactory().getAddressSpace("CODE");
		mem = program.getMemory();
		transactionID = program.startTransaction("Test");

		createBlock("Code", addr(0), 0x1000);
		mem.setBytes(addr(0x693), b);
		mem.setBytes(addr(0x84d), b);

		Address addr = mem.findBytes(mem.getMinAddress(), b, masks, true, TaskMonitor.DUMMY);
		assertNotNull(addr);
		assertEquals(addr(0x693), addr);

		addr = addr.add(b.length);

		addr = mem.findBytes(addr, b, masks, true, TaskMonitor.DUMMY);
		assertNotNull(addr);
		assertEquals(addr(0x84d), addr);
	}

	@Test
	public void testCreateOverlayBlock() throws Exception {
		MemoryBlock block = mem.createInitializedBlock(".overlay", addr(0), 0x1000, (byte) 0xa,
			TaskMonitor.DUMMY, true);
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isOverlay());
	}

	@Test
	public void testCreateBitMappedBlock() throws Exception {
		mem.createInitializedBlock("mem", addr(0), 0x1000, (byte) 0xa, TaskMonitor.DUMMY, false);
		MemoryBlock bitBlock =
			mem.createBitMappedBlock("bit", addr(0x2000), addr(0xf00), 0x1000, false);

		assertEquals(MemoryBlockType.BIT_MAPPED, bitBlock.getType());

		MemoryBlockSourceInfo info = bitBlock.getSourceInfos().get(0);
		assertEquals(new AddressRangeImpl(addr(0xf00), addr(0x10ff)), info.getMappedRange().get());
		AddressSet expectedInitializedSet = new AddressSet();
		expectedInitializedSet.add(addr(0), addr(0xfff));
		expectedInitializedSet.add(addr(0x2000), addr(0x27ff));
		assertEquals(expectedInitializedSet, mem.getAllInitializedAddressSet());

	}

	@Test
	public void testCreateByteMappedBlock() throws Exception {
		mem.createInitializedBlock("mem", addr(0), 0x1000, (byte) 0xa, TaskMonitor.DUMMY, false);
		MemoryBlock byteBlock =
			mem.createByteMappedBlock("byte", addr(0x2000), addr(0xf00), 0x200, false);

		assertEquals(MemoryBlockType.BYTE_MAPPED, byteBlock.getType());

		MemoryBlockSourceInfo info = byteBlock.getSourceInfos().get(0);
		assertEquals(new AddressRangeImpl(addr(0xf00), addr(0x10ff)), info.getMappedRange().get());
		AddressSet expectedInitializedSet = new AddressSet();
		expectedInitializedSet.add(addr(0), addr(0xfff));
		expectedInitializedSet.add(addr(0x2000), addr(0x20ff));
		assertEquals(expectedInitializedSet, mem.getAllInitializedAddressSet());
	}

	@Test
	public void testCreateRemoveCreateOverlayBlock() throws Exception {
		MemoryBlock block = mem.createInitializedBlock(".overlay", addr(0), 0x1000, (byte) 0xa,
			TaskMonitor.DUMMY, true);
		assertEquals(MemoryBlockType.DEFAULT, block.getType());
		assertTrue(block.isOverlay());
		mem.removeBlock(block, TaskMonitor.DUMMY);
		block =
			mem.createInitializedBlock("ov2", addr(0), 0x2000, (byte) 0xa, TaskMonitor.DUMMY, true);
		assertEquals("ov2", block.getStart().getAddressSpace().getName());
		assertEquals("ov2", block.getEnd().getAddressSpace().getName());
	}

	@Test
	public void testJoinOverlayBlocks() throws Exception {
		MemoryBlock blockOne = mem.createInitializedBlock(".overlay", addr(0), 0x1000, (byte) 0xa,
			TaskMonitor.DUMMY, true);

		MemoryBlock blockTwo = mem.createInitializedBlock(".overlay2", addr(0x1000), 0x100,
			(byte) 0xa, TaskMonitor.DUMMY, true);

		try {
			mem.join(blockOne, blockTwo);
			Assert.fail("Join should have caused and Exception!");
		}
		catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testSplitOverlayBlocks() throws Exception {
		MemoryBlock blockOne = mem.createInitializedBlock(".overlay", addr(0), 0x1000, (byte) 0xa,
			TaskMonitor.DUMMY, true);
		try {
			mem.split(blockOne, addr(0x50));
			Assert.fail("Split should have caused and Exception!");
		}
		catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testGetBytesInvalidArgs() throws Exception {

		createBlock("Test", addr(0), 100);

		byte[] b = new byte[10];
		try {
			mem.getBytes(addr(0), b, 9, 50);
			fail("Expected exception");
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// expected
		}

	}

	private void setupGetTests() throws Exception {
		createBlock("Test", addr(0), 100);

		byte[] bytes = new byte[4];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) i;
		}
		MemoryBlock mb2 = createBlock("Block2", addr(0x100), bytes.length);
		mem.setBytes(addr(0x100), bytes);
		assertEquals(0, mem.getByte(addr(0x100)));

		// test across block boundaries
		bytes = new byte[4];
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = (byte) (i + 4);
		}
		MemoryBlock mb3 = createBlock("Block3", addr(0x100 + mb2.getSize()), bytes.length);
		mem.setBytes(mb3.getStart(), bytes);
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private MemoryBlock createBlock(String name, Address start, long size) throws Exception {
		return createBlock(name, start, size, 0);
	}

	private MemoryBlock createBlock(String name, Address start, long size, int initialValue)
			throws Exception {
		return mem.createInitializedBlock(name, start, size, (byte) initialValue, TaskMonitor.DUMMY,
			false);
	}

}
