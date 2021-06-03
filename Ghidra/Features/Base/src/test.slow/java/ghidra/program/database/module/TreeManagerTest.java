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
package ghidra.program.database.module;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the tree manager.
 * 
 * 
 */
public class TreeManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private TreeManager treeManager;
	private ProgramDB program;
	private AddressSpace space;
	private int transactionID;

	/** 
	 * Constructor for TestTreeManager.
	 * @param arg0
	 */
	public TreeManagerTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
    @Before
    public void setUp() throws Exception {
		TestEnv env = new TestEnv();
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		env.dispose();
		space = program.getAddressFactory().getDefaultAddressSpace();
		treeManager = program.getTreeManager();
		transactionID = program.startTransaction("Test");
		treeManager.createRootModule("Default");
		addBlock("block1", 0, 100);
		addBlock("block2", 0x1000, 100);
	}

	/*
	 * @see TestCase#tearDown()
	 */
    @After
    public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

@Test
    public void testCreateRootModule() throws DuplicateNameException {
		ProgramModule root = treeManager.createRootModule("Test-One");
		assertNotNull(root);

		// now get the module again
		ProgramModule rm = treeManager.getRootModule("Test-One");

		assertEquals(root, rm);

		root = treeManager.createRootModule("Test-Two");
		assertEquals(root, treeManager.getRootModule("Test-Two"));
	}

@Test
    public void testCreateModuleWithDuplicateBlockNames() throws Exception {
		addBlock("block2", 0x2000, 100);

		ProgramModule root = treeManager.createRootModule("MyRoot");
		assertNotNull(root);

		Group[] children = root.getChildren();
		assertEquals(2, children.length);
		assertTrue(children[1] instanceof ProgramFragment);
		ProgramFragment frag = (ProgramFragment) children[1];
		assertEquals(2, frag.getNumAddressRanges());
		Iterator<AddressRange> it = frag.iterator();
		assertEquals(new AddressRangeImpl(getAddr(0x1000), getAddr(0x1063)), it.next());
		assertEquals(new AddressRangeImpl(getAddr(0x2000), getAddr(0x2063)), it.next());
	}

@Test
    public void testCreateDuplicateRootModule() {
		try {
			treeManager.createRootModule("Default");
			Assert.fail("Should have gotten DuplicateNameException!");
		}
		catch (DuplicateNameException e) {
		}
	}

@Test
    public void testRemoveRootModule() throws Exception {

		ProgramModule root = treeManager.createRootModule("Test-One");
		assertNotNull(root);

		String[] names = treeManager.getTreeNames();
		for (String name : names) {
			treeManager.removeTree(name);
		}
		assertNull(treeManager.getRootModule("Test-One"));
		assertEquals(0, treeManager.getTreeNames().length);
	}

@Test
    public void testRename() throws Exception {
		treeManager.createRootModule("Test-One");

		treeManager.renameTree("Test-One", "MyTest");
		assertNotNull(treeManager.getRootModule("MyTest"));
		assertNull(treeManager.getRootModule("Test-One"));
	}

@Test
    public void testRenameDuplicate() {
		try {
			treeManager.createRootModule("Test-One");
			treeManager.renameTree("Test-One", "Default");

			Assert.fail("Should have gotten DuplicateNameException!");
		}
		catch (DuplicateNameException e) {
		}
	}

@Test
    public void testGetTreeNames() throws Exception {
		treeManager.createRootModule("Test-One");
		treeManager.createRootModule("Test-Two");
		treeManager.createRootModule("Test-Three");
		treeManager.createRootModule("Test-Four");
		String[] names = treeManager.getTreeNames();
		//we always get a tree when we construct a ProgramDB,
		//plus we created one in setUp()...
		assertEquals(6, names.length);
		assertEquals("Default", names[1]);
	}

@Test
    public void testGetFragmentByName() throws Exception {
		ProgramModule root = treeManager.getRootModule("Default");
		ProgramFragment frag = root.createFragment("Fragment-1");
		ProgramFragment f = treeManager.getFragment("Default", "Fragment-1");
		assertEquals(frag, f);
	}

@Test
    public void testGetFragmentByAddress() {
		ProgramFragment frag = treeManager.getFragment("Default", getAddr(0x10));
		assertNotNull(frag);
		assertEquals("block1", frag.getName());
	}

@Test
    public void testGetModule() throws Exception {
		ProgramModule root = treeManager.getRootModule("Default");
		ProgramModule module = root.createModule("Module-A");
		ProgramModule m = treeManager.getModule("Default", "Module-A");
		assertEquals(module, m);
	}

@Test
    public void testAddBlock() throws Exception {

		ProgramModule root = treeManager.createRootModule("Test-One");
		ProgramModule r2 = treeManager.createRootModule("Test-Two");

		int r1FragCount = root.getChildren().length;
		int r2FragCount = r2.getChildren().length;

		assertEquals(r1FragCount, r2FragCount);
		assertEquals(2, r1FragCount);

		addBlock("TestBlock", 0x5000, 100);

		// make sure new fragment was created in all trees
		ProgramModule r1 = treeManager.getRootModule("Default");
		r2 = treeManager.getRootModule("Test-One");
		ProgramModule r3 = treeManager.getRootModule("Test-Two");

		int r1Count = r1.getChildren().length;
		int r2Count = r2.getChildren().length;
		int r3Count = r3.getChildren().length;

		assertEquals(r1Count, r2Count);
		assertEquals(r2Count, r3Count);
		assertEquals(3, r1Count);
	}

@Test
    public void testRemoveBlock() throws Exception {
		ProgramModule root = treeManager.createRootModule("Test-One");
		ProgramModule r2 = treeManager.createRootModule("Test-Two");

		addBlock("TestBlock", 0x5000, 100);
		MemoryBlock b2 = addBlock("TestTwoBlock", 0x6000, 200);
		addBlock("TestThreeBlock", 0x6500, 100);

		int r1FragCount = root.getChildren().length;
		int r2FragCount = r2.getChildren().length;
		assertEquals(r1FragCount, r2FragCount);
		assertEquals(5, r1FragCount);
		Address startAddr = b2.getStart();
		Address endAddr = b2.getEnd();
		treeManager.deleteAddressRange(startAddr, endAddr, TaskMonitorAdapter.DUMMY_MONITOR);
		r1FragCount = root.getChildren().length;
		r2FragCount = r2.getChildren().length;
		assertEquals(r1FragCount, r2FragCount);
		assertEquals(4, r1FragCount);
	}

@Test
    public void testMoveBlock() throws Exception {
		ProgramModule root = treeManager.createRootModule("Test-One");
		ProgramModule r2 = treeManager.createRootModule("Test-Two");

		addBlock("TestBlock", 0x5000, 100);
		MemoryBlock b2 = addBlock("TestTwoBlock", 0x6000, 200);
		addBlock("TestThreeBlock", 0x6500, 100);
		ProgramFragment fragB2 = treeManager.getFragment("Test-One", getAddr(0x6050));
		assertEquals(getAddr(0x6000), fragB2.getMinAddress());

		int r1FragCount = root.getChildren().length;
		int r2FragCount = r2.getChildren().length;
		assertEquals(r1FragCount, r2FragCount);
		assertEquals(5, r1FragCount);

		// move b2 to 0x2000
		treeManager.moveAddressRange(b2.getStart(), getAddr(0x2000), b2.getSize(),
			TaskMonitorAdapter.DUMMY_MONITOR);

		Listing listing = program.getListing();
		root = listing.getRootModule("Test-One");
		r2 = listing.getRootModule("Test-Two");

		r1FragCount = root.getChildren().length;
		r2FragCount = r2.getChildren().length;
		assertEquals(r1FragCount, r2FragCount);
		assertEquals(5, r1FragCount);

		ProgramFragment f = treeManager.getFragment("Test-One", getAddr(0x2020));
		assertNotNull(f);
		assertEquals(getAddr(0x2000), f.getMinAddress());

		f = treeManager.getFragment("Test-Two", getAddr(0x2020));
		assertNotNull(f);

		f = treeManager.getFragment("Test-One", getAddr(0x6000));
		assertNull(f);

		f = treeManager.getFragment("Test-Two", getAddr(0x6000));
		assertNull(f);
	}

@Test
    public void testMoveBlockOverlap() throws Exception {
		treeManager.createRootModule("Test-One");

		MemoryBlock b1 = addBlock("TestBlock", 0x5000, 0x100);
		addBlock("TestTwoBlock", 0x6000, 0x200);
		addBlock("TestThreeBlock", 0x6500, 0x100);

		ProgramFragment fragB1 = treeManager.getFragment("Test-One", getAddr(0x5000));
		assertEquals(getAddr(0x5000), fragB1.getMinAddress());
		assertEquals(getAddr(0x50ff), fragB1.getMaxAddress());

		// move b1 to 0x5050
		treeManager.moveAddressRange(b1.getStart(), getAddr(0x5050), b1.getSize(),
			TaskMonitorAdapter.DUMMY_MONITOR);

		fragB1 = treeManager.getFragment("Test-One", getAddr(0x5050));
		assertNotNull(fragB1);

		assertEquals(getAddr(0x5050), fragB1.getMinAddress());
		assertEquals(getAddr(0x514f), fragB1.getMaxAddress());
	}

@Test
    public void testMoveBlockOverlap2() throws Exception {
		treeManager.createRootModule("Test-One");

		addBlock("TestBlock", 0x5000, 0x100);
		MemoryBlock b2 = addBlock("TestTwoBlock", 0x6000, 0x200);
		addBlock("TestThreeBlock", 0x6500, 0x100);

		ProgramFragment fragB2 = treeManager.getFragment("Test-One", getAddr(0x6000));
		assertEquals(getAddr(0x6000), fragB2.getMinAddress());
		assertEquals(getAddr(0x61ff), fragB2.getMaxAddress());

		// move b2 to 0x5600
		treeManager.moveAddressRange(b2.getStart(), getAddr(0x5600), b2.getSize(),
			TaskMonitorAdapter.DUMMY_MONITOR);

		fragB2 = treeManager.getFragment("Test-One", getAddr(0x5600));
		assertNotNull(fragB2);
		assertEquals(getAddr(0x5600), fragB2.getMinAddress());
		assertEquals(getAddr(0x57ff), fragB2.getMaxAddress());
	}

@Test
    public void testMoveBlockMultiFragments() throws Exception {
		ProgramModule root = treeManager.createRootModule("Test-One");

		MemoryBlock b1 = addBlock("TestBlock", 0x5000, 0x100);
		addBlock("TestTwoBlock", 0x6000, 0x200);
		addBlock("TestThreeBlock", 0x6500, 0x100);

		ProgramFragment fragB1 = treeManager.getFragment("Test-One", getAddr(0x5000));
		String fragB1Name = fragB1.getName();

		ProgramFragment f2 = root.createFragment("f2");
		f2.move(getAddr(0x5000), getAddr(0x5020));
		f2.move(getAddr(0x5040), getAddr(0x5060));
		f2.move(getAddr(0x5065), getAddr(0x5068));

		// move b1 to 0
		treeManager.moveAddressRange(b1.getStart(), getAddr(0), b1.getSize(),
			TaskMonitorAdapter.DUMMY_MONITOR);

		f2 = program.getListing().getFragment("Test-One", "f2");
		assertNotNull(f2);
		assertEquals(getAddr(0), f2.getMinAddress());
		assertEquals(getAddr(0x68), f2.getMaxAddress());
		assertTrue(f2.contains(getAddr(0x66)));

		fragB1 = treeManager.getFragment("Test-One", fragB1Name);
		assertNotNull(fragB1);

		assertEquals(getAddr(0x21), fragB1.getMinAddress());
		assertTrue(fragB1.contains(getAddr(0x3f)));
		assertEquals(getAddr(0xff), fragB1.getMaxAddress());
	}

	/**
	 * Method addBlock.
	 * @param name block name
	 * @param offset offset for the starting address
	 * @param length number of bytes in the block
	 */
	private MemoryBlock addBlock(String name, long offset, int length) throws Exception {
		Memory memory = program.getMemory();
		Address start = getAddr(offset);
		return memory.createInitializedBlock(name, start, length, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
	}

	private Address getAddr(long offset) {
		return space.getAddress(offset);
	}

}
