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

import org.junit.*;

import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test for Module.
 *
 *
 */
public class ModuleTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private TreeManager treeManager;
	private int transactionID;

	/**
	 * Creates a new test instance.
	 */
	public ModuleTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		TestEnv env = new TestEnv();
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		env.dispose();
		space = program.getAddressFactory().getDefaultAddressSpace();
		treeManager = program.getTreeManager();
		transactionID = program.startTransaction("Test");

		treeManager.createRootModule("Default");
		addBlock("block1", 0, 1000);

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
	public void testRootModule() throws Exception {

		ProgramModule root = createRootModule("MyTree");

		assertEquals("Test", root.getName());

		assertEquals(1, root.getNumChildren());// have 1 memory block==>1 fragment
		assertEquals(0, root.getNumParents());

	}

	@Test
	public void testCreateModules() throws Exception {

		ProgramModule root = createRootModule("MyTree");
		root.createModule("printf");
		root.createModule("Module-1");
		root.createModule("Module-2");

		assertEquals(4, root.getNumChildren());

	}

	@Test
	public void testCreateFragments() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule m1 = root.createModule("printf");

		m1.createFragment("Fragment-1");
		m1.createFragment("Fragment-2");
		assertEquals(2, m1.getNumChildren());
	}

	@Test
	public void testDuplicateName() {
		// test duplicate on module name
		try {
			ProgramModule root = createRootModule("MyTree");
			ProgramModule m1 = root.createModule("printf");

			try {
				root.createModule("printf");
				Assert.fail("Should have been a duplicate name!");
			}
			catch (DuplicateNameException e) {
			}

			// test duplicate on fragment name
			m1.createFragment("Fragment-1");

			try {
				m1.createFragment("Fragment-1");
				Assert.fail("Should have been a duplicate name!");
			}
			catch (DuplicateNameException e) {
			}
		}
		catch (DuplicateNameException e) {
		}
	}

	@Test
	public void testContainsCodeUnit() throws DuplicateNameException, NotFoundException {

		ProgramModule root = createRootModule("MyTree");
		ProgramModule m = root.createModule("Module-A");
		ProgramFragment frag1 = m.createFragment("MyFragment-1");
		frag1.move(addr(0), addr(3));

		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(addr(0));

		assertTrue(m.contains(cu));

	}

//
////	public void testNotContainsCodeUnit() throws DuplicateNameException,
////		NotFoundException {
////
////		Module root = createRootModule("MyTree");
////		Module m = root.createModule("Module-A");
////		Fragment frag1 = m.createFragment("Fragment-1");
////		frag1.move(getAddr(0), getAddr(1));
////		// test that the module does not contain a code unit
////		Listing listing = program.getListing();
////		CodeUnit cu = listing.getCodeUnitContaining(getAddr(4));
////		assertTrue(!m.contains(cu));
////	}
//

	@Test
	public void testContainsFragment() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule m = root.createModule("Module-A");
		ProgramFragment frag1 = m.createFragment("Fragment-1");
		assertTrue(m.contains(frag1));

		// test that root module does not contain frag1
		assertTrue(!root.contains(frag1));
	}

	@Test
	public void testContainsModule() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule m = root.createModule("Module-A");
		ProgramModule subModule = m.createModule("SubModule-A");
		ProgramModule s = subModule.createModule("printf");
		assertTrue(subModule.contains(s));

		assertTrue(!root.contains(s));
		assertTrue(!m.contains(s));
	}

	@Test
	public void testGetChildren() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		root.createModule("Module-2");
		root.createModule("Module-3");
		assertEquals(4, root.getChildren().length);// 4 because of the memory block

		// create modules under submodule1
		submodule1.createModule("printf");
		submodule1.createModule("strcmp");
		submodule1.createModule("strcpy");
		assertEquals(3, submodule1.getChildren().length);
	}

	@Test
	public void testAddModule() throws Exception {

		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		ProgramModule submodule2 = root.createModule("Module-2");
		ProgramModule submodule3 = root.createModule("Module-3");

		ProgramModule s1 = submodule1.createModule("printf");
		submodule1.createModule("strcmp");

		// add s1 to submodule3
		submodule3.add(s1);
		assertTrue(submodule3.contains(s1));

		// add s1 to submodule2
		submodule2.add(s1);
		assertTrue(submodule2.contains(s1));

		// assert that root does not contain s1
		assertTrue(!root.contains(s1));
	}

	@Test
	public void testCircularDependency() throws Exception {
		try {
			ProgramModule root = createRootModule("MyTree");
			ProgramModule submodule1 = root.createModule("Module-1");
			root.createModule("Module-2");
			root.createModule("Module-3");

			ProgramModule s1 = submodule1.createModule("printf");
			ProgramModule s2 = submodule1.createModule("strcmp");

			// try adding submodule1 to s1
			s1.add(submodule1);
			Assert.fail("Should not be able to add a parent to its child!");

			// try adding root to s2
			s2.add(root);
			Assert.fail("Should not be able to add root to its child!");
		}
		catch (CircularDependencyException e) {
		}
		catch (DuplicateGroupException e) {
		}

	}

	@Test
	public void testDuplicateGroup() throws Exception {
		try {
			ProgramModule root = createRootModule("MyTree");
			ProgramModule submodule1 = root.createModule("Module-1");
			root.createModule("Module-2");
			ProgramModule submodule3 = root.createModule("Module-3");

			ProgramModule s1 = submodule1.createModule("printf");
			submodule1.createModule("strcmp");

			// try adding s1 to submodule1 again
			submodule1.add(s1);
			Assert.fail("Should have gotten a duplicate group exception!");

			// try adding submodule3 to root again
			root.add(submodule3);
			Assert.fail("Should have gotten a duplicate group exception!");

		}
		catch (DuplicateGroupException e) {
		}
	}

	@Test
	public void testAddFragment() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		ProgramModule submodule2 = root.createModule("Module-2");
		ProgramModule submodule3 = root.createModule("Module-3");

		ProgramFragment fragOne = submodule1.createFragment("Fragment-1");
		submodule1.createFragment("Fragment-2");

		// add fragOne to submodule3
		submodule3.add(fragOne);
		assertTrue(submodule3.contains(fragOne));

		// add fragOne to submodule2
		submodule2.add(fragOne);
		assertTrue(submodule2.contains(fragOne));

		// assert that root does not contain s1
		assertTrue(!root.contains(fragOne));
	}

	@Test
	public void testAddFragmentDuplicate() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		ProgramFragment fragOne = submodule1.createFragment("Fragment-1");
		submodule1.createFragment("Fragment-2");

		try {
			submodule1.add(fragOne);
			Assert.fail("Should have gotten duplicate group exception");
		}
		catch (DuplicateGroupException e) {
		}
	}

	@Test
	public void testAddModuleDuplicate() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		submodule1.createModule("Module-2");
		ProgramModule sub3 = submodule1.createModule("Module-3");
		try {
			submodule1.add(sub3);
			Assert.fail("Should have gotten duplicate group exception");
		}
		catch (DuplicateGroupException e) {
		}
	}

	@Test
	public void testGetParents() throws Exception {

		// set up some modules
		testAddModule();

		ProgramModule m = treeManager.getModule("MyTree", "printf");
		assertEquals(3, m.getParents().length);

	}

	@Test
	public void testGetParentNames() throws Exception {

		// set up some modules
		testAddModule();

		ProgramModule m = treeManager.getModule("MyTree", "printf");
		String[] names = m.getParentNames();
		assertEquals(3, names.length);
	}

	@Test
	public void testMoveChild() throws Exception {

		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		// create some modules and fragment under submodule1
		submodule1.createFragment("sprintf");
		submodule1.createFragment("strcpy");
		ProgramFragment f3 = submodule1.createFragment("strcmp");
		ProgramFragment f4 = submodule1.createFragment("malloc");

		// now move malloc to the second index
		submodule1.moveChild("malloc", 1);
		Group[] children = submodule1.getChildren();
		assertEquals(f4, children[1]);

		// now move strcmp to first index
		submodule1.moveChild("strcmp", 0);
		children = submodule1.getChildren();
		assertEquals(f4, children[2]);
		assertEquals(f3, children[0]);

		// move malloc to last index
		submodule1.moveChild("malloc", 3);
		children = submodule1.getChildren();
		assertEquals(f4, children[3]);
		assertEquals(3, submodule1.getIndex("malloc"));
	}

	@Test
	public void testRemoveChild() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		ProgramFragment f1 = submodule1.createFragment("sprintf");
		f1.move(addr(40), addr(60));

		root.add(f1);

		// remove f1 from submodule1
		assertTrue(submodule1.removeChild("sprintf"));
		assertEquals(addr(40), f1.getMinAddress());
		assertEquals(addr(60), f1.getMaxAddress());
		Group[] children = submodule1.getChildren();
		assertEquals(0, children.length);

	}

	@Test
	public void testRemoveChild2() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");

		int parentCount = submodule1.getNumParents();
		assertTrue(root.removeChild("Module-1"));
		assertEquals(parentCount - 1, submodule1.getNumParents());
	}

	@Test
	public void testAddBlock() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		addBlock("newblock", 1000, 200);
		addBlock("newblock2", 2000, 100);

		Group[] groups = root.getChildren();
		assertEquals(3, groups.length);
		assertEquals("block1", groups[0].getName());
		assertEquals("newblock", groups[1].getName());
		assertEquals("newblock2", groups[2].getName());
	}

	@Test
	public void testAddBlockWithSameNameAsExistingFolder() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		root.createModule("bob");
		addBlock("bob", 1000, 200);

		Group[] groups = root.getChildren();
		assertEquals(3, groups.length);
		assertEquals("block1", groups[0].getName());
		assertEquals("bob", groups[1].getName());
		assertEquals("bob.1", groups[2].getName());
		assertTrue(groups[1] instanceof ProgramModule);
		assertTrue(groups[2] instanceof ProgramFragment);
	}

	@Test
	public void testRemoveChildNotEmpty() throws Exception {

		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		ProgramFragment f1 = submodule1.createFragment("sprintf");
		f1.move(addr(0), addr(3));

		// try to remove f1 from submodule1

		try {
			submodule1.removeChild("sprintf");
			Assert.fail("Should not have removed sprintf!");
		}
		catch (NotEmptyException e) {
		}
	}

	@Test
	public void testRemoveModuleNotEmpty() throws Exception {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		submodule1.createFragment("sprintf");
		submodule1.createFragment("strcpy");
		submodule1.createModule("Sub-Module");
		try {
			root.removeChild("Module-1");
			Assert.fail("Should not have removed Module-1");
		}
		catch (NotEmptyException e) {
		}
	}

	@Test
	public void testIsDescendant() throws DuplicateNameException {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		ProgramModule s1 = submodule1.createModule("Sub-1");
		ProgramModule ss1 = s1.createModule("Sub-subModule");
		ProgramFragment f1 = ss1.createFragment("subFragment");
		ProgramModule subm = s1.createModule("fred");

		// assert that f1 is a descendant of ss1
		assertTrue(ss1.isDescendant(f1));

		assertTrue(root.isDescendant(f1));

		assertTrue(s1.isDescendant(subm));

		assertTrue(!s1.isDescendant(submodule1));

		assertTrue(!submodule1.isDescendant(root));
	}

	@Test
	public void testGetIndex() throws DuplicateNameException {
		ProgramModule root = createRootModule("MyTree");
		ProgramModule submodule1 = root.createModule("Module-1");
		// create some modules and fragment under submodule1
		submodule1.createFragment("sprintf");
		submodule1.createFragment("strcpy");
		submodule1.createFragment("strcmp");
		submodule1.createFragment("malloc");

		assertEquals(0, submodule1.getIndex("sprintf"));
		assertEquals(1, submodule1.getIndex("strcpy"));
		assertEquals(2, submodule1.getIndex("strcmp"));
		assertEquals(3, submodule1.getIndex("malloc"));

		assertEquals(-1, submodule1.getIndex("fred"));
	}

	@Test
	public void testGetMinAddress() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		ProgramFragment f2 = root.createFragment("Frag2");
		f2.move(addr(0), addr(9));

		ProgramFragment f3 = root.createFragment("Frag3");
		f3.move(addr(40), addr(60));
		assertEquals(addr(0), root.getMinAddress());

		ProgramModule m = root.createModule("Module-1");
		m.add(f2);
		ProgramModule m2 = root.createModule("Module-2");
		ProgramFragment f4 = m2.createFragment("Frag4");
		f4.move(addr(10), addr(20));

		root.removeChild("Frag2");
		assertEquals(addr(10), m2.getMinAddress());

		assertEquals(addr(0), m.getMinAddress());
	}

	@Test
	public void testGetMaxAddress() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		ProgramModule m = root.createModule("Module-1");

		ProgramFragment f2 = m.createFragment("Frag2");
		f2.move(addr(0), addr(9));

		ProgramFragment f3 = m.createFragment("Frag3");
		f3.move(addr(40), addr(60));
		assertEquals(addr(60), m.getMaxAddress());

		ProgramModule m2 = root.createModule("Module-2");
		ProgramFragment f4 = m2.createFragment("Frag4");
		f4.move(addr(70), addr(80));
		f4.move(addr(10), addr(20));
		assertEquals(addr(80), m2.getMaxAddress());

	}

	@Test
	public void testGetFirstAddress() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		ProgramModule m = root.createModule("Module-1");

		ProgramFragment f2 = m.createFragment("Frag2");
		f2.move(addr(0), addr(9));

		ProgramFragment f3 = m.createFragment("Frag3");
		f3.move(addr(40), addr(60));

		ProgramFragment f4 = m.createFragment("Frag4");
		f4.move(addr(500), addr(510));

		m.moveChild("Frag4", 0);
		assertEquals(addr(500), m.getFirstAddress());

		m.moveChild("Frag3", 0);
		assertEquals(addr(40), m.getFirstAddress());

		m.createFragment("Empty");
		m.moveChild("Empty", 0);
		assertEquals(addr(40), m.getFirstAddress());
	}

	@Test
	public void testGetLastAddress() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		ProgramModule m = root.createModule("Module-1");

		ProgramFragment f2 = m.createFragment("Frag2");
		f2.move(addr(0), addr(9));

		ProgramFragment f3 = m.createFragment("Frag3");
		f3.move(addr(40), addr(60));

		ProgramFragment f4 = m.createFragment("Frag4");
		f4.move(addr(500), addr(510));

		assertEquals(addr(510), m.getLastAddress());

		m.moveChild("Frag4", 0);
		assertEquals(addr(60), m.getLastAddress());

		m.moveChild("Frag3", 0);
		assertEquals(addr(9), m.getLastAddress());

		m.createFragment("Empty");
		m.moveChild("Empty", m.getNumChildren() - 1);
		assertEquals(addr(9), m.getLastAddress());

	}

	@Test
	public void testSetComments() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		ProgramFragment f2 = root.createFragment("Frag2");
		f2.move(addr(0), addr(9));

		ProgramFragment f3 = root.createFragment("Frag3");
		f3.move(addr(40), addr(60));
		f2.setComment("my comments");
		assertEquals("my comments", f2.getComment());

		f2.setComment(null);
		assertNull(f2.getComment());
	}

	@Test
	public void testSetName() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		ProgramFragment f2 = root.createFragment("Frag2");
		root.createFragment("Frag3");

		f2.setName("Fred");
		assertEquals("Fred", f2.getName());

		root.setName("Root");
		assertEquals("Root", root.getName());
	}

	@Test
	public void testSetNameDuplicate() throws Exception {
		ProgramModule root = treeManager.createRootModule("MyTree");
		treeManager.getFragment("MyTree", addr(0));
		root.createFragment("Frag2");
		ProgramFragment f3 = root.createFragment("Frag3");
		try {
			f3.setName("Frag2");
			Assert.fail("Should have gotten Duplicate name exception");
		}
		catch (DuplicateNameException e) {
		}

		f3.setName("Frag3");

		ProgramModule m2 = root.createModule("Module-1");
		root.createModule("Module-2");
		try {
			m2.setName("Frag3");
			Assert.fail("Should have gotten Duplicate name exception");
		}
		catch (DuplicateNameException e) {
		}

		try {
			m2.setName(root.getName());
			Assert.fail("Should have gotten Duplicate name exception");
		}
		catch (DuplicateNameException e) {
		}
	}

	@Test
	public void testReparentGroup() throws Exception {
		ProgramModule root = treeManager.createRootModule("test");
		ProgramModule s = root.createModule("SubmoduleA");
		ProgramFragment f = s.createFragment("myfrag");
		f.move(addr(0), addr(50));

		ProgramModule m2 = root.createModule("SubmoduleB");
		ProgramModule m = treeManager.getModule("test", "SubmoduleA");
		ProgramFragment f1 = treeManager.getFragment("test", "myfrag");
		assertNotNull(f1);
		assertTrue(m.contains(f1));
		m2.reparent("myfrag", m);
	}

	@Test
	public void testReparentGroup2() throws Exception {
		ProgramModule root = treeManager.createRootModule("test");

		ProgramModule m2 = root.createModule("SubmoduleB");
		m2.createModule("One");
		m2.createModule("Two");
		m2.createModule("Three");
		m2.createModule("Four");
		m2.createModule("Five");

		ProgramModule m = root.createModule("SubmoduleA");

		assertEquals(3, root.getChildren().length);

		m2.reparent("SubmoduleA", root);
		assertTrue(!root.contains(m));
		assertEquals(2, root.getChildren().length);

		String[] names = m.getParentNames();
		assertEquals(1, names.length);

		assertEquals(6, m2.getNumChildren());

		Group[] g = m2.getChildren();
		assertEquals("SubmoduleA", g[5].getName());
	}

	////////////////////////////////////////////////////////////////////

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	private ProgramModule createRootModule(String name) throws DuplicateNameException {
		return treeManager.createRootModule(name);
	}

	/**
	 * Method addBlock.
	 * @param name block name
	 * @param offset offset for the starting address
	 * @param length number of bytes in the block
	 */
	private MemoryBlock addBlock(String name, long offset, int length) throws Exception {
		Memory memory = program.getMemory();
		Address start = addr(offset);
		try {
			MemoryBlock block = memory.createInitializedBlock(name, start, length, (byte) 0,
				TaskMonitorAdapter.DUMMY_MONITOR, false);
			return block;

		}
		catch (AddressOverflowException e) {
			Assert.fail(e.getMessage());
		}
		catch (MemoryConflictException e) {
			Assert.fail(e.getMessage());
		}
		catch (LockException e) {
			Assert.fail(e.getMessage());
		}
		return null;
	}

}
