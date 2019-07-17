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
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * 
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
 */
public class FragmentTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private Listing listing;
	private AddressSpace space;
	private ProgramFragment f1;
	private ProgramFragment f2;
	private ProgramModule root;
	private int transactionID;

	/**
	 * Constructor for FragmentTest.
	 * @param name
	 */
	public FragmentTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");
		addBlock(".test-1", 0, 0x100);
		addBlock(".test-2", 0x200, 0x200);
		listing = program.getListing();
		root = listing.createRootModule("MyTree");
		Group[] groups = root.getChildren();
		// we know root has 2 fragments because we create 2 memory blocks
		// in the set up.
		f1 = (ProgramFragment) groups[0];
		f2 = (ProgramFragment) groups[1];

	}

	@Test
	public void testContainsCodeUnit() throws Exception {

		assertTrue(f1.contains(listing.getCodeUnitAt(addr(20))));
		assertTrue(f1.contains(listing.getCodeUnitAt(addr(200))));
		assertTrue(f2.contains(listing.getCodeUnitAt(addr(0x250))));

	}

	@Test
	public void testGetParents() throws Exception {

		ProgramModule m1 = root.createModule("Module-A");
		ProgramModule m2 = root.createModule("Module-B");
		m1.add(f1);
		m2.add(f1);

		assertEquals(3, f1.getNumParents());
		ProgramModule[] parents = f1.getParents();
		assertEquals(3, parents.length);
		for (int i = 0; i < parents.length; i++) {
			assertTrue(parents[i].equals(root) || parents[i].equals(m1) || parents[i].equals(m2));
		}
	}

	@Test
	public void testGetParentNames() throws Exception {
		ProgramModule m1 = root.createModule("Module-A");
		ProgramModule m2 = root.createModule("Module-B");
		ProgramModule m3 = root.createModule("Module-C");

		m1.add(f1);
		m1.add(f2);

		m2.add(f1);
		m3.add(f1);
		String[] names = f1.getParentNames();
		assertEquals(4, names.length);
		assertEquals(root.getName(), names[0]);
		assertEquals("Module-A", names[1]);
		assertEquals("Module-B", names[2]);
		assertEquals("Module-C", names[3]);

		m1.removeChild(f1.getName());
		assertEquals(3, f1.getParentNames().length);
	}

	@Test
	public void testGetTreeName() throws Exception {
		assertEquals("MyTree", f1.getTreeName());
		ProgramModule r2 = program.getListing().createRootModule("AnotherTree");
		ProgramFragment frag = r2.createFragment("frag");
		assertEquals("AnotherTree", frag.getTreeName());
	}

	/**
	 * Test getting a code unit iterator over a fragment.
	 */
	@Test
	public void testGetCodeUnits() {

		int count = countCodeUnits(f1);
		assertEquals(0x100, count);

		// check next fragment
		count = countCodeUnits(f2);
		assertEquals(0x200, count);
	}

	@Test
	public void testGetMinAddress() {
		assertEquals(addr(0), f1.getMinAddress());
		assertEquals(addr(0x200), f2.getMinAddress());
	}

	@Test
	public void testMinForMultiRange() throws Exception {
		// add another memory block
		addBlock(".newblock", 0x110, 20);
		f2.move(addr(0x115), addr(0x120));
		assertEquals(addr(0x115), f2.getMinAddress());
	}

	@Test
	public void testGetMaxAddress() {
		assertEquals(addr(0xff), f1.getMaxAddress());
		assertEquals(addr(0x3ff), f2.getMaxAddress());
	}

	@Test
	public void testMaxForMultiRange() throws Exception {
		// add another memory block
		addBlock(".newblock", 0x1000, 200);
		f1.move(addr(0x1005), addr(0x1015));
		assertEquals(addr(0x1015), f1.getMaxAddress());
	}

	@Test
	public void testMoveCodeUnits() throws NotFoundException {
		// 
		// move all from f1 to f2
		f2.move(f1.getMinAddress(), f1.getMaxAddress());
		assertNull(f1.getMinAddress());
		assertEquals(0, f1.getNumAddresses());

		// test for Empty
		assertTrue(f1.isEmpty());
	}

	@Test
	public void testNotFound() {
		try {
			f1.move(addr(0x2000), addr(0x2500));
			Assert.fail("Expected the NotFoundException!");
		}
		catch (NotFoundException e) {
			// good
		}
	}

	@Test
	public void testContainsAddress() {
		assertTrue(f1.contains(addr(0x10)));
		assertTrue(f1.contains(addr(0xff)));

		assertTrue(!f1.contains(addr(0x100)));

		assertTrue(f2.contains(addr(0x200)));
		assertTrue(f2.contains(addr(0x3ff)));

		assertTrue(!f2.contains(addr(0)));
	}

	@Test
	public void testContainsRange() {
		assertTrue(f1.contains(addr(0), addr(0x50)));
		assertTrue(f1.contains(addr(0x35), addr(0x60)));
		assertTrue(!f1.contains(addr(0x50), addr(0x200)));

		assertTrue(f2.contains(addr(0x250), addr(0x255)));
		assertTrue(!f2.contains(addr(0x100), addr(0x300)));
		assertTrue(!f2.contains(addr(0x500), addr(0x600)));
	}

	@Test
	public void testContainsSet() throws Exception {
		// create a new fragment
		ProgramFragment f3 = root.createFragment("Frag3");
		f3.move(addr(0), addr(0xa));
		f3.move(addr(0x14), addr(0x1e));
		f3.move(addr(0x28), addr(0x32));
		f3.move(addr(0x3c), addr(0x46));

		AddressSet set = new AddressSet();
		set.addRange(addr(0x14), addr(0x1e));
		set.addRange(addr(0x3c), addr(0x46));
		assertTrue(f3.contains(set));

		set = new AddressSet();
		set.addRange(addr(0x28), addr(0x30));
		set.addRange(addr(0x3c), addr(0x6c));
		assertTrue(!f3.contains(set));
	}

	@Test
	public void testMoveAddresses() throws Exception {

		ProgramModule defaultRoot = listing.createRootModule("Default");
		ProgramFragment frag = listing.getFragment("Default", addr(0));
		assertNotNull(frag);
		assertEquals(0x100, frag.getNumAddresses());
		ProgramModule m = defaultRoot.createModule("Module-A");
		ProgramFragment frag1 = m.createFragment("Fragment-1");
		frag1.move(addr(0), addr(25));
		assertEquals(26, frag1.getNumAddresses());
		assertEquals(230, frag.getNumAddresses());

		ProgramFragment frag2 = m.createFragment("Frag-2");
		frag2.move(addr(20), addr(40));

		assertEquals(21, frag2.getNumAddresses());
		assertEquals(20, frag1.getNumAddresses());
		assertEquals(215, frag.getNumAddresses());
	}

	@Test
	public void testGetAddressRanges() throws Exception {
		ProgramFragment f3 = root.createFragment("Frag3");
		f3.move(addr(0), addr(0xa));
		f3.move(addr(0x14), addr(0x1e));
		f3.move(addr(0x28), addr(0x32));
		f3.move(addr(0x3c), addr(0x46));

		AddressRangeIterator iter = f3.getAddressRanges();
		int count = 0;
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			++count;
			if (count == 3) {
				assertEquals(new AddressRangeImpl(addr(0x28), addr(0x32)), range);
			}
		}
		assertEquals(4, count);
	}

	@Test
	public void testDoIntersect() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x10), addr(0x20));
		set.addRange(addr(0x50), addr(0x500));
		AddressSetView view = f1.intersect(set);

		AddressSet expectedSet = new AddressSet();
		expectedSet.addRange(addr(0x10), addr(0x20));
		expectedSet.addRange(addr(0x50), addr(0xff));

		assertEquals(expectedSet, view);

		// an empty fragment should return an empty set
		ProgramFragment f3 = root.createFragment("frag3");
		assertEquals(new AddressSet(), f3.intersect(set));
	}

	@Test
	public void testGetAddresses() {
		int count = 0;
		AddressIterator iter = f1.getAddresses(true);
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		assertEquals(0x100, count);
	}

	/**
	 * Test the address iterator starting at a specific address.
	 */
	@Test
	public void testGetAddressesAt() {
		int count = 0;
		AddressIterator iter = f1.getAddresses(addr(0x10), true);
		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		assertEquals(0xf0, count);
	}

	@Test
	public void testIntersects() {
		assertTrue(f1.intersects(addr(0x10), addr(0x60)));
		assertTrue(f1.intersects(addr(0x20), addr(0x200)));
		assertTrue(f2.intersects(addr(0x220), addr(0x250)));
		assertTrue(f2.intersects(addr(0), addr(0x220)));

		assertTrue(!f1.intersects(addr(0x100), addr(0x200)));
		assertTrue(!f2.intersects(addr(0x400), addr(0x500)));
	}

	@Test
	public void testIntersectsRange() {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x50));
		set.addRange(addr(0x200), addr(0x201));
		assertTrue(f1.intersects(set));

		set = new AddressSet();
		set.addRange(addr(0x100), addr(0x200));
		assertTrue(!f1.intersects(set));
	}

	@Test
	public void testEquals() throws DuplicateNameException, NotFoundException {

		ProgramFragment f = listing.getFragment("MyTree", addr(0));
		assertTrue(f1.equals(f));

		// test equals on address set
		ProgramFragment f3 = root.createFragment("Frag3");
		f3.move(addr(0), addr(0xa));
		f3.move(addr(0x14), addr(0x1e));
		f3.move(addr(0x28), addr(0x32));
		f3.move(addr(0x3c), addr(0x46));
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0xa));
		set.addRange(addr(0x14), addr(0x1e));
		set.addRange(addr(0x28), addr(0x32));
		set.addRange(addr(0x3c), addr(0x46));

		assertTrue(f3.hasSameAddresses(set));

		set = set.subtract(new AddressSet(addr(0x28), addr(0x3d)));
		assertTrue(!f3.equals(set));
	}

	@Test
	public void testGetMinAddress2() throws Exception {
		ProgramModule myTreeRoot = listing.getRootModule("MyTree");
		// create module with two fragments
		ProgramModule m = myTreeRoot.createModule("Module-A");
		ProgramFragment frag1 = m.createFragment("Fragment-1");
		frag1.move(addr(0), addr(25));
		ProgramFragment frag2 = m.createFragment("Frag-2");
		frag2.move(addr(30), addr(40));

		assertEquals(addr(0), m.getMinAddress());

		// create another module with two fragments
		ProgramModule m2 = myTreeRoot.createModule("Module-B");
		ProgramFragment fragment2 = m2.createFragment("Fragment-2");
		fragment2.move(addr(60), addr(70));
		ProgramFragment frag3 = m2.createFragment("Frag-3");
		frag3.move(addr(45), addr(50));

		assertEquals(addr(45), m2.getMinAddress());
	}

	@Test
	public void testGetMaxAddress2() throws Exception {
		ProgramModule myTreeRoot = listing.getRootModule("MyTree");
		ProgramModule m = myTreeRoot.createModule("Module-A");
		ProgramFragment frag2 = m.createFragment("Frag-2");
		frag2.move(addr(30), addr(40));
		ProgramFragment frag1 = m.createFragment("Fragment-1");
		frag1.move(addr(0), addr(25));

		assertEquals(addr(40), m.getMaxAddress());

		ProgramModule m2 = myTreeRoot.createModule("Module-B");
		ProgramFragment fragment2 = m2.createFragment("Fragment-2");
		fragment2.move(addr(60), addr(70));
		ProgramFragment frag3 = m2.createFragment("Frag-3");
		frag3.move(addr(45), addr(50));
		ProgramFragment frag4 = m2.createFragment("Frag-4");
		frag4.move(addr(20), addr(25));
		assertEquals(addr(70), m2.getMaxAddress());
	}

	@Test
	public void testSetName() throws Exception {
		ProgramFragment f = listing.getFragment("MyTree", addr(10));

		f.setName("Fred");
		assertEquals("Fred", f.getName());
	}

	@Test
	public void testSetComment() throws Exception {
		ProgramFragment f = listing.getFragment("MyTree", addr(10));
		assertNull(f.getComment());
		f.setComment("my comment");

		assertEquals("my comment", f.getComment());
		f.setComment(null);
		assertNull(f.getComment());
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	private int countCodeUnits(ProgramFragment frag) {
		CodeUnitIterator iter = frag.getCodeUnits();
		int count = 0;

		while (iter.hasNext()) {
			iter.next();
			++count;
		}
		return count;
	}

	private MemoryBlock addBlock(String name, long offset, int length) throws Exception {
		Memory memory = program.getMemory();
		Address start = addr(offset);
		try {
			MemoryBlock block =
				memory.createInitializedBlock(name, start, length, (byte) 0,
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
