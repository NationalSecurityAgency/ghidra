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
package ghidra.program.database.symbol;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

/**
 */
public class NamespaceManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private NamespaceManager namespaceManager;
	private SymbolTable symbolMgr;
	private FunctionManager functionMgr;
	private ProgramDB program;
	private AddressSpace space;
	private int transactionID;
	private Namespace globalNamespace;

	/**
	 * Constructor for NamespaceManagerTest.
	 * @param arg0
	 */
	public NamespaceManagerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		namespaceManager = program.getNamespaceManager();
		symbolMgr = program.getSymbolTable();
		functionMgr = program.getFunctionManager();
		globalNamespace = namespaceManager.getGlobalNamespace();
		transactionID = program.startTransaction("Test");
		addBlock("BlockOne", addr(0), 0x1000);
		addBlock("BlockTwo", addr(0x2000), 0x4000);
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	@Test
	public void testCreateSubNamespace() throws Exception {
		GhidraClass gc =
			symbolMgr.createClass(globalNamespace, "classNamespace", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));

		Function f1 = functionMgr.createFunction("fun", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(gc);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));
		Function f2 = functionMgr.createFunction("TextFunctionNamespace", addr(0x100), set2,
			SourceType.USER_DEFINED);
		f2.setParentNamespace(gc);

		assertTrue(gc.getBody().hasSameAddresses(set.union(set2)));

		assertEquals(f1, namespaceManager.getNamespaceContaining(addr(0x12)));
		assertEquals(f1, namespaceManager.getNamespaceContaining(addr(0x255)));
		assertEquals(f1, namespaceManager.getNamespaceContaining(addr(0x502)));

		assertEquals(f2, namespaceManager.getNamespaceContaining(addr(0x110)));
	}

	@Test
	public void testGetBody() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function function =
			functionMgr.createFunction("Function1", addr(0x300), set, SourceType.USER_DEFINED);
		function.setParentNamespace(classNamespace);

		assertEquals(function, symbolMgr.getNamespace(addr(0x510)));

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x800), addr(0x900));
		set2.addRange(addr(0x2000), addr(0x2050));

		Function function2 =
			functionMgr.createFunction("Function2", addr(0x850), set2, SourceType.USER_DEFINED);
		function2.setParentNamespace(classNamespace);

		assertEquals(function2, symbolMgr.getNamespace(addr(0x810)));

		AddressSet set3 = new AddressSet();
		set3.addRange(addr(0x3000), addr(0x3500));
		set3.addRange(addr(0x4000), addr(0x5000));

		Function function3 =
			functionMgr.createFunction("Function3", addr(0x3000), set3, SourceType.USER_DEFINED);
		function3.setParentNamespace(classNamespace);

		assertEquals(function3, symbolMgr.getNamespace(addr(0x3100)));

		AddressSetView gcSet = classNamespace.getBody();
		AddressSet newSet = set.union(set2);
		newSet = newSet.union(set3);
		assertTrue(gcSet.hasSameAddresses(newSet));
	}

	@Test
	public void testFullName() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x2000), addr(0x2200));
		set2.addRange(addr(0x2500), addr(0x2800));

		Function f2 = functionMgr.createFunction("F2", addr(0x2000), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		AddressSet set3 = new AddressSet();
		set3.addRange(addr(0x3100), addr(0x3150));

		Function f3 = functionMgr.createFunction("F3", addr(0x3100), set3, SourceType.USER_DEFINED);
		f3.setParentNamespace(classNamespace);

		assertEquals("TestNamespaceClass::F1", f1.getName(true));
		assertEquals("TestNamespaceClass::F2", f2.getName(true));
		assertEquals("TestNamespaceClass::F3", f3.getName(true));
	}

	@Test
	public void testRemoveNamespace() throws Exception {

		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));

		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x2000), addr(0x2200));
		set2.addRange(addr(0x2500), addr(0x2800));

		Function f2 = functionMgr.createFunction("F2", addr(0x2000), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);
		long id2 = f2.getID();

		AddressSet set3 = new AddressSet();
		set3.addRange(addr(0x3100), addr(0x3150));

		Function f3 = functionMgr.createFunction("F3", addr(0x3100), set3, SourceType.USER_DEFINED);
		f3.setParentNamespace(classNamespace);
		long id3 = f3.getID();

		// delete class; its namespaces should be removed
		symbolMgr.removeSymbolSpecial(classNamespace.getSymbol());

		assertNull(functionMgr.getFunction(id2));
		assertNull(functionMgr.getFunction(id3));
		assertEquals(globalNamespace, namespaceManager.getNamespaceContaining(addr(0x2500)));
		assertEquals(globalNamespace, namespaceManager.getNamespaceContaining(addr(0x100)));
		assertEquals(globalNamespace, namespaceManager.getNamespaceContaining(addr(0x255)));

		Assert.assertTrue("Function 2 should be marked as deleted!", f2.isDeleted());
		Assert.assertTrue("Function 3 should be marked as deleted!", f3.isDeleted());
	}

	@Test
	public void testMoveNamespace() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);
		GhidraClass classNamespace2 =
			symbolMgr.createClass(null, "TestNamespaceClass2", SourceType.USER_DEFINED);
		GhidraClass classNamespace3 =
			symbolMgr.createClass(null, "TestNamespaceClass3", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));

		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));

		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace2);

		assertEquals(classNamespace2, f2.getParentNamespace());
		assertTrue(classNamespace2.getBody().hasSameAddresses(set2));
		AddressSetView view = classNamespace2.getBody();
		assertTrue(view.hasSameAddresses(f2.getBody()));

		f2.setParentNamespace(classNamespace3);
		assertEquals(classNamespace3, f2.getParentNamespace());
	}

	@Test
	public void testMoveAddressRange() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));

		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		MemoryBlock[] blocks = program.getMemory().getBlocks();
		namespaceManager.moveAddressRange(blocks[0].getStart(), addr(0x1000), blocks[0].getSize(),
			TaskMonitorAdapter.DUMMY_MONITOR);

		set = new AddressSet();
		set.addRange(addr(0x1000), addr(0x1030));
		set.addRange(addr(0x1250), addr(0x1310));
		set.addRange(addr(0x1500), addr(0x1520));
		set.addRange(addr(0x1100), addr(0x1130));

		assertTrue(classNamespace.getBody().hasSameAddresses(set));

		set2 = new AddressSet();
		set2.addRange(addr(0x1100), addr(0x1130));
		assertTrue(f2.getBody().hasSameAddresses(set2));
	}

	@Test
	public void testMoveAddressRange2() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));
		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		namespaceManager.moveAddressRange(addr(0x300), addr(0x1000), 0x100,
			TaskMonitorAdapter.DUMMY_MONITOR);

		set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x100), addr(0x130));
		set.addRange(addr(0x250), addr(0x2ff));
		set.addRange(addr(0x500), addr(0x520));
		set.addRange(addr(0x1000), addr(0x1010));

		assertTrue(classNamespace.getBody().hasSameAddresses(set));

		assertTrue(f2.getBody().hasSameAddresses(set2));
	}

	@Test
	public void testDeleteAddressRange() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));
		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		functionMgr.removeFunction(addr(0x300));
		AddressSet classSet = new AddressSet(classNamespace.getBody());
		AddressSet newSet = classSet.subtract(set);
		assertTrue(newSet.hasSameAddresses(namespaceManager.getAddressSet(f2)));

		assertEquals(globalNamespace, namespaceManager.getNamespaceContaining(addr(0)));
	}

	@Test
	public void testIsOverlappedNamespace() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));
		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		set2 = new AddressSet();
		set2.addRange(addr(0x20), addr(0x50));
		set2.addRange(addr(0x1000), addr(0x3000));

		if (namespaceManager.overlapsNamespace(set2) == null) {
			Assert.fail("Should overlap!");
		}

		set2 = new AddressSet();
		set2.addRange(addr(0xff), addr(0x101));
		set2.addRange(addr(0x1000), addr(0x3000));

		if (namespaceManager.overlapsNamespace(set2) == null) {
			Assert.fail("Should overlap!");
		}

		set2 = new AddressSet();
		set.addRange(addr(0x200), addr(0x210));
		set.addRange(addr(0x55), addr(0xff));
		set2.addRange(addr(0x1000), addr(0x3000));
		if (namespaceManager.overlapsNamespace(set2) != null) {
			Assert.fail("Should not overlap!");
		}
	}

	@Test
	public void testNamespaceIteratorForOverlaps() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));
		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		AddressSet set3 = new AddressSet();
		set3.addRange(addr(0x600), addr(0x700));
		set3.addRange(addr(0x750), addr(0x760));
		set3.addRange(addr(0x770), addr(0x780));
		Function f3 = functionMgr.createFunction("F3", addr(0x600), set3, SourceType.USER_DEFINED);
		f3.setParentNamespace(classNamespace);

		AddressSet set4 = new AddressSet();
		set4.addRange(addr(0x900), addr(0x950));
		set4.addRange(addr(0x960), addr(0x980));
		set4.addRange(addr(0x1000), addr(0x1020));
		set4.addRange(addr(0x1030), addr(0x1050));
		Function f4 = functionMgr.createFunction("F4", addr(0x900), set4, SourceType.USER_DEFINED);
		f4.setParentNamespace(classNamespace);

		AddressSet testSet = new AddressSet();
		testSet.addRange(addr(0x500), addr(0x501));
		testSet.addRange(addr(0x1025), addr(0x1070));

		// should get back only TestFunctionNamespace and TestFunctionNamespace4
		Iterator<Namespace> iter = namespaceManager.getNamespacesOverlapping(testSet);
		assertTrue(iter.hasNext());
		Namespace namespace = iter.next();
		assertNotNull(namespace);
		assertEquals("F1", namespace.getName());

		assertTrue(iter.hasNext());
		namespace = iter.next();
		assertNotNull(namespace);
		assertEquals("F4", namespace.getName());

		assertTrue(!iter.hasNext());

	}

	@Test
	public void testNamespaceIteratorForOverlaps2() throws Exception {
		GhidraClass classNamespace =
			symbolMgr.createClass(null, "TestNamespaceClass", SourceType.USER_DEFINED);

		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(0x30));
		set.addRange(addr(0x250), addr(0x310));
		set.addRange(addr(0x500), addr(0x520));
		Function f1 = functionMgr.createFunction("F1", addr(0x300), set, SourceType.USER_DEFINED);
		f1.setParentNamespace(classNamespace);

		AddressSet set2 = new AddressSet();
		set2.addRange(addr(0x100), addr(0x130));
		Function f2 = functionMgr.createFunction("F2", addr(0x100), set2, SourceType.USER_DEFINED);
		f2.setParentNamespace(classNamespace);

		AddressSet set3 = new AddressSet();
		set3.addRange(addr(0x600), addr(0x700));
		set3.addRange(addr(0x750), addr(0x760));
		set3.addRange(addr(0x770), addr(0x780));
		Function f3 = functionMgr.createFunction("F3", addr(0x600), set3, SourceType.USER_DEFINED);
		f3.setParentNamespace(classNamespace);

		AddressSet set4 = new AddressSet();
		set4.addRange(addr(0x900), addr(0x950));
		set4.addRange(addr(0x960), addr(0x980));
		set4.addRange(addr(0x1000), addr(0x1020));
		set4.addRange(addr(0x1030), addr(0x1050));
		Function f4 = functionMgr.createFunction("F4", addr(0x900), set4, SourceType.USER_DEFINED);
		f4.setParentNamespace(classNamespace);

		AddressSet testSet = new AddressSet();
		testSet.addRange(addr(0x101), addr(0x101));
		testSet.addRange(addr(0x105), addr(0x110));
		testSet.addRange(addr(0x771), addr(0x772));
		testSet.addRange(addr(0x755), addr(0x757));
		testSet.addRange(addr(0x601), addr(0x602));

		// should get back only TestFunctionNamespace2 and TestFunctionNamespace3
		Iterator<Namespace> iter = namespaceManager.getNamespacesOverlapping(testSet);
		assertTrue(iter.hasNext());
		Namespace namespace = iter.next();
		assertNotNull(namespace);
		assertEquals("F2", namespace.getName());

		assertTrue(iter.hasNext());
		namespace = iter.next();
		assertNotNull(namespace);
		assertEquals("F3", namespace.getName());

		assertTrue(!iter.hasNext());
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	private void addBlock(String name, Address addr, int length) throws Exception {
		program.getMemory()
				.createInitializedBlock(name, addr, length, (byte) 0,
					TaskMonitorAdapter.DUMMY_MONITOR, false);
	}
}
