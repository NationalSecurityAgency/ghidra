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
package ghidra.program.database.references;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

public class StackVariableReferencesTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private ReferenceDBManager refMgr;
	private FunctionManager functionMgr;
	private Listing listing;
	private int transactionID;

	/**
	 * Constructor
	 * @param arg0
	 */
	public StackVariableReferencesTest() {
		super();
	}

	/* 
	 * @see TestCase#setUp()
	 */
    @Before
    public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		refMgr = (ReferenceDBManager) program.getReferenceManager();
		listing = program.getListing();
		functionMgr = program.getFunctionManager();
		transactionID = program.startTransaction("Test");
		program.getMemory().createInitializedBlock("code", addr(0), 10000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
	}

    @After
    public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

@Test
    public void testAddStackReference() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(200));
		set.addRange(addr(500), addr(550));
		Function f = functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		Variable var3_0 =
			f.getStackFrame().createVariable("Foo0", -3, null, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(512), 0, -3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(512), 1, -1, RefType.READ, SourceType.USER_DEFINED);

		Reference ref =
			refMgr.addStackReference(addr(100), 0, 2, RefType.WRITE, SourceType.DEFAULT);
		refMgr.setPrimary(ref, false);

		ref = refMgr.addStackReference(addr(100), 2, -3, RefType.WRITE, SourceType.USER_DEFINED);
		refMgr.setPrimary(ref, true);

		CodeUnit cu = listing.getCodeUnitAt(addr(100));
		Reference[] refs = cu.getOperandReferences(2);
		assertEquals(1, refs.length);
		assertEquals(addr(100), refs[0].getFromAddress());
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(-3, ((StackReference) refs[0]).getStackOffset());
		Variable var = refMgr.getReferencedVariable(refs[0]);
		assertNotNull(var);
		assertTrue(var.isStackVariable());
		assertEquals(var3_0, var);
		assertEquals(-3, var.getStackOffset());
		assertEquals(refs[0].getToAddress(), var.getFirstStorageVarnode().getAddress());
		assertEquals(2, refs[0].getOperandIndex());

		assertEquals(2, refs[0].getOperandIndex());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(2, refs.length);

		cu = listing.getCodeUnitAt(addr(512));
		refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertEquals(addr(512), refs[0].getFromAddress());
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(-3, ((StackReference) refs[0]).getStackOffset());
		var = refMgr.getReferencedVariable(refs[0]);
		assertNotNull(var);
		assertTrue(var.isStackVariable());
		assertEquals(var3_0, var);
		assertEquals(-3, var.getStackOffset());
		assertEquals(refs[0].getToAddress(), var.getFirstStorageVarnode().getAddress());
		assertEquals(0, refs[0].getOperandIndex());

		refs = cu.getOperandReferences(1);
		assertEquals(1, refs.length);
		assertEquals(addr(512), refs[0].getFromAddress());
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(-1, ((StackReference) refs[0]).getStackOffset());
		var = refMgr.getReferencedVariable(refs[0]);
		assertNull(var);
		assertEquals(1, refs[0].getOperandIndex());

		cu = listing.getCodeUnitAt(addr(100));
		refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertEquals(addr(100), refs[0].getFromAddress());
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(2, ((StackReference) refs[0]).getStackOffset());
		var = refMgr.getReferencedVariable(refs[0]);
		assertNull(var);
		assertEquals(0, refs[0].getOperandIndex());

		Variable var2_0 =
			f.getStackFrame().createVariable("Fum0", 2, null, SourceType.USER_DEFINED);
		assertNotNull(var2_0);
		assertEquals(var2_0, refMgr.getReferencedVariable(refs[0]));
	}

@Test
    public void testRemoveStackReference() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(200));
		set.addRange(addr(500), addr(550));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(512), 0, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(512), 1, -1, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(100), 0, 2, RefType.READ, SourceType.DEFAULT);

		CodeUnit cu = listing.getCodeUnitAt(addr(512));
		Reference[] refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(3, ((StackReference) refs[0]).getStackOffset());
		refMgr.delete(refs[0]);
		assertEquals(0, cu.getOperandReferences(0).length);

		assertEquals(1, cu.getOperandReferences(1).length);

		cu = listing.getCodeUnitAt(addr(100));
		refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(2, ((StackReference) refs[0]).getStackOffset());
		refMgr.delete(refs[0]);
		assertEquals(0, cu.getOperandReferences(0).length);
	}

@Test
    public void testRemoveStackRefsInRange() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		set.addRange(addr(500), addr(550));
		set.addRange(addr(1000), addr(2000));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(512), 0, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(512), 1, -1, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(100), 0, 2, RefType.READ, SourceType.DEFAULT);

		refMgr.addStackReference(addr(20), 0, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(50), 1, -1, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(1000), 0, 2, RefType.READ, SourceType.DEFAULT);

		refMgr.removeAllReferencesFrom(addr(100), addr(2000));

		CodeUnit cu = listing.getCodeUnitAt(addr(100));
		assertEquals(0, cu.getOperandReferences(0).length);

		cu = listing.getCodeUnitAt(addr(512));
		assertEquals(0, cu.getOperandReferences(0).length);
		assertEquals(0, cu.getOperandReferences(1).length);

		cu = listing.getCodeUnitAt(addr(20));
		assertEquals(1, cu.getOperandReferences(0).length);

		cu = listing.getCodeUnitAt(addr(50));
		assertEquals(1, cu.getOperandReferences(1).length);
	}

@Test
    public void testGetStackReferences() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(100), 2, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(100), 1, 5, RefType.READ, SourceType.USER_DEFINED);

		Reference[] refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(2, refs.length);

		assertTrue(refs[0].getToAddress().isStackAddress());
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(3, ((StackReference) refs[0]).getStackOffset());

		assertTrue(refs[1].getToAddress().isStackAddress());
		assertTrue(refs[1] instanceof StackReference);
		assertEquals(5, ((StackReference) refs[1]).getStackOffset());
	}

@Test
    public void testIteratorStackRefs() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		set.addRange(addr(500), addr(550));
		set.addRange(addr(1000), addr(2000));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(100), 2, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(100), 1, 5, RefType.READ, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(512), 0, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(512), 1, -1, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(1000), 0, 2, RefType.READ, SourceType.DEFAULT);
		refMgr.addStackReference(addr(1100), 0, 2, RefType.READ, SourceType.DEFAULT);

		AddressIterator iter = refMgr.getReferenceSourceIterator(addr(100), true);
		assertTrue(iter.hasNext());
		Address a = iter.next();
		assertNotNull(a);
		assertEquals(addr(100), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(512), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(1000), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(1100), a);

		assertNull(iter.next());
	}

@Test
    public void testSetIteratorStacRefs() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		set.addRange(addr(500), addr(550));
		set.addRange(addr(1000), addr(2000));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(100), 2, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(100), 2, 5, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(110), 2, 5, RefType.READ, SourceType.USER_DEFINED);

		refMgr.addStackReference(addr(512), 0, 3, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(512), 1, -1, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addStackReference(addr(1000), 0, 2, RefType.READ, SourceType.DEFAULT);
		refMgr.addStackReference(addr(1100), 0, 2, RefType.READ, SourceType.DEFAULT);

		set = new AddressSet();
		set.addRange(addr(0), addr(50));
		set.addRange(addr(105), addr(110));
		set.addRange(addr(1050), addr(2000));

		AddressIterator iter = refMgr.getReferenceSourceIterator(set, true);
		Address a = iter.next();
		assertNotNull(a);
		assertEquals(addr(110), a);

		a = iter.next();
		assertNotNull(a);
		assertEquals(addr(1100), a);

		assertTrue(!iter.hasNext());
	}

}
