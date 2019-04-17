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
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;

public class RegisterVariableReferencesTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private ReferenceDBManager refMgr;
	private FunctionManager functionMgr;
	private Listing listing;
	private int transactionID;

	private Register regA;
	private Register regB;
	private Register regC;

	public RegisterVariableReferencesTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._X86, this);
		regA = program.getRegister("AX");
		regB = program.getRegister("BX");
		regC = program.getRegister("CX");
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
    public void testAddRegisterReference() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(200));
		set.addRange(addr(500), addr(550));
		Function f = functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);
		f.setCustomVariableStorage(true);

		Parameter p = new ParameterImpl("ParmA", Undefined2DataType.dataType, regA, program);
		Parameter parmA = f.addParameter(p, SourceType.USER_DEFINED);

		Variable v = new LocalVariableImpl("VarA", 400, Undefined2DataType.dataType, regA, program);
		Variable varA = f.addLocalVariable(v, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(512), 0, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(512), 1, regB, RefType.READ, SourceType.USER_DEFINED);

		Reference ref =
			refMgr.addRegisterReference(addr(100), 0, regC, RefType.WRITE, SourceType.DEFAULT);
		refMgr.setPrimary(ref, false);

		ref =
			refMgr.addRegisterReference(addr(100), 2, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.setPrimary(ref, true);

		CodeUnit cu = listing.getCodeUnitAt(addr(100));
		Reference[] refs = cu.getOperandReferences(2);
		assertEquals(1, refs.length);
		assertEquals(regA.getAddress(), refs[0].getToAddress());
		Variable var = refMgr.getReferencedVariable(refs[0]);
		assertNotNull(var);
		assertEquals(parmA, var);
		assertTrue(var.isRegisterVariable());
		assertEquals(regA, var.getRegister());
		assertEquals(addr(100), refs[0].getFromAddress());
		assertEquals(2, refs[0].getOperandIndex());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(2, refs.length);

		cu = listing.getCodeUnitAt(addr(512));
		refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertEquals(regA.getAddress(), refs[0].getToAddress());
		var = refMgr.getReferencedVariable(refs[0]);
		assertNotNull(var);
		assertEquals(varA, var);
		assertEquals(regA, var.getRegister());
		assertEquals(regA, var.getRegister());
		assertEquals(addr(512), refs[0].getFromAddress());
		assertEquals(0, refs[0].getOperandIndex());

		refs = cu.getOperandReferences(1);
		assertEquals(1, refs.length);
		var = refMgr.getReferencedVariable(refs[0]);
		assertNull(var);
		assertEquals(regB.getAddress(), refs[0].getToAddress());
		assertEquals(addr(512), refs[0].getFromAddress());
		assertEquals(1, refs[0].getOperandIndex());

		cu = listing.getCodeUnitAt(addr(100));
		refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		var = refMgr.getReferencedVariable(refs[0]);
		assertNull(var);
		assertEquals(regC.getAddress(), refs[0].getToAddress());
		assertEquals(addr(100), refs[0].getFromAddress());
		assertEquals(0, refs[0].getOperandIndex());

		v = new LocalVariableImpl("VarC", 0, null, regC, program);
		Variable varC = f.addLocalVariable(v, SourceType.USER_DEFINED);
		assertNotNull(varC);
		assertEquals(varC, refMgr.getReferencedVariable(refs[0]));
	}

@Test
    public void testRemoveRegisterReference() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(100), addr(200));
		set.addRange(addr(500), addr(550));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(512), 0, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(512), 1, regB, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(100), 0, regC, RefType.READ, SourceType.DEFAULT);

		CodeUnit cu = listing.getCodeUnitAt(addr(512));
		Reference[] refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertEquals(regA.getAddress(), refs[0].getToAddress());
		refMgr.delete(refs[0]);
		assertEquals(0, cu.getOperandReferences(0).length);

		assertEquals(1, cu.getOperandReferences(1).length);

		cu = listing.getCodeUnitAt(addr(100));
		refs = cu.getOperandReferences(0);
		assertEquals(1, refs.length);
		assertEquals(regC.getAddress(), refs[0].getToAddress());
		refMgr.delete(refs[0]);
		assertEquals(0, cu.getOperandReferences(0).length);
	}

@Test
    public void testRemoveRegisterRefsInRange() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		set.addRange(addr(500), addr(550));
		set.addRange(addr(1000), addr(2000));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(512), 0, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(512), 1, regB, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(100), 0, regC, RefType.READ, SourceType.DEFAULT);

		refMgr.addRegisterReference(addr(20), 0, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(50), 1, regB, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(1000), 0, regC, RefType.READ, SourceType.DEFAULT);

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
    public void testGetRegisterReferences() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(100), 2, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(100), 1, regB, RefType.READ, SourceType.USER_DEFINED);

		Reference[] refs = refMgr.getReferencesFrom(addr(100));
		assertEquals(2, refs.length);
		assertEquals(regA.getAddress(), refs[0].getToAddress());
		assertEquals(regB.getAddress(), refs[1].getToAddress());
	}

@Test
    public void testIteratorRegisterRefs() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0), addr(200));
		set.addRange(addr(500), addr(550));
		set.addRange(addr(1000), addr(2000));
		functionMgr.createFunction("test", addr(100), set, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(100), 2, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(100), 1, regB, RefType.READ, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(512), 0, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(512), 1, regC, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(1000), 0, regB, RefType.READ, SourceType.DEFAULT);
		refMgr.addRegisterReference(addr(1100), 0, regB, RefType.READ, SourceType.DEFAULT);

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

		refMgr.addRegisterReference(addr(100), 2, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(100), 2, regB, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(110), 2, regB, RefType.READ, SourceType.USER_DEFINED);

		refMgr.addRegisterReference(addr(512), 0, regA, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(512), 1, regC, RefType.READ, SourceType.USER_DEFINED);
		refMgr.addRegisterReference(addr(1000), 0, regB, RefType.READ, SourceType.DEFAULT);
		refMgr.addRegisterReference(addr(1100), 0, regB, RefType.READ, SourceType.DEFAULT);

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
