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
package ghidra.program.database.function;

import static org.junit.Assert.*;

import java.util.Iterator;
import java.util.List;

import org.junit.*;

import ghidra.app.cmd.function.AddStackVarCmd;
import ghidra.app.cmd.refs.AddStackRefCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;

public class FunctionManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private FunctionManager functionManager;
	private int transactionID;

	public FunctionManagerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		functionManager = program.getFunctionManager();
		transactionID = program.startTransaction("Test");
		program.getMemory().createInitializedBlock("temp", addr(0), 10000, (byte) 0,
			TaskMonitorAdapter.DUMMY_MONITOR, false);
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.release(this);

		}
	}

	private Address addr(long l) {
		return space.getAddress(l);
	}

	private Function createFunction(String name, Address entryPt, AddressSetView body)
			throws DuplicateNameException, InvalidInputException, OverlappingFunctionException {

		functionManager.createFunction(name, entryPt, body, SourceType.USER_DEFINED);
		Function f = functionManager.getFunctionAt(entryPt);
		assertEquals(entryPt, f.getEntryPoint());
		assertEquals(body, f.getBody());
		return f;
	}

	@Test
	public void testCreateFunction() throws Exception {

		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		// Overlapping functions - not allowed
		try {
			functionManager.createFunction("foo1", addr(50), new AddressSet(addr(50), addr(100)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}
		try {
			functionManager.createFunction("foo2", addr(200), new AddressSet(addr(200), addr(250)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}
		try {
			functionManager.createFunction("foo3", addr(150), new AddressSet(addr(150), addr(250)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}

		// Invalid entry address
		try {
			createFunction("foo4", addr(250), new AddressSet(addr(300), addr(350)));
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		createFunction("foo4", addr(50), new AddressSet(addr(50), addr(99)));
		createFunction("foo5", addr(201), new AddressSet(addr(201), addr(250)));

		//  try duplicate name
		createFunction("foo5", addr(500), new AddressSet(addr(500), addr(600)));
	}

	@Test
	public void testCreateVarArgFunction() throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setVarArgs(true);
		assertEquals(true, f.hasVarArgs());
		f.setVarArgs(false);
		assertEquals(false, f.hasVarArgs());
	}

	@Test
	public void testCreateInlineFunction() throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertEquals(false, f.isInline());
		f.setInline(true);
		assertEquals(true, f.isInline());
		f.setInline(false);
		assertEquals(false, f.isInline());
	}

	@Test
	public void testCreateNoReturnFunction() throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertEquals(false, f.hasNoReturn());
		f.setNoReturn(true);
		assertEquals(true, f.hasNoReturn());
		f.setNoReturn(false);
		assertEquals(false, f.hasNoReturn());
	}

	@Test
	public void testRemoveFunction() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		Function foo2 = createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		// add stack references and make sure they get removed when the
		// function is deleted
		int transactionIDForTest = program.startTransaction("test");
		AddStackVarCmd cmd = new AddStackVarCmd(foo2.getEntryPoint(), -4, "local_var", null,
			SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(foo2.getEntryPoint(), 4, "param_1", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));

		AddStackRefCmd c = new AddStackRefCmd(addr(210), 0, -4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));
		c = new AddStackRefCmd(addr(222), 1, 4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));

		program.endTransaction(transactionIDForTest, true);

		Variable[] vars = foo2.getLocalVariables();
		assertEquals(1, vars.length);

		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(vars[0]);
		assertEquals(1, vrefs.length);
		assertEquals(addr(210), vrefs[0].getFromAddress());

		Parameter[] params = foo2.getParameters();
		assertEquals(1, params.length);
		vrefs = refMgr.getReferencesTo(params[0]);
		assertEquals(1, vrefs.length);
		assertEquals(addr(222), vrefs[0].getFromAddress());

		functionManager.removeFunction(addr(201));

		vrefs = refMgr.getReferencesTo(vars[0]);
		assertEquals(0, vrefs.length);

		vrefs = refMgr.getReferencesTo(params[0]);
		assertEquals(0, vrefs.length);

		Function f = functionManager.getFunctionAt(addr(100));
		assertEquals(new AddressSet(addr(100), addr(200)), f.getBody());
		assertNull(functionManager.getFunctionAt(addr(201)));
		f = functionManager.getFunctionAt(addr(250));
		assertEquals(new AddressSet(addr(250), addr(350)), f.getBody());

		assertTrue(program.getSymbolTable().getPrimarySymbol(
			addr(201)).getSymbolType() != SymbolType.FUNCTION);
	}

	@Test
	public void testGetFirstFunctionContaining() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		Function f = functionManager.getFunctionContaining(addr(120));
		assertEquals(new AddressSet(addr(100), addr(200)), f.getBody());

		f = functionManager.getFunctionContaining(addr(240));
		assertTrue(new AddressSet(addr(201), addr(249)).equals(f.getBody()));

	}

	@Test
	public void testIsInFunction() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));
		assertTrue(!functionManager.isInFunction(addr(95)));
		assertTrue(functionManager.isInFunction(addr(100)));
		assertTrue(functionManager.isInFunction(addr(250)));
		assertTrue(functionManager.isInFunction(addr(240)));
		assertTrue(!functionManager.isInFunction(addr(500)));
	}

	@Test
	public void testGetFunctionsContaining() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		Function function = functionManager.getFunctionContaining(addr(160));
		assertNotNull(function);
		assertEquals(addr(100), function.getEntryPoint());
		function = functionManager.getFunctionContaining(addr(50));
		assertNull(function);
		function = functionManager.getFunctionContaining(addr(100));
		assertNotNull(function);
		assertEquals(addr(100), function.getEntryPoint());

	}

	@Test
	public void testGetFunctionsOverlapping() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		AddressSet set = new AddressSet();
		set.addRange(addr(50), addr(100));
		set.addRange(addr(350), addr(500));
		Iterator<Function> iter = functionManager.getFunctionsOverlapping(set);
		assertEquals(addr(100), iter.next().getEntryPoint());
		assertEquals(addr(250), iter.next().getEntryPoint());
		assertTrue(!iter.hasNext());

		set = new AddressSet(addr(99), addr(199));
		iter = functionManager.getFunctionsOverlapping(set);
		assertEquals(addr(100), iter.next().getEntryPoint());
		assertTrue(!iter.hasNext());
	}

	/*
	 * Test for FunctionIterator getFunctions()
	 */
	@Test
	public void testGetFunctions() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		FunctionIterator iter = functionManager.getFunctions(true);
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			assertNotNull(iter.next());
		}
		assertEquals(3, cnt);
	}

	@Test
	public void testGetReferencedFunction() throws Exception {

		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		Function foo2 = createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		Function fum = program.getExternalManager().addExtLocation("lib", "fum", null,
			SourceType.USER_DEFINED).createFunction();

		program.getMemory().setInt(addr(50), 201);
		program.getListing().createData(addr(50), PointerDataType.dataType);
		assertEquals(foo2, program.getFunctionManager().getReferencedFunction(addr(50)));

		program.getReferenceManager().addExternalReference(addr(50), 0,
			program.getExternalManager().getExternalLocation(fum.getSymbol()),
			SourceType.USER_DEFINED, RefType.DATA);

		assertEquals(fum, program.getFunctionManager().getReferencedFunction(addr(50)));

	}

	/*
	 * Test for FunctionIterator getFunctions(Address)
	 */
	@Test
	public void testGetFunctionsAddress() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		FunctionIterator iter = functionManager.getFunctions(addr(125), true);
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			assertNotNull(iter.next());
		}
		assertEquals(2, cnt);
	}

	/*
	 * Test for FunctionIterator getFunctions(AddressSetView)
	 */
	@Test
	public void testGetFunctionsAddressSetView() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(250), new AddressSet(addr(250), addr(350)));
		createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		AddressSet asv = new AddressSet();
		asv.addRange(addr(50), addr(60));
		asv.addRange(addr(70), addr(90));
		asv.addRange(addr(110), addr(160));
		asv.addRange(addr(200), addr(249));

		FunctionIterator iter = functionManager.getFunctions(asv, true);
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			Function f = iter.next();
			assertEquals(new AddressSet(addr(201), addr(249)), f.getBody());
		}
		assertEquals(1, cnt);

	}

	@Test
	public void testFunctionIteratorBackwards() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(201), new AddressSet(addr(201), addr(249)));
		createFunction("foo2", addr(250), new AddressSet(addr(250), addr(350)));

		FunctionIterator iter = functionManager.getFunctions(false);
		assertTrue(iter.hasNext());
		Function f = iter.next();
		assertEquals("foo2", f.getName());

		assertTrue(iter.hasNext());
		f = iter.next();
		assertEquals("foo1", f.getName());

		assertTrue(iter.hasNext());
		f = iter.next();
		assertEquals("foo", f.getName());

		assertTrue(!iter.hasNext());
	}

	@Test
	public void testFunctionIteratorBackwards2() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(201), new AddressSet(addr(201), addr(210)));
		createFunction("foo2", addr(250), new AddressSet(addr(250), addr(350)));

		FunctionIterator iter = functionManager.getFunctions(addr(250), false);
		assertTrue(iter.hasNext());
		Function f = iter.next();
		assertEquals("foo2", f.getName());

		assertTrue(iter.hasNext());
		f = iter.next();
		assertEquals("foo1", f.getName());

		assertTrue(iter.hasNext());
		f = iter.next();
		assertEquals("foo", f.getName());

		assertTrue(!iter.hasNext());
	}

	@Test
	public void testFunctionIteratorBackwards3() throws Exception {
		createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		createFunction("foo1", addr(201), new AddressSet(addr(201), addr(210)));
		createFunction("foo2", addr(250), new AddressSet(addr(250), addr(350)));

		FunctionIterator iter = functionManager.getFunctions(addr(300), false);
		assertTrue(iter.hasNext());
		Function f = iter.next();
		assertEquals("foo2", f.getName());

		assertTrue(iter.hasNext());
		f = iter.next();
		assertEquals("foo1", f.getName());

		assertTrue(iter.hasNext());
		f = iter.next();
		assertEquals("foo", f.getName());

		assertTrue(!iter.hasNext());
	}

	@Test
	public void testGetDefaultCallingConvention() throws Exception {
		PrototypeModel protoModel = functionManager.getDefaultCallingConvention();
		assertEquals("__stdcall", protoModel.getName());

		PrototypeModel defaultModel = functionManager.getCallingConvention("default");
		assertEquals(defaultModel, protoModel);
	}

	@Test
	public void testGetCallingConventions() throws Exception {
		PrototypeModel[] protoModels = functionManager.getCallingConventions();
		assertTrue(protoModels.length >= 1);
	}

	@Test
	public void testGetCallingConventionNames() throws Exception {

		List<String> names = functionManager.getCallingConventionNames();
		assertTrue(names.size() >= 1);

		for (String name : names) {
			if (Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(name)) {
				assertNull(functionManager.getCallingConvention(name));
			}
			else {
				assertNotNull(functionManager.getCallingConvention(name));
			}
		}
	}

}
