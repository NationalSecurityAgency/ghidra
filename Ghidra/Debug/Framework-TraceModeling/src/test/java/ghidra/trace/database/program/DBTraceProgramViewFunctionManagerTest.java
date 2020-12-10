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
package ghidra.trace.database.program;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;

import org.junit.*;

import ghidra.app.cmd.function.AddStackVarCmd;
import ghidra.app.cmd.refs.AddStackRefCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.InvalidInputException;

public class DBTraceProgramViewFunctionManagerTest extends AbstractGhidraHeadlessIntegrationTest {
	ToyDBTraceBuilder b;
	FunctionManager functionManager;
	Program program;
	UndoableTransaction tid;

	@Before
	public void setUpFunctionManagerTest() throws IOException {
		b = new ToyDBTraceBuilder("Testing", ProgramBuilder._TOY);
		program = b.trace.getFixedProgramView(0);
		functionManager = program.getFunctionManager();
		tid = b.startTransaction();
	}

	@After
	public void tearDownFunctionManagerTest() {
		tid.close();
		b.close();
	}

	protected Function createFunction(String name, Address entry, AddressSetView body)
			throws InvalidInputException, OverlappingFunctionException {
		Function created =
			functionManager.createFunction(name, entry, body, SourceType.USER_DEFINED);
		Function found = functionManager.getFunctionAt(entry);
		assertSame(created, found);
		assertEquals(entry, created.getEntryPoint());
		assertEquals(body, created.getBody());
		return created;
	}

	@Test
	public void testCreateFunction() throws Exception {

		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));

		// Overlapping functions - not allowed
		try {
			functionManager.createFunction("foo1", b.addr(50), b.set(b.range(50, 100)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}
		try {
			functionManager.createFunction("foo2", b.addr(200), b.set(b.range(200, 250)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}
		try {
			functionManager.createFunction("foo3", b.addr(150), b.set(b.range(150, 250)),
				SourceType.USER_DEFINED);
			Assert.fail();
		}
		catch (OverlappingFunctionException e) {
			// Expected
		}

		// Invalid entry address
		try {
			createFunction("foo4", b.addr(250), b.set(b.range(300, 350)));
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		createFunction("foo4", b.addr(50), b.set(b.range(50, 99)));
		createFunction("foo5", b.addr(201), b.set(b.range(201, 250)));

		//  try duplicate name
		createFunction("foo5", b.addr(500), b.set(b.range(500, 600)));
	}

	@Test
	public void testCreateVarArgFunction() throws Exception {

		Function f = createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		f.setVarArgs(true);
		assertEquals(true, f.hasVarArgs());
		f.setVarArgs(false);
		assertEquals(false, f.hasVarArgs());
	}

	@Test
	public void testCreateInlineFunction() throws Exception {

		Function f = createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		assertEquals(false, f.isInline());
		f.setInline(true);
		assertEquals(true, f.isInline());
		f.setInline(false);
		assertEquals(false, f.isInline());
	}

	@Test
	public void testCreateNoReturnFunction() throws Exception {

		Function f = createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		assertEquals(false, f.hasNoReturn());
		f.setNoReturn(true);
		assertEquals(true, f.hasNoReturn());
		f.setNoReturn(false);
		assertEquals(false, f.hasNoReturn());
	}

	@Test
	@Ignore("TODO, low priority")
	public void testRemoveFunction() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		Function foo2 = createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		// add stack references and make sure they get removed when the
		// function is deleted
		int transactionIDForTest = program.startTransaction("test");
		AddStackVarCmd cmd = new AddStackVarCmd(foo2.getEntryPoint(), -4, "local_var", null,
			SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(foo2.getEntryPoint(), 4, "param_1", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));

		AddStackRefCmd c = new AddStackRefCmd(b.addr(210), 0, -4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));
		c = new AddStackRefCmd(b.addr(222), 1, 4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));

		program.endTransaction(transactionIDForTest, true);

		Variable[] vars = foo2.getLocalVariables();
		assertEquals(1, vars.length);

		ReferenceManager refMgr = program.getReferenceManager();
		TODO(); // TODO: Need to support variable references
		Reference[] vrefs = refMgr.getReferencesTo(vars[0]);
		assertEquals(1, vrefs.length);
		assertEquals(b.addr(210), vrefs[0].getFromAddress());

		Parameter[] params = foo2.getParameters();
		assertEquals(1, params.length);
		vrefs = refMgr.getReferencesTo(params[0]);
		assertEquals(1, vrefs.length);
		assertEquals(b.addr(222), vrefs[0].getFromAddress());

		functionManager.removeFunction(b.addr(201));

		vrefs = refMgr.getReferencesTo(vars[0]);
		assertEquals(0, vrefs.length);

		vrefs = refMgr.getReferencesTo(params[0]);
		assertEquals(0, vrefs.length);

		Function f = functionManager.getFunctionAt(b.addr(100));
		assertEquals(b.set(b.range(100, 200)), f.getBody());
		assertNull(functionManager.getFunctionAt(b.addr(201)));
		f = functionManager.getFunctionAt(b.addr(250));
		assertEquals(b.set(b.range(250, 350)), f.getBody());

		assertTrue(program.getSymbolTable()
				.getPrimarySymbol(
					b.addr(201))
				.getSymbolType() != SymbolType.FUNCTION);
	}

	@Test
	public void testGetFirstFunctionContaining() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		Function f = functionManager.getFunctionContaining(b.addr(120));
		assertEquals(b.set(b.range(100, 200)), f.getBody());

		f = functionManager.getFunctionContaining(b.addr(240));
		assertTrue(b.set(b.range(201, 249)).equals(f.getBody()));

	}

	@Test
	public void testIsInFunction() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));
		assertTrue(!functionManager.isInFunction(b.addr(95)));
		assertTrue(functionManager.isInFunction(b.addr(100)));
		assertTrue(functionManager.isInFunction(b.addr(250)));
		assertTrue(functionManager.isInFunction(b.addr(240)));
		assertTrue(!functionManager.isInFunction(b.addr(500)));
	}

	@Test
	public void testGetFunctionsContaining() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		Function function = functionManager.getFunctionContaining(b.addr(160));
		assertNotNull(function);
		assertEquals(b.addr(100), function.getEntryPoint());
		function = functionManager.getFunctionContaining(b.addr(50));
		assertNull(function);
		function = functionManager.getFunctionContaining(b.addr(100));
		assertNotNull(function);
		assertEquals(b.addr(100), function.getEntryPoint());

	}

	@Test
	public void testGetFunctionsOverlapping() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		AddressSet set = new AddressSet();
		set.addRange(b.addr(50), b.addr(100));
		set.addRange(b.addr(350), b.addr(500));
		Iterator<Function> iter = functionManager.getFunctionsOverlapping(set);
		assertEquals(b.addr(100), iter.next().getEntryPoint());
		assertEquals(b.addr(250), iter.next().getEntryPoint());
		assertTrue(!iter.hasNext());

		iter = functionManager.getFunctionsOverlapping(b.set(b.range(99, 199)));
		assertEquals(b.addr(100), iter.next().getEntryPoint());
		assertTrue(!iter.hasNext());
	}

	/*
	 * Test for FunctionIterator getFunctions()
	 */
	@Test
	public void testGetFunctions() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

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
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		Function foo2 = createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		program.getMemory().setInt(b.addr(50), 201);
		program.getListing().createData(b.addr(50), PointerDataType.dataType);
		// TODO: It seems this is failing because of a missing inferred reference.
		Reference cheating = program.getReferenceManager()
				.addMemoryReference(b.addr(50),
					b.addr(201), RefType.DATA, SourceType.ANALYSIS, 0);
		// TODO: Remove the explicit reference above and ensure this test still passes
		program.getReferenceManager().setPrimary(cheating, true);
		// TODO: Also remove explit set primary
		assertEquals(foo2, program.getFunctionManager().getReferencedFunction(b.addr(50)));
	}

	/*
	 * Test for FunctionIterator getFunctions(Address)
	 */
	@Test
	public void testGetFunctionsAddress() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		FunctionIterator iter = functionManager.getFunctions(b.addr(125), true);
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
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(250), b.set(b.range(250, 350)));
		createFunction("foo2", b.addr(201), b.set(b.range(201, 249)));

		AddressSet asv = new AddressSet();
		asv.addRange(b.addr(50), b.addr(60));
		asv.addRange(b.addr(70), b.addr(90));
		asv.addRange(b.addr(110), b.addr(160));
		asv.addRange(b.addr(200), b.addr(249));

		FunctionIterator iter = functionManager.getFunctions(asv, true);
		int cnt = 0;
		while (iter.hasNext()) {
			++cnt;
			Function f = iter.next();
			assertEquals(b.set(b.range(201, 249)), f.getBody());
		}
		assertEquals(1, cnt);

	}

	@Test
	public void testFunctionIteratorBackwards() throws Exception {
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(201), b.set(b.range(201, 249)));
		createFunction("foo2", b.addr(250), b.set(b.range(250, 350)));

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
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(201), b.set(b.range(201, 210)));
		createFunction("foo2", b.addr(250), b.set(b.range(250, 350)));

		FunctionIterator iter = functionManager.getFunctions(b.addr(250), false);
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
		createFunction("foo", b.addr(100), b.set(b.range(100, 200)));
		createFunction("foo1", b.addr(201), b.set(b.range(201, 210)));
		createFunction("foo2", b.addr(250), b.set(b.range(250, 350)));

		FunctionIterator iter = functionManager.getFunctions(b.addr(300), false);
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
