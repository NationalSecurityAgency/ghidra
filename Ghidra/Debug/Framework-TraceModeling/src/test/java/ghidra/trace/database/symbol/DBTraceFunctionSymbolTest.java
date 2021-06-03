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
package ghidra.trace.database.symbol;

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import org.junit.*;

import com.google.common.collect.Range;

import ghidra.app.cmd.function.AddRegisterParameterCommand;
import ghidra.app.cmd.function.AddStackVarCmd;
import ghidra.app.cmd.refs.AddStackRefCmd;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.ToyDBTraceBuilder;
import ghidra.trace.database.program.DBTraceProgramView;
import ghidra.trace.model.memory.TraceOverlappedRegionException;
import ghidra.trace.model.symbol.*;
import ghidra.util.IntersectionAddressSetView;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DBTraceFunctionSymbolTest extends AbstractGhidraHeadlessIntegrationTest {
	ToyDBTraceBuilder b;
	TraceFunctionSymbolView functions;
	TraceParameterSymbolView parameters;

	@Before
	public void setUpFunctionTest()
			throws IOException, TraceOverlappedRegionException, DuplicateNameException {
		b = new ToyDBTraceBuilder("Testing", ProgramBuilder._TOY);
		try (UndoableTransaction tid = b.startTransaction()) {
			b.trace.getMemoryManager().createRegion("test", 0, b.range(100, 599));
		}
		functions = b.trace.getSymbolManager().functions();
		parameters = b.trace.getSymbolManager().parameters();
	}

	@After
	public void tearDownFunctionTest() {
		b.close();
	}

	protected TraceFunctionSymbol createTestFunction() throws DuplicateNameException,
			InvalidInputException, IllegalArgumentException, OverlappingFunctionException {
		TraceSymbolManager symbolManager = b.trace.getSymbolManager();
		TraceClassSymbol c = symbolManager.classes()
				.add("MyClass",
					symbolManager.getGlobalNamespace(), SourceType.USER_DEFINED);

		DBTraceProgramView view0 = b.trace.getFixedProgramView(0);
		TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 350)), "foo",
			null, c, SourceType.USER_DEFINED);
		f.updateFunction("__stdcall", //
			new ParameterImpl(null, Undefined4DataType.dataType, view0), List.of( //
				new ParameterImpl("p1", Undefined4DataType.dataType, view0), //
				new ParameterImpl("p2", Undefined2DataType.dataType, view0), //
				new ParameterImpl("p3", Undefined1DataType.dataType, view0), //
				new ParameterImpl("p4", Undefined4DataType.dataType, view0), //
				new ParameterImpl("p5", Undefined2DataType.dataType, view0) //
			), FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED);

		assertFalse(f.hasCustomVariableStorage());
		assertEquals("__stdcall", f.getCallingConventionName());
		assertEquals(5, f.getParameterCount());
		return f;
	}

	protected static void assertParameter(boolean checkStorage, Parameter expected,
			Parameter actual) {
		assertEquals(expected.getName(), actual.getName());
		if (!expected.getDataType().isEquivalent(actual.getDataType())) {
			fail("Expected parameter of type " + expected.getDataType().getName() + ", but got " +
				actual.getDataType().getName());
		}
		if (checkStorage) {
			assertEquals(expected.getVariableStorage(), actual.getVariableStorage());
		}
	}

	protected Parameter createParameter(String name, DataType dt) throws InvalidInputException {
		return new ParameterImpl(name, dt, b.trace.getFixedProgramView(0));
	}

	protected Parameter createParameter(String name, DataType dt, VariableStorage storage)
			throws InvalidInputException {
		return new ParameterImpl(name, dt, storage, b.trace.getFixedProgramView(0));
	}

	protected Parameter createReturn(DataType dt, VariableStorage storage)
			throws InvalidInputException {
		return createParameter(Parameter.RETURN_NAME, dt, storage);
	}

	protected LocalVariable createLocal(String name, DataType dt, int offset)
			throws InvalidInputException {
		return new LocalVariableImpl(name, dt, offset, b.trace.getFixedProgramView(0));
	}

	protected LocalVariable createLocal(String name, int firstUseOffset, DataType dt,
			VariableStorage storage) throws InvalidInputException {
		return new LocalVariableImpl(name, firstUseOffset, dt, storage,
			b.trace.getFixedProgramView(0));
	}

	protected LocalVariable createLocal(String name, int firstUseOffset, DataType dt, Address addr)
			throws InvalidInputException {
		return new LocalVariableImpl(name, firstUseOffset, dt, addr,
			b.trace.getFixedProgramView(0));
	}

	protected VariableStorage createRegStorage(String registerName, int size)
			throws InvalidInputException {
		return new VariableStorage(b.trace.getFixedProgramView(0),
			b.trace.getBaseLanguage().getRegister(registerName).getAddress(), size);
	}

	protected VariableStorage createRegStorage(String registerName) throws InvalidInputException {
		return new VariableStorage(b.trace.getFixedProgramView(0),
			b.trace.getBaseLanguage().getRegister(registerName));
	}

	protected VariableStorage createRegStorage(String registerName, String... more)
			throws InvalidInputException {
		List<Register> regs = new ArrayList<>(1 + more.length);
		regs.add(b.trace.getBaseLanguage().getRegister(registerName));
		for (String rn : more) {
			regs.add(b.trace.getBaseLanguage().getRegister(rn));
		}
		return new VariableStorage(b.trace.getFixedProgramView(0),
			regs.toArray(new Register[regs.size()]));
	}

	protected VariableStorage createStackStorage(int offset, int size)
			throws InvalidInputException {
		return new VariableStorage(b.trace.getFixedProgramView(0), offset, size);
	}

	@Test
	public void testGetName() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			assertEquals("foo", f.getName());
		}
	}

	@Test
	public void testSetNameUser()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			// TODO: Monitor for event
			f.setName("bar", SourceType.USER_DEFINED);
			assertEquals("bar", f.getName());
			assertEquals(SourceType.USER_DEFINED, f.getSource());
			// TODO: Check that event records correct old and new values
		}
	}

	@Test
	public void testSetNameAnalysis()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setName("bar", SourceType.ANALYSIS);
			assertEquals("bar", f.getName());
			assertEquals(SourceType.ANALYSIS, f.getSource());
		}
	}

	@Test
	public void testSetNameImported()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setName("bar", SourceType.IMPORTED);
			assertEquals("bar", f.getName());
			assertEquals(SourceType.IMPORTED, f.getSource());
		}
	}

	@Test
	public void testSetNameDefault()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			String defaultName = SymbolUtilities.getDefaultFunctionName(b.addr(100));
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setName(defaultName, SourceType.DEFAULT);
			assertEquals(defaultName, f.getName());
			assertEquals(SourceType.DEFAULT, f.getSource());
		}
	}

	@Test
	public void testSetNameDefaultError()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			try {
				f.setName("bar", SourceType.DEFAULT);
				fail();
			}
			catch (IllegalArgumentException e) {
				assertEquals("foo", f.getName());
				assertEquals(SourceType.USER_DEFINED, f.getSource());
			}
		}
	}

	@Test
	public void testSetComment() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setComment("Test Comment\nLine 2");
			assertEquals("Test Comment\nLine 2", f.getComment());
			assertArrayEquals(new String[] { "Test Comment", "Line 2" }, f.getCommentAsArray());
			assertNull(f.getRepeatableComment());
		}
	}

	@Test
	public void testSetRepeatable() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setRepeatableComment("Test Comment\nLine 2");
			assertEquals("Test Comment\nLine 2", f.getRepeatableComment());
			assertArrayEquals(new String[] { "Test Comment", "Line 2" },
				f.getRepeatableCommentAsArray());
		}
	}

	@Test
	public void testCreateFunction() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			// TODO: Monitor events
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			assertEquals(Range.atLeast(0L), f.getLifespan());
			assertEquals(b.addr(100), f.getEntryPoint());
			assertEquals(body, f.getBody());
			assertEquals("foo", f.getName());
			assertNull(f.getThunkedFunction(false));
			assertTrue(f.getParentNamespace().isGlobal());
			assertEquals(SourceType.USER_DEFINED, f.getSource());
			// TODO: Check that event record includes the created function (assertSame)
		}
	}

	@Test
	public void testSetBody() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			// TODO: Monitor events
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			body = b.set(b.range(50, 120), b.range(300, 400), b.range(10, 20));
			f.setBody(body);
			assertEquals(body, f.getBody());
			// TODO: Check that event record includes the modified function (assertSame)
		}
	}

	@Test
	public void testSetBodyClearVarRefs()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			DBTraceProgramView view0 = b.trace.getFixedProgramView(0);

			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -4, "local_var", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), 4, "param_1", null,
				SourceType.USER_DEFINED).applyTo(view0));

			assertTrue(
				new AddStackRefCmd(b.addr(210), 0, -4, SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(
				new AddStackRefCmd(b.addr(222), 1, 4, SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(
				new AddStackRefCmd(b.addr(250), 1, -8, SourceType.USER_DEFINED).applyTo(view0));

			TraceVariableSymbol[] vars = f.getLocalVariables();
			assertEquals(2, vars.length);

			TraceReferenceManager refMgr = b.trace.getReferenceManager();

			// TODO: ReferenceManager getReferencesTo(Variable)
			/*
			TraceReference[] vrefs = refMgr.getReferencesTo(0, vars[0]);
			assertEquals(1, vrefs.length);
			assertEquals(b.addr(210), vrefs[0].getFromAddress());
			*/

			for (Address fromAddr : new IntersectionAddressSetView(
				refMgr.getReferenceSources(Range.singleton(0L)), body).getAddresses(true)) {
				Collection<? extends TraceReference> refs = refMgr.getReferencesFrom(0, fromAddr);
				assertEquals(1, refs.size());
			}

			body = b.set(b.range(50, 120), b.range(300, 400), b.range(10, 20));

			f.setBody(body);
			assertEquals(body, f.getBody());

			for (Address fromAddr : new IntersectionAddressSetView(
				refMgr.getReferenceSources(Range.singleton(0L)), body).getAddresses(true)) {
				Collection<? extends TraceReference> refs = refMgr.getReferencesFrom(0, fromAddr);
				assertTrue(refs.isEmpty());
			}
		}
	}

	@Test
	public void testSetBodyClearVarRefsExceptOneInBoth()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			DBTraceProgramView view0 = b.trace.getFixedProgramView(0);

			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -4, "local_var", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), 4, "param_1", null,
				SourceType.USER_DEFINED).applyTo(view0));

			assertTrue(
				new AddStackRefCmd(b.addr(210), 0, -4, SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(
				new AddStackRefCmd(b.addr(222), 1, 4, SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(
				new AddStackRefCmd(b.addr(250), 1, -8, SourceType.USER_DEFINED).applyTo(view0));

			TraceVariableSymbol[] vars = f.getLocalVariables();
			assertEquals(2, vars.length);

			TraceReferenceManager refMgr = b.trace.getReferenceManager();

			// TODO: ReferenceManager getReferencesTo(Variable)
			/*
			TraceReference[] vrefs = refMgr.getReferencesTo(0, vars[0]);
			assertEquals(1, vrefs.length);
			assertEquals(b.addr(210), vrefs[0].getFromAddress());
			*/

			for (Address fromAddr : new IntersectionAddressSetView(
				refMgr.getReferenceSources(Range.singleton(0L)), body).getAddresses(true)) {
				Collection<? extends TraceReference> refs = refMgr.getReferencesFrom(0, fromAddr);
				assertEquals(1, refs.size());
			}

			// NOTE: This time, the old and new bodies intersect where a reference was
			// That reference should remain
			body = b.set(b.range(50, 120), b.range(250, 400), b.range(10, 20));

			f.setBody(body);
			assertEquals(body, f.getBody());

			Collection<TraceReference> refs = new ArrayList<>();
			for (Address fromAddr : new IntersectionAddressSetView(
				refMgr.getReferenceSources(Range.singleton(0L)), body).getAddresses(true)) {
				refs.addAll(refMgr.getReferencesFrom(0, fromAddr));
			}
			assertEquals(1, refs.size());
			TraceReference oneRef = refs.iterator().next();
			assertEquals(b.addr(250), oneRef.getFromAddress());
		}
	}

	@Test
	public void testSetBodyInvalidEntryPoint()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			try {
				f.setBody(b.set(b.range(110, 120), b.range(300, 400), b.range(10, 20)));
				fail();
			}
			catch (IllegalArgumentException e) {
				// Verify it didn't change
				assertEquals(body, f.getBody());
			}
		}
	}

	@Test
	public void testSetBodyOverlapping()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			functions.create(0, b.addr(0), b.set(b.range(0, 50), b.range(75, 90)), "foo2", null,
				null, SourceType.USER_DEFINED);

			try {
				f.setBody(b.set(b.range(50, 120), b.range(300, 400), b.range(10, 20)));
				fail();
			}
			catch (OverlappingFunctionException e) {
				assertEquals(body, f.getBody());
			}

			try {
				f.setBody(b.set(b.range(80, 120), b.range(300, 400), b.range(10, 20)));
				fail();
			}
			catch (OverlappingFunctionException e) {
				assertEquals(body, f.getBody());
			}
		}
	}

	@Test
	public void testSetBodyClearSymbols()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			DBTraceSymbolManager symbolManager = b.trace.getSymbolManager();
			DBTraceLabelSymbolView labels = symbolManager.labels();
			TraceLabelSymbol l1 =
				labels.create(0, null, b.addr(410), "fred", f, SourceType.USER_DEFINED);
			TraceLabelSymbol l2 =
				labels.create(0, null, b.addr(100), "bob", f, SourceType.USER_DEFINED);
			TraceLabelSymbol l3 =
				labels.create(0, null, b.addr(200), "joe", f, SourceType.USER_DEFINED);
			TraceLabelSymbol l4 =
				labels.create(0, null, b.addr(400), "ricky", f, SourceType.USER_DEFINED);

			// Should remove fred and joe
			body = b.set(b.range(10, 20), b.range(50, 120), b.range(300, 400));
			f.setBody(body);
			assertEquals(body, f.getBody());

			assertNull(symbolManager.getSymbolByID(l1.getID()));
			assertSame(l2, symbolManager.getSymbolByID(l2.getID()));
			assertNull(symbolManager.getSymbolByID(l3.getID()));
			assertSame(l4, symbolManager.getSymbolByID(l4.getID()));
		}
	}

	@Test
	public void testGetVariables() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			DBTraceProgramView view0 = b.trace.getFixedProgramView(0);

			assertTrue(new AddStackVarCmd(f.getEntryPoint(), 4, "param_1", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), 8, "param_2", null,
				SourceType.USER_DEFINED).applyTo(view0));

			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -4, "local_var_1", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -8, "local_var_2", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -12, "local_var_3", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -16, "local_var_4", null,
				SourceType.USER_DEFINED).applyTo(view0));
			assertTrue(new AddStackVarCmd(f.getEntryPoint(), -20, "local_var_5", null,
				SourceType.USER_DEFINED).applyTo(view0));

			TraceVariableSymbol[] locals = f.getLocalVariables();
			assertEquals(5, locals.length);
			for (int i = 0; i < locals.length; i++) {
				assertEquals("local_var_" + (i + 1), locals[i].getName());
			}

			Parameter[] params = f.getParameters();
			assertEquals(2, params.length);
			for (int i = 0; i < params.length; i++) {
				assertEquals("param_" + (i + 1), params[i].getName());
			}
		}
	}

	@Test
	public void testGetReturnType() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			assertEquals(DataType.DEFAULT, f.getReturnType());
		}
	}

	@Test
	public void testSetReturnType() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			AddressSetView body = b.set(b.range(100, 350), b.range(400, 450), b.range(500, 550));
			TraceFunctionSymbol f =
				functions.create(0, b.addr(100), body, "foo", null, null, SourceType.USER_DEFINED);

			TraceParameterSymbol ret = f.getReturn();
			assertTrue(Undefined.isUndefined(ret.getDataType()));
			// TODO: Monitor events

			f.setReturnType(ByteDataType.dataType, SourceType.ANALYSIS);
			assertTrue(ByteDataType.dataType.isEquivalent(ret.getDataType()));
			// TODO: Check for expected event
		}
	}

	@Test
	public void testSetCustomStorage() throws DuplicateNameException, InvalidInputException,
			IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = createTestFunction();
			int initialParamCnt = f.getParameterCount();

			Structure bar = new StructureDataType("bar", 20);
			Pointer barPtr = b.trace.getDataTypeManager().getPointer(bar);

			TraceParameterSymbol ret = f.getReturn();
			Parameter p1 = f.getParameter(0);
			Parameter p2 = f.getParameter(1);
			p2.setDataType(bar, SourceType.USER_DEFINED);

			VariableStorage initialRetStorage = ret.getVariableStorage();
			VariableStorage initialP1Storage = p1.getVariableStorage();
			VariableStorage initialP2Storage = p2.getVariableStorage();
			assertTrue(p2.isForcedIndirect());

			assertEquals("r12:4", initialRetStorage.toString());
			assertEquals("r12:4", initialP1Storage.toString());
			assertEquals("r11:4 (ptr)", initialP2Storage.toString());

			f.setCustomVariableStorage(true);

			assertEquals(initialParamCnt, f.getParameterCount());

			ret.setDataType(IntegerDataType.dataType, createRegStorage("r5"), false,
				SourceType.USER_DEFINED);
			assertSame(ret, f.getReturn());
			assertParameter(true, createReturn(IntegerDataType.dataType, createRegStorage("r5")),
				ret);

			p1.setDataType(IntegerDataType.dataType, createRegStorage("r7"), false,
				SourceType.USER_DEFINED);
			assertSame(p1, f.getParameter(0));
			assertParameter(true,
				createParameter("p1", IntegerDataType.dataType, createRegStorage("r7")), p1);

			assertSame(p2, f.getParameter(1));
			assertParameter(false,
				createParameter("p2", barPtr, VariableStorage.UNASSIGNED_STORAGE), p2);
			assertFalse(p2.isForcedIndirect());

			f.setCustomVariableStorage(false);

			assertSame(ret, f.getReturn());
			assertParameter(true, createReturn(IntegerDataType.dataType, initialRetStorage), ret);

			assertSame(p1, f.getParameter(0));
			assertParameter(true, createParameter("p1", IntegerDataType.dataType, initialP1Storage),
				p1);

			assertSame(p2, f.getParameter(1));
			/**
			 * NOTE: Could not use createParmater. initialP2Storage is still forcedIndirect, but its
			 * new storage is not. Just check the type directly.
			 */
			assertTrue(barPtr.isEquivalent(p2.getDataType()));
			assertFalse(p2.isForcedIndirect());
		}
	}

	@Test
	public void testSetCallingConvention() throws DuplicateNameException, InvalidInputException,
			IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = createTestFunction();

			int initialParamCnt = f.getParameterCount();

			Structure bar = new StructureDataType("bar", 20);
			Pointer barPtr = b.trace.getDataTypeManager().getPointer(bar);

			Parameter returnVar = f.getReturn();
			Parameter p1 = f.getParameter(0);
			Parameter p2 = f.getParameter(1);
			p2.setDataType(bar, SourceType.USER_DEFINED);

			VariableStorage initialReturnStorage = f.getReturn().getVariableStorage();
			VariableStorage initialP1Storage = f.getParameter(0).getVariableStorage();

			assertEquals("p1", p1.getName());
			assertEquals("p2", p2.getName());

			assertEquals(0, p1.getOrdinal());
			assertEquals(1, p2.getOrdinal());

			assertEquals("r12:4", initialReturnStorage.toString());
			assertEquals("r12:4", initialP1Storage.toString());
			assertEquals("r11:4 (ptr)", p2.getVariableStorage().toString());

			assertTrue(p1.getDataType().isEquivalent(Undefined4DataType.dataType));
			assertTrue(p2.getDataType().isEquivalent(barPtr));

			// switch to __stackcall

			f.setCallingConvention("__stackcall");
			assertEquals("__stackcall", f.getCallingConventionName());
			assertEquals(initialParamCnt, f.getParameterCount());

			assertEquals("p1", p1.getName());
			assertEquals("p2", p2.getName());

			assertEquals(0, p1.getOrdinal());
			assertEquals(1, p2.getOrdinal());

			// TODO: need better test of return storage - no change in spec storage
			assertEquals(createRegStorage("r12"), returnVar.getVariableStorage());
			assertEquals(createStackStorage(4, 4), p1.getVariableStorage());
			assertEquals(createStackStorage(8, 20), p2.getVariableStorage());

			assertTrue(p1.getDataType().isEquivalent(Undefined4DataType.dataType));
			assertTrue(p2.getDataType().isEquivalent(bar));

			f.setCallingConvention("__stdcall");
			assertEquals("__stdcall", f.getCallingConventionName());
			assertEquals(initialParamCnt, f.getParameterCount());

			assertEquals("p1", f.getParameter(0).getName());
			assertEquals("p2", f.getParameter(1).getName());

			assertEquals(0, p1.getOrdinal());
			assertEquals(1, p2.getOrdinal());

			assertEquals(initialReturnStorage, returnVar.getVariableStorage());// TODO: need better test - no change
			assertEquals(initialP1Storage, p1.getVariableStorage());
			assertEquals("r11:4 (ptr)", p2.getVariableStorage().toString());

			assertTrue(p1.getDataType().isEquivalent(Undefined4DataType.dataType));
			assertTrue(p2.getDataType().isEquivalent(barPtr));

			// switch to __thiscall

			f.setCallingConvention("__thiscall");
			assertEquals("__thiscall", f.getCallingConventionName());
			assertEquals(initialParamCnt + 1, f.getParameterCount());

			Parameter thisParam = f.getParameter(0);
			assertEquals(1, p1.getOrdinal());
			assertEquals(2, p2.getOrdinal());

			p1 = f.getParameter(1);
			p2 = f.getParameter(2);

			assertEquals("this", thisParam.getName());
			assertEquals("p1", p1.getName());
			assertEquals("p2", p2.getName());

			assertEquals(initialReturnStorage, returnVar.getVariableStorage());// TODO: need better test - no change
			assertEquals("r12:4 (auto)", thisParam.getVariableStorage().toString());
			assertEquals("r11:4", p1.getVariableStorage().toString());
			assertEquals("r10:4 (ptr)", p2.getVariableStorage().toString());

			// the "this" param data type will be an empty unresolved Class structure
			// if it did not already exist
			String namespaceName = f.getSymbol().getParentNamespace().getName();
			DataType namespaceStruct = new StructureDataType(namespaceName, 0);
			Pointer structPtr = b.trace.getDataTypeManager().getPointer(namespaceStruct);

			assertTrue(thisParam.getDataType().isEquivalent(structPtr));
			assertTrue(p1.getDataType().isEquivalent(Undefined4DataType.dataType));
			assertTrue(p2.getDataType().isEquivalent(barPtr));
		}
	}

	@Test
	public void testUpdateFunctionCustomStorage() throws DuplicateNameException,
			InvalidInputException, IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			Function f = createTestFunction();

			Structure bigStruct = new StructureDataType("bigStruct", 20);

			Parameter returnVar =
				createReturn(new PointerDataType(bigStruct), createRegStorage("r6"));

			Parameter p1 = createParameter(Function.RETURN_PTR_PARAM_NAME,
				new PointerDataType(bigStruct), createRegStorage("r7"));
			Parameter p2 =
				createParameter("m2", LongLongDataType.dataType, createRegStorage("r12", "r11"));
			Parameter p3 = createParameter("m3", ByteDataType.dataType, createRegStorage("r9", 1));

			f.updateFunction("__stdcall", returnVar, FunctionUpdateType.CUSTOM_STORAGE, true,
				SourceType.USER_DEFINED, p1, p2, p3);

			assertTrue(f.hasCustomVariableStorage());
			assertEquals("__stdcall", f.getCallingConventionName());

			Parameter return1 = f.getReturn();
			assertParameter(true, returnVar, return1);
			assertEquals("r6:4", return1.getVariableStorage().toString());

			Parameter[] params = f.getParameters();
			assertEquals(3, params.length);

			assertParameter(true, p1, params[0]);
			assertParameter(true, p2, params[1]);
			assertParameter(true, p3, params[2]);
		}

	}

	@Test
	public void testUpdateFunctionDynamicStorage() throws DuplicateNameException,
			InvalidInputException, IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			Function f = createTestFunction();

			Structure bigStruct = new StructureDataType("bigStruct", 20);

			Parameter returnVar = createReturn(bigStruct, VariableStorage.UNASSIGNED_STORAGE);

			Parameter p1 = createParameter(Function.RETURN_PTR_PARAM_NAME,
				new PointerDataType(bigStruct), createRegStorage("r7"));
			Structure classStruct = VariableUtilities.findOrCreateClassStruct(f);
			Parameter p2 = createParameter(Function.THIS_PARAM_NAME,
				new PointerDataType(classStruct), createRegStorage("r8"));
			Parameter p3 =
				createParameter("m2", LongLongDataType.dataType, createRegStorage("r12", "r11"));
			Parameter p4 = createParameter("m3", ByteDataType.dataType, createRegStorage("r9"));

			// function updated with formal signature
			f.updateFunction("__thiscall", returnVar, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, SourceType.USER_DEFINED, p3, p4);

			assertTrue(!f.hasCustomVariableStorage());
			assertEquals("__thiscall", f.getCallingConventionName());

			Parameter return1 = f.getReturn();
			assertTrue(return1.isForcedIndirect());
			assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
			assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
			assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

			Parameter[] params = f.getParameters();
			assertEquals(4, params.length);

			assertParameter(false, p1, params[0]);
			assertEquals(0, params[0].getOrdinal());
			assertEquals("r12:4 (auto)", params[0].getVariableStorage().toString());
			assertParameter(false, p2, params[1]);
			assertEquals(1, params[1].getOrdinal());
			assertEquals("r11:4 (auto)", params[1].getVariableStorage().toString());
			assertParameter(false, p3, params[2]);
			assertEquals(2, params[2].getOrdinal());
			assertEquals("Stack[0x0]:8", params[2].getVariableStorage().toString());
			assertParameter(false, p4, params[3]);
			assertEquals(3, params[3].getOrdinal());
			assertEquals("r10l:1", params[3].getVariableStorage().toString());
		}
	}

	@Test
	public void testUpdateFunctionDynamicStorage1() throws DuplicateNameException,
			InvalidInputException, IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			Function f = createTestFunction();

			Structure bigStruct = new StructureDataType("bigStruct", 20);

			Parameter returnVar =
				createReturn(new PointerDataType(bigStruct), VariableStorage.UNASSIGNED_STORAGE);

			Parameter p1 = createParameter(Function.RETURN_PTR_PARAM_NAME,
				new PointerDataType(bigStruct), createRegStorage("r7"));
			Structure classStruct = VariableUtilities.findOrCreateClassStruct(f);
			Parameter p2 = createParameter(Function.THIS_PARAM_NAME,
				new PointerDataType(classStruct), createRegStorage("r8"));
			Parameter p3 =
				createParameter("m2", LongLongDataType.dataType, createRegStorage("r12", "r11"));
			Parameter p4 = createParameter("m3", ByteDataType.dataType, createRegStorage("r9"));

			// function updated with auto parameters
			f.updateFunction("__thiscall", returnVar, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, SourceType.USER_DEFINED, p1, p2, p3, p4);

			assertFalse(f.hasCustomVariableStorage());
			assertEquals("__thiscall", f.getCallingConventionName());

			Parameter return1 = f.getReturn();
			assertTrue(return1.isForcedIndirect());
			assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
			assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
			assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

			Parameter[] params = f.getParameters();
			assertEquals(4, params.length);

			assertParameter(false, p1, params[0]);
			assertEquals(0, params[0].getOrdinal());
			assertEquals("r12:4 (auto)", params[0].getVariableStorage().toString());
			assertParameter(false, p2, params[1]);
			assertEquals(1, params[1].getOrdinal());
			assertEquals("r11:4 (auto)", params[1].getVariableStorage().toString());
			assertParameter(false, p3, params[2]);
			assertEquals(2, params[2].getOrdinal());
			assertEquals("Stack[0x0]:8", params[2].getVariableStorage().toString());
			assertParameter(false, p4, params[3]);
			assertEquals(3, params[3].getOrdinal());
			assertEquals("r10l:1", params[3].getVariableStorage().toString());
		}
	}

	@Test
	public void testUpdateFunctionDynamicStorage2() throws DuplicateNameException,
			InvalidInputException, IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			Function f = createTestFunction();

			Structure bigStruct = new StructureDataType("bigStruct", 20);

			Parameter returnVar =
				createReturn(new PointerDataType(bigStruct), VariableStorage.UNASSIGNED_STORAGE);

			Parameter p1 = createParameter(Function.RETURN_PTR_PARAM_NAME,
				new PointerDataType(bigStruct), createRegStorage("r7"));
			Parameter p2 =
				createParameter("m2", LongLongDataType.dataType, createRegStorage("r12", "r11"));
			Parameter p3 = createParameter("m3", ByteDataType.dataType, createRegStorage("r9"));

			f.updateFunction("__thiscall", returnVar, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, SourceType.USER_DEFINED, p1, p2, p3);

			assertTrue(!f.hasCustomVariableStorage());
			assertEquals("__thiscall", f.getCallingConventionName());

			Parameter return1 = f.getReturn();
			assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
			assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
			assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

			Parameter[] params = f.getParameters();
			assertEquals(4, params.length);

			Structure classStruct = VariableUtilities.findOrCreateClassStruct(f);

			Parameter thisParam = createParameter(Function.THIS_PARAM_NAME,
				new PointerDataType(classStruct), VariableStorage.UNASSIGNED_STORAGE);

			assertParameter(false, p1, params[0]);
			assertEquals("r12:4 (auto)", params[0].getVariableStorage().toString());
			assertParameter(false, thisParam, params[1]);
			assertEquals("r11:4 (auto)", params[1].getVariableStorage().toString());
			assertParameter(false, p2, params[2]);
			assertEquals("Stack[0x0]:8", params[2].getVariableStorage().toString());
			assertParameter(false, p3, params[3]);
			assertEquals("r10l:1", params[3].getVariableStorage().toString());

			// try again with DB params

			f.updateFunction("__thiscall", f.getReturn(),
				FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true, SourceType.USER_DEFINED,
				f.getParameters());

			assertTrue(!f.hasCustomVariableStorage());
			assertEquals("__thiscall", f.getCallingConventionName());

			return1 = f.getReturn();
			assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
			assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
			assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

			params = f.getParameters();
			assertEquals(4, params.length);

			assertParameter(false, p1, params[0]);
			assertEquals(0, params[0].getOrdinal());
			assertEquals("r12:4 (auto)", params[0].getVariableStorage().toString());
			assertParameter(false, thisParam, params[1]);
			assertEquals(1, params[1].getOrdinal());
			assertEquals("r11:4 (auto)", params[1].getVariableStorage().toString());
			assertParameter(false, p2, params[2]);
			assertEquals(2, params[2].getOrdinal());
			assertEquals("Stack[0x0]:8", params[2].getVariableStorage().toString());
			assertParameter(false, p3, params[3]);
			assertEquals(3, params[3].getOrdinal());
			assertEquals("r10l:1", params[3].getVariableStorage().toString());

			// try again with DB params and custom storage

			f.updateFunction("__thiscall", f.getReturn(), FunctionUpdateType.CUSTOM_STORAGE, true,
				SourceType.USER_DEFINED, f.getParameters());

			assertTrue(f.hasCustomVariableStorage());
			assertEquals("__thiscall", f.getCallingConventionName());

			return1 = f.getReturn();
			assertParameter(false, returnVar, return1);
			assertEquals("r12:4", return1.getVariableStorage().toString());

			params = f.getParameters();
			assertEquals(4, params.length);

			assertParameter(false, p1, params[0]);
			assertEquals(0, params[0].getOrdinal());
			assertEquals("r12:4", params[0].getVariableStorage().toString());
			assertParameter(false, thisParam, params[1]);
			assertEquals(1, params[1].getOrdinal());
			assertEquals("r11:4", params[1].getVariableStorage().toString());
			assertParameter(false, p2, params[2]);
			assertEquals(2, params[2].getOrdinal());
			assertEquals("Stack[0x0]:8", params[2].getVariableStorage().toString());
			assertParameter(false, p3, params[3]);
			assertEquals(3, params[3].getOrdinal());
			assertEquals("r10l:1", params[3].getVariableStorage().toString());
		}
	}

	@Test
	public void testAutoAddingRemovingThisParameter() throws DuplicateNameException,
			InvalidInputException, IllegalArgumentException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			TraceFunctionSymbol f = createTestFunction();
			assertEquals(5, f.getParameters().length);

			assertNull(parameters.getChildNamed("this", f));

			f.setCallingConvention("__thiscall");
			assertEquals(6, f.getParameters().length);
			assertEquals("this", f.getParameter(0).getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			assertNull(parameters.getChildNamed("this", f));

			f.setCallingConvention("__stdcall");
			assertEquals(5, f.getParameters().length);
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(0).getDataType()));

			assertNull(parameters.getChildNamed("this", f));

			f.setCallingConvention("__thiscall");
			assertEquals(6, f.getParameters().length);
			Parameter param = f.getParameter(0);
			assertTrue(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			assertNull(parameters.getChildNamed("this", f));

			f.setCustomVariableStorage(true);

			assertNotNull(parameters.getChildNamed("this", f));

			assertEquals(6, f.getParameters().length);
			param = f.getParameter(0);
			assertFalse(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			f.setCustomVariableStorage(false);

			assertNull(parameters.getChildNamed("this", f));

			assertEquals(6, f.getParameters().length);
			param = f.getParameter(0);
			assertTrue(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			f.setCustomVariableStorage(true);

			assertNotNull(parameters.getChildNamed("this", f));

			assertEquals(6, f.getParameters().length);
			param = f.getParameter(0);
			assertFalse(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			f.setCallingConvention("__stdcall");
			assertEquals(6, f.getParameters().length);
			param = f.getParameter(0);
			assertFalse(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			f.setCustomVariableStorage(false);

			assertNotNull(parameters.getChildNamed("this", f));

			assertEquals(6, f.getParameters().length);
			param = f.getParameter(0);
			assertFalse(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			f.setCallingConvention("__thiscall");

			assertNull(parameters.getChildNamed("this", f));

			assertEquals(6, f.getParameters().length);
			param = f.getParameter(0);
			assertTrue(param.isAutoParameter());
			assertEquals(Function.THIS_PARAM_NAME, param.getName());
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

			f.setCallingConvention("__stdcall");
			assertEquals(5, f.getParameters().length);
			assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(0).getDataType()));
		}
	}

	/*
	 * Test for String getSignature(String)
	 */
	@Test
	public void testGetSignatureString()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			Structure s = new StructureDataType("bar", 20);
			f.setReturnType(s, SourceType.ANALYSIS);
			Parameter p = f.addParameter(createParameter("p1", s), SourceType.IMPORTED);

			assertEquals("bar foo(bar p1)", f.getPrototypeString(true, false));
			assertEquals("bar foo(bar p1)", f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, bar * p1)",
				f.getPrototypeString(false, false));
			assertEquals("bar * foo(bar * __return_storage_ptr__, bar * p1)",
				f.getPrototypeString(false, true));

			f.setCallingConvention("__thiscall");

			assertEquals("bar foo(bar p1)", f.getPrototypeString(true, false));
			assertEquals("bar __thiscall foo(bar p1)", f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, false));
			assertEquals(
				"bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, true));

			f.removeVariable(p);

			assertEquals("bar foo(void)", f.getPrototypeString(true, false));
			assertEquals("bar __thiscall foo(void)", f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, void * this)",
				f.getPrototypeString(false, false));
			assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this)",
				f.getPrototypeString(false, true));

			p = f.addParameter(createParameter("p1", s), SourceType.ANALYSIS);

			assertEquals("bar foo(bar p1)", f.getPrototypeString(true, false));
			assertEquals("bar __thiscall foo(bar p1)", f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, false));
			assertEquals(
				"bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, true));

			f.setCustomVariableStorage(true);

			assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(true, false));
			assertEquals(
				"bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, false));
			assertEquals(
				"bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, true));

			f.setCustomVariableStorage(false);

			// forced-indirect round trip not supported for parameter
			assertEquals("bar foo(bar * p1)", f.getPrototypeString(true, false));
			assertEquals("bar __thiscall foo(bar * p1)", f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, false));
			assertEquals(
				"bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
				f.getPrototypeString(false, true));

			p.setDataType(s, SourceType.ANALYSIS);
			f.setCallingConvention("__stackcall");

			assertEquals("bar foo(bar p1)", f.getPrototypeString(true, false));
			assertEquals("bar __stackcall foo(bar p1)", f.getPrototypeString(true, true));
			assertEquals("bar * foo(bar * __return_storage_ptr__, bar p1)",
				f.getPrototypeString(false, false));
			assertEquals("bar * __stackcall foo(bar * __return_storage_ptr__, bar p1)",
				f.getPrototypeString(false, true));
		}
	}

	@Test
	@Ignore("TODO")
	public void testDataTypeOnRegisterVariable()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			Register r7l = b.trace.getBaseLanguage().getRegister("r7l");
			assertNotNull(r7l);

			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			DataType dt;

			// TODO: Monitor events

			try (UndoableTransaction localTid = b.startTransaction()) {
				DataType bdt = b.trace.getDataTypeManager()
						.addDataType(ByteDataType.dataType,
							DataTypeConflictHandler.DEFAULT_HANDLER);
				dt = new TypedefDataType("byteTD", bdt);
				dt = b.trace.getDataTypeManager()
						.addDataType(dt,
							DataTypeConflictHandler.DEFAULT_HANDLER);
				AddRegisterParameterCommand cmd = new AddRegisterParameterCommand(f, r7l,
					"reg_param_0", dt, 0, SourceType.USER_DEFINED);
				cmd.applyTo(b.trace.getFixedProgramView(0));
			}

			// TODO: Check for expected event

			Parameter[] params = f.getParameters();
			assertEquals(1, params.length);

			Parameter rp = params[0];
			assertEquals(dt, rp.getDataType());
			assertEquals(r7l, rp.getRegister());

			// delete the typedef data type
			try (UndoableTransaction localTid = b.startTransaction()) {
				b.trace.getDataTypeManager().remove(dt, TaskMonitor.DUMMY);
			}

			params = f.getParameters();
			assertEquals(1, params.length);
			assertTrue(params[0].isRegisterVariable());
			TODO(); // TODO: SymbolManager must process type deletion
			assertEquals(Undefined1DataType.dataType, params[0].getDataType());
			assertEquals(r7l, params[0].getRegister());
		}
	}

	@Test
	public void testSetStackDepthChange()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);

			// TODO: Monitor events

			f.setStackPurgeSize(20);
			assertEquals(20, f.getStackPurgeSize());

			// TODO: Check for expected event
		}
	}

	@Test
	public void testSetStackParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);
			f.setCallingConvention("__stackcall");

			DataType[] dt =
				new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

			LocalVariable stackVar = createLocal("TestStack0", dt[0], 4);
			stackVar.setComment("My Comment0");

			// TODO: Monitor events

			// causes both symbol created and function change events
			f.addParameter(stackVar, SourceType.USER_DEFINED);

			// TODO: Check for expected event

			stackVar = createLocal("TestStack1", dt[1], 8);
			stackVar.setComment("My Comment1");

			// causes both symbol created and function change events
			f.addParameter(stackVar, SourceType.USER_DEFINED);

			// TODO: Check for expected event

			stackVar = createLocal("TestStack2", dt[2], 12);
			stackVar.setComment("My Comment2");
			f.addParameter(stackVar, SourceType.USER_DEFINED);

			Parameter[] params = f.getParameters();
			assertEquals(3, params.length);
			for (int i = 0; i < 3; i++) {
				Parameter param = params[i];
				assertTrue(param.isStackVariable());
				int stackOffset = param.getStackOffset();
				assertEquals("TestStack" + i, param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + i, param.getComment());
				assertEquals(f, param.getFunction());
				assertEquals((i * 4) + 4, stackOffset);
				assertTrue(dt[i].isEquivalent(param.getDataType()));
			}

			f.setCustomVariableStorage(false);

			params = f.getParameters();
			assertEquals(3, params.length);
			int[] stackOffsets = new int[] { 7, 10, 14 };
			for (int i = 0; i < 3; i++) {
				Parameter param = params[i];
				assertTrue(param.isStackVariable());
				int stackOffset = param.getStackOffset();
				assertEquals("TestStack" + i, param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + i, param.getComment());
				assertEquals(f, param.getFunction());
				assertEquals(stackOffsets[i], stackOffset);
				assertTrue(dt[i].isEquivalent(param.getDataType()));
			}
		}
	}

	@Test
	public void testSetDuplicateStackParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			DataType[] dt =
				new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

			LocalVariable stackVar = createLocal("TestStack0", dt[0], 4);
			stackVar.setComment("My Comment0");
			f.addParameter(stackVar, SourceType.USER_DEFINED);
			stackVar = createLocal("TestStack1", dt[1], 8);
			stackVar.setComment("My Comment1");
			f.addParameter(stackVar, SourceType.USER_DEFINED);
			stackVar = createLocal("TestStack2", dt[2], 4);// duplicate stack offset
			stackVar.setComment("My Comment2");
			f.addParameter(stackVar, SourceType.USER_DEFINED);

			Parameter[] params = f.getParameters();
			assertEquals(2, params.length);
			assertTrue(params[0].isStackVariable());
			assertTrue(params[1].isStackVariable());
			assertEquals(8, params[0].getStackOffset());
			assertEquals(4, params[1].getStackOffset());
			for (int i = 0; i < 2; i++) {
				int n = i + 1;
				Parameter param = params[i];
				assertEquals("TestStack" + n, param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + n, param.getComment());
				assertEquals(f, param.getFunction());
				assertTrue(dt[n].isEquivalent(param.getDataType()));
			}
		}
	}

	@Test
	public void testSetStackVariable()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);

			DataType[] dt =
				new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

			LocalVariable stackVar = createLocal("TestStack0", dt[0], -4);
			stackVar.setComment("My Comment0");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
			stackVar = createLocal("TestStack1", dt[1], -8);
			stackVar.setComment("My Comment1");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
			stackVar = createLocal("TestStack2", dt[2], -12);
			stackVar.setComment("My Comment2");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

			Variable[] vars = f.getLocalVariables();
			assertEquals(3, vars.length);
			for (int i = 0; i < 3; i++) {
				Variable var = vars[i];
				assertTrue(var.isStackVariable());
				assertEquals("TestStack" + i, var.getName());
				assertEquals(0, var.getFirstUseOffset());
				assertEquals("My Comment" + i, var.getComment());
				assertEquals(f, var.getFunction());
				assertEquals(-(i * 4) - 4, var.getStackOffset());
				assertTrue(dt[i].isEquivalent(var.getDataType()));
			}
		}
	}

	@Test
	public void testSetStackVariableOverwrite()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);

			Structure dt =
				b.trace.getDataTypeManager().addType(new StructureDataType("Struct1", 0), null);

			LocalVariable stackVar = createLocal("TestStack0", dt, -8);
			stackVar.setComment("My Comment0");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

			// TODO: Argue for overrides on clone to more specific type
			dt = dt.clone(b.trace.getDataTypeManager());
			dt.add(WordDataType.dataType);

			stackVar = createLocal("TestStack2", dt, -8);
			stackVar.setComment("My Comment2");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

			Variable[] vars = f.getLocalVariables();
			assertEquals(1, vars.length);

			Variable var = vars[0];
			assertTrue(var.isStackVariable());
			assertEquals("TestStack2", var.getName());
			assertEquals(0, var.getFirstUseOffset());
			assertEquals("My Comment2", var.getComment());
			assertEquals(f, var.getFunction());
			assertEquals(-8, var.getStackOffset());
			assertTrue(dt.isEquivalent(var.getDataType()));
		}
	}

	@Test
	public void testSetDuplicateStackVariable()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);

			DataType[] dt =
				new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

			LocalVariable stackVar = createLocal("TestStack0", dt[0], -4);
			stackVar.setComment("My Comment0");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
			stackVar = createLocal("TestStack1", dt[1], -8);
			stackVar.setComment("My Comment1");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
			stackVar = createLocal("TestStack2", dt[2], -4);// duplicate stack offset
			stackVar.setComment("My Comment2");
			f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

			Variable[] vars = f.getLocalVariables();
			assertEquals(2, vars.length);
			assertTrue(vars[0].isStackVariable());
			assertTrue(vars[1].isStackVariable());
			assertEquals(-4, vars[0].getStackOffset());
			assertEquals(-8, vars[1].getStackOffset());
			for (int i = 0; i < 2; i++) {
				int n = 2 - i;
				Variable var = vars[i];
				assertEquals("TestStack" + n, var.getName());
				assertEquals(0, var.getFirstUseOffset());
				assertEquals("My Comment" + n, var.getComment());
				assertEquals(f, var.getFunction());
				assertTrue(dt[n].isEquivalent(var.getDataType()));
			}
		}
	}

	@Test
	public void testSetRegisterParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			LocalVariable regVar =
				createLocal("TestReg0", 0, ByteDataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment0");
			f.addParameter(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg1", 0, WordDataType.dataType, createRegStorage("r2"));
			regVar.setComment("My Comment1");
			f.addParameter(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg2", 0, Pointer16DataType.dataType, createRegStorage("r3"));
			regVar.setComment("My Comment2");
			f.addParameter(regVar, SourceType.USER_DEFINED);

			Parameter[] params = f.getParameters();
			assertEquals(3, params.length);
			for (int i = 0; i < 3; i++) {
				Parameter param = params[i];
				assertTrue(param.isRegisterVariable());
				assertEquals("TestReg" + i, param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + i, param.getComment());
				assertEquals(f, param.getFunction());
				assertEquals("r" + (i + 1) + "l", param.getRegister().getName());
			}
			assertTrue(ByteDataType.dataType.isEquivalent(params[0].getDataType()));
			assertTrue(WordDataType.dataType.isEquivalent(params[1].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(params[2].getDataType()));
		}
	}

	@Test
	public void testSetDuplicateRegisterParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			LocalVariable regVar =
				createLocal("TestReg0", 0, ByteDataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment0");
			f.addParameter(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg1", 0, WordDataType.dataType, createRegStorage("r2"));
			regVar.setComment("My Comment1");
			f.addParameter(regVar, SourceType.USER_DEFINED);
			// NOTE: This next is r1 instead of r3
			regVar = createLocal("TestReg2", 0, Pointer16DataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment2");
			f.addParameter(regVar, SourceType.USER_DEFINED);

			Parameter[] params = f.getParameters();
			assertEquals(2, params.length);
			for (int i = 0; i < 2; i++) {
				Parameter param = params[i];
				assertTrue(param.isRegisterVariable());
				assertEquals("TestReg" + (i + 1), param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + (i + 1), param.getComment());
				assertEquals(f, param.getFunction());
				assertEquals("r" + (2 - i) + "l", param.getRegister().getName());
			}
			assertTrue(WordDataType.dataType.isEquivalent(params[0].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(params[1].getDataType()));
		}
	}

	@Test
	public void testSetRegisterVariable()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);

			LocalVariable regVar =
				createLocal("TestReg0", 0, ByteDataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment0");
			f.addLocalVariable(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg1", 4, WordDataType.dataType, createRegStorage("r2"));
			regVar.setComment("My Comment1");
			f.addLocalVariable(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg2", 8, Pointer16DataType.dataType, createRegStorage("r3"));
			regVar.setComment("My Comment2");
			f.addLocalVariable(regVar, SourceType.USER_DEFINED);

			Variable[] vars = f.getLocalVariables();
			assertEquals(3, vars.length);
			Arrays.sort(vars);
			for (int i = 0; i < 3; i++) {
				Variable var = vars[i];
				assertTrue(var.isRegisterVariable());
				assertEquals("TestReg" + i, var.getName());
				assertEquals(i * 4, var.getFirstUseOffset());
				assertEquals("My Comment" + i, var.getComment());
				assertEquals(f, var.getFunction());
				assertEquals("r" + (i + 1) + "l", var.getRegister().getName());
			}
			assertTrue(ByteDataType.dataType.isEquivalent(vars[0].getDataType()));
			assertTrue(WordDataType.dataType.isEquivalent(vars[1].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(vars[2].getDataType()));
		}
	}

	@Test
	public void testSetDuplicateRegisterVariable()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);

			LocalVariable regVar =
				createLocal("TestReg0", 4, ByteDataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment0");
			f.addLocalVariable(regVar, SourceType.USER_DEFINED);
			// NOTE: This next one is r1 instead of r2
			regVar = createLocal("TestReg1", 4, WordDataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment1");
			f.addLocalVariable(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg2", 8, Pointer16DataType.dataType, createRegStorage("r3"));
			regVar.setComment("My Comment2");
			f.addLocalVariable(regVar, SourceType.USER_DEFINED);

			Variable[] vars = f.getLocalVariables();
			assertEquals(2, vars.length);
			for (int i = 0; i < 2; i++) {
				Variable var = vars[i];
				assertTrue(var.isRegisterVariable());
				assertEquals("TestReg" + (i + 1), var.getName());
				assertEquals((i + 1) * 4, var.getFirstUseOffset());
				assertEquals("My Comment" + (i + 1), var.getComment());
				assertEquals(f, var.getFunction());
				assertEquals("r" + (i * 2 + 1) + "l", var.getRegister().getName());
			}
			assertTrue(WordDataType.dataType.isEquivalent(vars[0].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(vars[1].getDataType()));
		}
	}

	@Test
	public void testSetMemoryParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			LocalVariable memVar = createLocal("TestMem0", 0, ByteDataType.dataType, b.addr(0));
			memVar.setComment("My Comment0");
			f.addParameter(memVar, SourceType.USER_DEFINED);
			memVar = createLocal("TestMem1", 0, WordDataType.dataType, b.addr(4));
			memVar.setComment("My Comment1");
			f.addParameter(memVar, SourceType.USER_DEFINED);
			memVar = createLocal("TestMem2", 0, Pointer16DataType.dataType, b.addr(8));
			memVar.setComment("My Comment2");
			f.addParameter(memVar, SourceType.USER_DEFINED);

			Parameter[] params = f.getParameters();
			assertEquals(3, params.length);
			for (int i = 0; i < 3; i++) {
				Parameter param = params[i];
				assertTrue(param.isMemoryVariable());
				assertEquals("TestMem" + i, param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + i, param.getComment());
				assertEquals(f, param.getFunction());
				assertEquals(b.addr(i * 4), param.getMinAddress());
			}
			assertTrue(ByteDataType.dataType.isEquivalent(params[0].getDataType()));
			assertTrue(WordDataType.dataType.isEquivalent(params[1].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(params[2].getDataType()));
		}
	}

	@Test
	public void testSetDuplicateMemoryParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			LocalVariable memVar = createLocal("TestMem0", 0, ByteDataType.dataType, b.addr(0));
			memVar.setComment("My Comment0");
			f.addParameter(memVar, SourceType.USER_DEFINED);
			memVar = createLocal("TestMem1", 0, WordDataType.dataType, b.addr(4));
			memVar.setComment("My Comment1");
			f.addParameter(memVar, SourceType.USER_DEFINED);
			memVar = createLocal("TestMem2", 0, Pointer16DataType.dataType, b.addr(0));
			memVar.setComment("My Comment2");
			f.addParameter(memVar, SourceType.USER_DEFINED);

			Parameter[] params = f.getParameters();
			assertEquals(2, params.length);
			assertTrue(params[0].isMemoryVariable());
			assertTrue(params[1].isMemoryVariable());
			assertEquals(b.addr(4), params[0].getMinAddress());
			assertEquals(b.addr(0), params[1].getMinAddress());
			for (int i = 0; i < 2; i++) {
				Parameter param = params[i];
				assertEquals("TestMem" + (i + 1), param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + (i + 1), param.getComment());
				assertEquals(f, param.getFunction());
			}
			assertTrue(WordDataType.dataType.isEquivalent(params[0].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(params[1].getDataType()));
		}
	}

	@Test
	public void testRemoveRegisterParameter()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {
			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			f.setCustomVariableStorage(true);

			LocalVariable regVar =
				createLocal("TestReg0", 0, ByteDataType.dataType, createRegStorage("r1"));
			regVar.setComment("My Comment0");
			f.addParameter(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg1", 0, WordDataType.dataType, createRegStorage("r2"));
			regVar.setComment("My Comment1");
			f.addParameter(regVar, SourceType.USER_DEFINED);
			regVar = createLocal("TestReg2", 0, Pointer16DataType.dataType, createRegStorage("r3"));
			regVar.setComment("My Comment2");
			f.addParameter(regVar, SourceType.USER_DEFINED);

			// TODO: Change to update?
			f.removeParameter(1);

			Parameter[] params = f.getParameters();
			assertEquals(2, params.length);
			for (int i = 0; i < 2; i++) {
				Parameter param = params[i];
				assertTrue(param.isRegisterVariable());
				assertEquals("TestReg" + (2 * i), param.getName());
				assertEquals(i, param.getOrdinal());
				assertEquals("My Comment" + (2 * i), param.getComment());
				assertEquals(f, param.getFunction());
				assertEquals("r" + (2 * i + 1) + "l", param.getRegister().getName());
			}
			assertTrue(ByteDataType.dataType.isEquivalent(params[0].getDataType()));
			assertTrue(Pointer16DataType.dataType.isEquivalent(params[1].getDataType()));
		}
	}

	@Test
	public void testSetInline() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			assertTrue(!f.isInline());

			// TODO: Monitor events

			f.setInline(true);

			// TODO: Check for expected event

			assertTrue(f.isInline());

			f.setInline(false);

			// TODO: Check for expected event

			assertFalse(f.isInline());
		}
	}

	@Test
	public void testSetNoReturn() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			assertTrue(!f.hasNoReturn());

			// TODO: Monitor events

			f.setNoReturn(true);

			// TODO: Check for expected event

			assertTrue(f.hasNoReturn());

			f.setNoReturn(false);

			// TODO: Check for expected event

			assertFalse(f.hasNoReturn());
		}
	}

	@Test
	public void testSetCallFixup() throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			TraceFunctionSymbol f = functions.create(0, b.addr(100), b.set(b.range(100, 200)),
				"foo", null, null, SourceType.USER_DEFINED);
			assertNull(f.getCallFixup());

			// TODO: Monitor events

			f.setCallFixup("TEST");

			// TODO: Check for expected event

			assertEquals("TEST", f.getCallFixup());

			f.setCallFixup(null);

			// TODO: Check for expected event

			assertNull(f.getCallFixup());
		}
	}

	@Test
	public void testSetThunkFunction()
			throws InvalidInputException, OverlappingFunctionException, DuplicateNameException {
		try (UndoableTransaction tid = b.startTransaction()) {

			Function f1 = functions.create(0, b.addr(0x100), b.set(b.range(0x100, 0x200)), "foo1",
				null, null, SourceType.USER_DEFINED);
			assertTrue(!f1.isThunk());
			assertNull(f1.getThunkedFunction(false));

			Function f2 = functions.create(0, b.addr(0x300), b.set(b.range(0x300, 0x400)), null,
				null, null, SourceType.DEFAULT);
			assertEquals("FUN_00000300", f2.getName());
			assertTrue(!f2.isThunk());
			assertNull(f2.getThunkedFunction(false));

			f1.setReturn(ByteDataType.dataType, VariableStorage.UNASSIGNED_STORAGE,
				SourceType.USER_DEFINED);

			// TODO: Monitor events

			// TODO: Change to update?
			f1.addParameter(createParameter("p1", IntegerDataType.dataType),
				SourceType.USER_DEFINED);

			// TODO: Check for expected event

			f1.addParameter(createParameter("p2", IntegerDataType.dataType),
				SourceType.USER_DEFINED);

			// TODO: Check for expected event

			assertEquals("byte foo1(int p1, int p2)", f1.getPrototypeString(false, false));
			assertEquals("undefined FUN_00000300()", f2.getPrototypeString(false, false));

			f2.setThunkedFunction(f1);

			// TODO: Check for expected event

			assertEquals("foo1", f2.getName());
			assertTrue(f2.isThunk());
			assertEquals(f1, f2.getThunkedFunction(false));

			assertEquals("byte foo1(int p1, int p2)", f1.getPrototypeString(false, false));
			// TODO: Not sure what the correct behavior should be?
			assertEquals("byte foo1(int p1, int p2)", f2.getPrototypeString(false, false));

			// Chum is fum
			f1.setName("fum", SourceType.USER_DEFINED);

			// TODO: Check for expected event
			// TODO: Should see an event for function and thunk
			// TODO: Check event addresses show real addresses (different for thunk)
			// TODO: Check that old and new names are given (same for real and thunk)

			f1.addParameter(createParameter("p3", IntegerDataType.dataType),
				SourceType.USER_DEFINED);// add to "thunked" func

			// TODO: Check for expected event
			// TODO: Should see event for both real and thunk

			f2.addParameter(createParameter("p4", IntegerDataType.dataType),
				SourceType.USER_DEFINED);// add to thunk

			// TODO: Check for expected event
			// TODO: Should see event for both real and thunk

			// Change thunk name (hides thunked function name)
			f2.setName("test", SourceType.USER_DEFINED);

			// TODO: Check for expected event
			// TODO: Only one name change of thunk

			assertEquals("test", f2.getName());
			assertEquals("fum", f1.getName());

			assertEquals("byte test(int p1, int p2, int p3, int p4)",
				f2.getPrototypeString(false, false));
			assertEquals("byte fum(int p1, int p2, int p3, int p4)",
				f1.getPrototypeString(false, false));

			// Restore thunk to name to its default (pass-thru thunked function name)
			f2.setName(null, SourceType.DEFAULT);

			// TODO: Check for expected event
			// TODO: Why does original test expect two events?

			assertEquals("fum", f2.getName());
			assertEquals("fum", f1.getName());

			assertEquals("byte fum(int p1, int p2, int p3, int p4)",
				f2.getPrototypeString(false, false));
			assertEquals("byte fum(int p1, int p2, int p3, int p4)",
				f1.getPrototypeString(false, false));
		}
	}

	@Test
	public void testPromoteLocalUserLabelsToGlobal()
			throws InvalidInputException, OverlappingFunctionException {
		try (UndoableTransaction tid = b.startTransaction()) {

			TraceFunctionSymbol foo2 = functions.create(0, b.addr(201), b.set(b.range(201, 249)),
				"foo2", null, null, SourceType.USER_DEFINED);

			// Add symbols to verify proper global conversion
			TraceLabelSymbolView labels = b.trace.getSymbolManager().labels();
			TraceNamespaceSymbol global = b.trace.getSymbolManager().getGlobalNamespace();
			// global - should keep
			labels.create(0, null, b.addr(220), "LAB_Test", global, SourceType.USER_DEFINED);
			// local - should remove (because its name conflicts with an existing global)
			labels.create(0, null, b.addr(220), "LAB_Test", foo2, SourceType.USER_DEFINED);
			// local - should keep (because it has a different name)
			labels.create(0, null, b.addr(220), "LAB_TestA", foo2, SourceType.USER_DEFINED);
			// local - should remove (because it's not USER_DEFINED)
			labels.create(0, null, b.addr(220), "LAB_TestB", foo2, SourceType.ANALYSIS);
			// local - should keep (because it's at a different address)
			labels.create(0, null, b.addr(224), "LAB_Test", foo2, SourceType.USER_DEFINED);

			assertNotNull(labels.getGlobalWithNameAt("LAB_Test", 0, null, b.addr(220)));
			assertNotNull(labels.getChildWithNameAt("LAB_Test", 0, null, b.addr(220), foo2));
			assertNotNull(labels.getChildWithNameAt("LAB_TestA", 0, null, b.addr(220), foo2));
			assertNotNull(labels.getChildWithNameAt("LAB_TestB", 0, null, b.addr(220), foo2));
			assertNotNull(labels.getChildWithNameAt("LAB_Test", 0, null, b.addr(224), foo2));

			foo2.promoteLocalUserLabelsToGlobal();

			foo2.getSymbol().delete(); // remove function (any remaining local symbols will be removed as well)

			// verify that only two symbols reside at b.addr(220)
			assertEquals(2, labels.getAt(0, null, b.addr(220), false).size());

			assertNotNull(labels.getGlobalWithNameAt("LAB_Test", 0, null, b.addr(220)));
			assertNotNull(labels.getGlobalWithNameAt("LAB_TestA", 0, null, b.addr(220)));
			assertNotNull(labels.getGlobalWithNameAt("LAB_Test", 0, null, b.addr(224)));

			assertTrue(b.trace.getSymbolManager()
					.labelsAndFunctions()
					.getAt(0, null, b.addr(201),
						false)
					.iterator()
					.next()
					.getSymbolType() != SymbolType.FUNCTION);
		}
	}

	@Test
	@Ignore("TODO")
	public void testSaveAndLoad() {
		TODO();
	}

	@Test
	@Ignore("TODO")
	public void testUndoThenRedo() {
		TODO();
	}
}
