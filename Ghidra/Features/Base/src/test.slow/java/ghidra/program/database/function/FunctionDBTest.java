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

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.*;

import ghidra.app.cmd.function.AddRegisterParameterCommand;
import ghidra.app.cmd.function.AddStackVarCmd;
import ghidra.app.cmd.refs.AddStackRefCmd;
import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *
 */
public class FunctionDBTest extends AbstractGhidraHeadedIntegrationTest
		implements DomainObjectListener {

	private ProgramDB program;
	private AddressSpace space;
	private FunctionManager functionManager;
	private int transactionID;

	private ProgramChangeRecord lastCaptureRecord;
	private ArrayList<ProgramChangeRecord> captureRecords = new ArrayList<>();

	private String captureFuncName;
	private int captureEventType;
	private int captureSubEvent;// not used if -1

	public FunctionDBTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		program.addListener(this);

		space = program.getAddressFactory().getDefaultAddressSpace();
		transactionID = program.startTransaction("Test");
		program.getMemory()
				.createInitializedBlock("test", addr(100), 500, (byte) 0,
					TaskMonitorAdapter.DUMMY_MONITOR, false);
		functionManager = program.getFunctionManager();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(transactionID, true);
			program.removeListener(this);
			program.release(this);
		}

	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord rec = ev.getChangeRecord(i);
			if (!(rec instanceof ProgramChangeRecord)) {
				continue;
			}
			ProgramChangeRecord pcRec = (ProgramChangeRecord) rec;
			if (captureFuncName != null &&
				rec.getEventType() == ChangeManager.DOCR_FUNCTION_CHANGED &&
				!captureFuncName.equals(((Function) pcRec.getObject()).getName())) {
				continue;
			}
			if (rec.getEventType() == captureEventType &&
				(captureSubEvent == -1 || rec.getSubEventType() == captureSubEvent)) {
				captureRecords.add(pcRec);
				lastCaptureRecord = pcRec;
			}
		}
	}

	private void captureFunctionChangeEvent(String funcName, int subEvent) {
		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED, subEvent);
		captureFuncName = funcName;
	}

	private void captureChangeEvent(int eventType, int subEvent) {
		captureEventType = eventType;
		captureSubEvent = subEvent;
		program.flushEvents();
		captureRecords.clear();
		lastCaptureRecord = null;
		captureFuncName = null;
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
	public void testGetName() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		String name = f.getName();
		assertTrue(name.indexOf("foo") == 0);
	}

	@Test
	public void testSetNameUser() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		captureChangeEvent(ChangeManager.DOCR_SYMBOL_RENAMED, -1);

		String name = "MyFunction";
		f.setName(name, SourceType.USER_DEFINED);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(name, f.getName());
		assertEquals(SourceType.USER_DEFINED, f.getSymbol().getSource());

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		Symbol s = (Symbol) lastCaptureRecord.getObject();
		assertTrue(f == s.getObject());
		assertEquals("foo", lastCaptureRecord.getOldValue());
		assertEquals("MyFunction", lastCaptureRecord.getNewValue());
	}

	@Test
	public void testSetNameAnalysis() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		String name = "MyFunction";
		f.setName(name, SourceType.ANALYSIS);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(name, f.getName());
		assertEquals(SourceType.ANALYSIS, f.getSymbol().getSource());
	}

	@Test
	public void testSetNameImport() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		String name = "MyFunction";
		f.setName(name, SourceType.IMPORTED);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(name, f.getName());
		assertEquals(SourceType.IMPORTED, f.getSymbol().getSource());
	}

	@Test
	public void testSetNameDefault() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		String name = SymbolUtilities.getDefaultFunctionName(addr(100));
		f.setName(name, SourceType.DEFAULT);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(name, f.getName());
		assertEquals(SourceType.DEFAULT, f.getSymbol().getSource());
	}

	@Test
	public void testSetComment() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		String comment = "Test Comment\nLine 2";
		f.setComment(comment);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(comment, f.getComment());
		assertEquals(2, f.getCommentAsArray().length);
	}

	@Test
	public void testSetRepeatable() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		String comment = "Test Repeatable Comment\nRepeatable Line 2";
		f.setRepeatableComment(comment);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(comment, f.getRepeatableComment());
		assertEquals(2, f.getRepeatableCommentAsArray().length);
	}

	@Test
	public void testCreateFunction() throws Exception {

		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_ADDED, -1);

		Function f = createFunction("foo", addr(100), asv);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(asv, f.getBody());

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		Function localF = (Function) lastCaptureRecord.getObject();
		assertEquals(asv, localF.getBody());
		assertEquals("foo", localF.getName());
	}

	@Test
	public void testSetBody() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		asv = new AddressSet();
		asv.addRange(addr(50), addr(120));
		asv.addRange(addr(300), addr(400));
		asv.addRange(addr(10), addr(20));

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_BODY_CHANGED, -1);

		f.setBody(asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(asv, f.getBody());

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		Function localF = (Function) lastCaptureRecord.getObject();
		assertEquals(asv, localF.getBody());
		assertEquals("foo", localF.getName());

	}

	@Test
	public void testSetBodyClearVarRefs() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));

		AddStackVarCmd cmd =
			new AddStackVarCmd(f.getEntryPoint(), -4, "local_var", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(f.getEntryPoint(), 4, "param_1", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));

		AddStackRefCmd c = new AddStackRefCmd(addr(210), 0, -4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));
		c = new AddStackRefCmd(addr(222), 1, 4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));
		c = new AddStackRefCmd(addr(250), 1, -8, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));

		Variable[] vars = f.getLocalVariables();
		assertEquals(2, vars.length);

		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(vars[0]);
		assertEquals(1, vrefs.length);
		assertEquals(addr(210), vrefs[0].getFromAddress());

		AddressIterator iter = refMgr.getReferenceSourceIterator(asv, true);
		while (iter.hasNext()) {
			Address fromAddr = iter.next();
			Reference[] refs = refMgr.getReferencesFrom(fromAddr);
			assertEquals(1, refs.length);
		}

		asv = new AddressSet();
		asv.addRange(addr(50), addr(120));
		asv.addRange(addr(300), addr(400));
		asv.addRange(addr(10), addr(20));

		f.setBody(asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(asv, f.getBody());

		iter = refMgr.getReferenceSourceIterator(asv, true);
		while (iter.hasNext()) {
			Address fromAddr = iter.next();
			Reference[] refs = refMgr.getReferencesFrom(fromAddr);
			assertEquals(0, refs.length);
		}

	}

	@Test
	public void testSetBodyClearVarRefs2() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));

		AddStackVarCmd cmd =
			new AddStackVarCmd(f.getEntryPoint(), -4, "local_var", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(f.getEntryPoint(), 4, "param_1", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));

		AddStackRefCmd c = new AddStackRefCmd(addr(210), 0, -4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));
		c = new AddStackRefCmd(addr(222), 1, 4, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));
		c = new AddStackRefCmd(addr(250), 1, -8, SourceType.USER_DEFINED);
		assertTrue(c.applyTo(program));

		Variable[] vars = f.getLocalVariables();
		assertEquals(2, vars.length);

		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] vrefs = refMgr.getReferencesTo(vars[0]);
		assertEquals(1, vrefs.length);
		assertEquals(addr(210), vrefs[0].getFromAddress());

		AddressIterator iter = refMgr.getReferenceSourceIterator(asv, true);
		while (iter.hasNext()) {
			Address fromAddr = iter.next();
			Reference[] refs = refMgr.getReferencesFrom(fromAddr);
			assertEquals(1, refs.length);
		}

		asv = new AddressSet();
		asv.addRange(addr(50), addr(120));
		asv.addRange(addr(250), addr(400));
		asv.addRange(addr(10), addr(20));

		f.setBody(asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(asv, f.getBody());

		iter = refMgr.getReferenceSourceIterator(asv, true);
		Address fromAddr = iter.next();
		Reference[] refs = refMgr.getReferencesFrom(fromAddr);
		assertEquals(1, refs.length);
		assertEquals(addr(250), fromAddr);
		assertTrue(!iter.hasNext());

	}

	@Test
	public void testSetBodyInvalidEntryPoint() throws Exception {

		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		asv = new AddressSet();
		asv.addRange(addr(110), addr(120));
		asv.addRange(addr(300), addr(400));
		asv.addRange(addr(10), addr(20));

		try {
			f.setBody(asv);
			Assert.fail(
				"Should have gotten illegal argument exception: original entry point not in new body");
		}
		catch (IllegalArgumentException e) {
		}

	}

	@Test
	public void testSetBodyOverlapping() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		AddressSetView oldSet = f.getBody();

		AddressSet asv2 = new AddressSet();
		asv2.addRange(addr(0), addr(50));
		asv2.addRange(addr(75), addr(90));
		createFunction("foo2", addr(0), asv2);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		asv = new AddressSet();
		asv.addRange(addr(50), addr(120));
		asv.addRange(addr(300), addr(400));
		asv.addRange(addr(10), addr(20));

		try {
			f.setBody(asv);
			Assert.fail("Should have gotten OverlappingFunctionException!");
		}
		catch (OverlappingFunctionException e) {
		}
		assertEquals(oldSet, f.getBody());

		asv = new AddressSet();
		asv.addRange(addr(80), addr(120));
		asv.addRange(addr(300), addr(400));
		asv.addRange(addr(10), addr(20));
		try {
			f.setBody(asv);
			Assert.fail("Should have gotten OverlappingFunctionException!");
		}
		catch (OverlappingFunctionException e) {
		}
		assertEquals(oldSet, f.getBody());
	}

	@Test
	public void testSetBodyClearSymbols() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));

		SymbolTable symbolTable = program.getSymbolTable();
		Symbol s1 = symbolTable.createLabel(addr(410), "fred", f, SourceType.USER_DEFINED);
		symbolTable.createLabel(addr(100), "bob", f, SourceType.USER_DEFINED);
		Symbol s3 = symbolTable.createLabel(addr(200), "joe", f, SourceType.USER_DEFINED);
		symbolTable.createLabel(addr(400), "ricky", f, SourceType.USER_DEFINED);

		asv = new AddressSet();
		asv.addRange(addr(10), addr(20));
		asv.addRange(addr(50), addr(120));
		asv.addRange(addr(300), addr(400));

		f.setBody(asv);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(asv, f.getBody());

		// Symbols fred and joe should have gotten removed;
		// bob and ricky should still exist
		assertNull(getUniqueSymbol(program, "fred", f));
		assertNull(getUniqueSymbol(program, "joe", f));
		assertNull(symbolTable.getSymbol(s1.getID()));
		assertNull(symbolTable.getSymbol(s3.getID()));
		assertNotNull(getUniqueSymbol(program, "bob", f));
		assertNotNull(getUniqueSymbol(program, "ricky", f));
	}

	@Test
	public void testGetVariables() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));
		asv.addRange(addr(400), addr(450));
		asv.addRange(addr(500), addr(550));

		Function f = createFunction("foo", addr(100), asv);
		AddStackVarCmd cmd =
			new AddStackVarCmd(f.getEntryPoint(), 4, "param_1", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(f.getEntryPoint(), 8, "param_2", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));

		cmd =
			new AddStackVarCmd(f.getEntryPoint(), -4, "local_var_1", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd =
			new AddStackVarCmd(f.getEntryPoint(), -8, "local_var_2", null, SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(f.getEntryPoint(), -12, "local_var_3", null,
			SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(f.getEntryPoint(), -16, "local_var_4", null,
			SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));
		cmd = new AddStackVarCmd(f.getEntryPoint(), -20, "local_var_5", null,
			SourceType.USER_DEFINED);
		assertTrue(cmd.applyTo(program));

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Variable[] locals = f.getLocalVariables();
		assertEquals(5, locals.length);
		for (int i = 0; i < locals.length; i++) {
			assertEquals("local_var_" + (i + 1), locals[i].getName());
		}

		Parameter[] params = f.getParameters();
		assertEquals(2, params.length);
		assertEquals("param_1", params[0].getName());
		assertEquals("param_2", params[1].getName());
	}

	@Test
	public void testGetReturnType() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertEquals(DataType.DEFAULT, f.getReturnType());
	}

	@Test
	public void testSetReturnType() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		DataType dt = new ByteDataType();

		Parameter return1 = f.getReturn();
		assertTrue(return1 instanceof ReturnParameterDB);
		assertTrue(Undefined.isUndefined(return1.getDataType()));

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_RETURN);

		f.setReturnType(dt, SourceType.ANALYSIS);

		assertTrue(dt.isEquivalent(return1.getDataType()));

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));

		assertTrue(dt.isEquivalent(f.getReturnType()));

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
	}

	private Function createTestFunction() throws Exception {
		AddressSet asv = new AddressSet();
		asv.addRange(addr(100), addr(350));

		SymbolTable symbolTable = program.getSymbolTable();
		Namespace globalNamespace = program.getNamespaceManager().getGlobalNamespace();
		GhidraClass c =
			symbolTable.createClass(globalNamespace, "MyClass", SourceType.USER_DEFINED);

		Function f = createFunction("foo", addr(100), asv);
		f.getSymbol().setNamespace(c);

		f.setCallingConvention("__stdcall");

		f.setReturnType(Undefined4DataType.dataType, SourceType.USER_DEFINED);

		f.addParameter(new ParameterImpl("p1", Undefined4DataType.dataType, program),
			SourceType.USER_DEFINED);
		f.addParameter(new ParameterImpl("p2", Undefined2DataType.dataType, program),
			SourceType.USER_DEFINED);
		f.addParameter(new ParameterImpl("p3", Undefined1DataType.dataType, program),
			SourceType.USER_DEFINED);
		f.addParameter(new ParameterImpl("p4", Undefined4DataType.dataType, program),
			SourceType.USER_DEFINED);
		f.addParameter(new ParameterImpl("p5", Undefined2DataType.dataType, program),
			SourceType.USER_DEFINED);

		assertTrue(!f.hasCustomVariableStorage());
		assertEquals("__stdcall", f.getCallingConventionName());
		assertEquals(5, f.getParameterCount());

		return f;
	}

	private void assertParameter(Parameter p1, Parameter p2, boolean checkStorage) {
		assertEquals(p1.getName(), p2.getName());
		if (!p1.getDataType().isEquivalent(p2.getDataType())) {
			Assert.fail("Expected " + p1.getDataType().getName() + " but parameter has type " +
				p2.getDataType().getName());
		}
		if (checkStorage) {
			assertEquals(p1.getVariableStorage(), p2.getVariableStorage());
		}
	}

	@Test
	public void testSetCustomStorage() throws Exception {

		Function f = createTestFunction();
		assertEquals("__stdcall", f.getCallingConventionName());

		int initialParamCnt = f.getParameterCount();

		Structure bar = new StructureDataType("bar", 20);
		Pointer barPtr = program.getDataTypeManager().getPointer(bar);

		Parameter returnVar = f.getReturn();
		Parameter p1 = f.getParameter(0);
		Parameter p2 = f.getParameter(1);
		p2.setDataType(bar, SourceType.USER_DEFINED);

		VariableStorage initialReturnStorage = returnVar.getVariableStorage();
		VariableStorage initialP1Storage = p1.getVariableStorage();
		VariableStorage initialP2Storage = p2.getVariableStorage();
		assertTrue(p2.isForcedIndirect());

		assertEquals("r12:4", initialReturnStorage.toString());
		assertEquals("r12:4", initialP1Storage.toString());
		assertEquals("r11:4 (ptr)", initialP2Storage.toString());

		// enable custom storage
		f.setCustomVariableStorage(true);

		assertEquals(initialParamCnt, f.getParameterCount());

		VariableStorage r5Storage = new VariableStorage(program, program.getRegister("r5"));
		returnVar.setDataType(IntegerDataType.dataType, r5Storage, false, SourceType.USER_DEFINED);
		VariableStorage r7Storage = new VariableStorage(program, program.getRegister("r7"));
		p1.setDataType(IntegerDataType.dataType,
			new VariableStorage(program, program.getRegister("r7")), false,
			SourceType.USER_DEFINED);

		assertEquals(r5Storage, returnVar.getVariableStorage());
		assertEquals(r5Storage, f.getReturn().getVariableStorage());

		assertEquals(r7Storage, p1.getVariableStorage());
		assertEquals(r7Storage, p1.getVariableStorage());
		assertArrayEquals(initialP2Storage.getVarnodes(), p2.getVariableStorage().getVarnodes());

		assertTrue(p1.getDataType().isEquivalent(IntegerDataType.dataType));
		assertTrue(p2.getDataType().isEquivalent(barPtr));
		assertFalse(p2.isForcedIndirect());

		// disable custom storage
		f.setCustomVariableStorage(false);

		assertEquals(initialReturnStorage, returnVar.getVariableStorage());
		assertEquals(initialReturnStorage, f.getReturn().getVariableStorage());

		assertArrayEquals(initialP1Storage.getVarnodes(), p1.getVariableStorage().getVarnodes());
		assertArrayEquals(initialP1Storage.getVarnodes(),
			f.getParameter(0).getVariableStorage().getVarnodes());
		assertArrayEquals(initialP2Storage.getVarnodes(), p2.getVariableStorage().getVarnodes());
		assertArrayEquals(initialP2Storage.getVarnodes(),
			f.getParameter(1).getVariableStorage().getVarnodes());

		assertTrue(p1.getDataType().isEquivalent(IntegerDataType.dataType));
		assertTrue(p2.getDataType().isEquivalent(barPtr));
		assertFalse(p2.isForcedIndirect());// unable to round-trip forced indirect

		// set __thiscall
	}

	@Test
	public void testSetCallingConvention() throws Exception {

		Function f = createTestFunction();
		assertEquals("__stdcall", f.getCallingConventionName());

		int initialParamCnt = f.getParameterCount();

		Structure bar = new StructureDataType("bar", 20);
		Pointer barPtr = program.getDataTypeManager().getPointer(bar);

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

		assertEquals(new VariableStorage(program, program.getRegister("r12")),
			returnVar.getVariableStorage());// TODO: need better test of return storage - no change in spec storage
		assertEquals(new VariableStorage(program, 4, 4), p1.getVariableStorage());
		assertEquals(new VariableStorage(program, 8, 20), p2.getVariableStorage());

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
		Pointer structPtr = program.getDataTypeManager().getPointer(namespaceStruct);

		assertTrue(thisParam.getDataType().isEquivalent(structPtr));
		assertTrue(p1.getDataType().isEquivalent(Undefined4DataType.dataType));
		assertTrue(p2.getDataType().isEquivalent(barPtr));
	}

	@Test
	public void testUpdateFunctionCustomStorage() throws Exception {

		Function f = createTestFunction();

		Structure bigStruct = new StructureDataType("bigStruct", 20);

		ReturnParameterImpl returnVar = new ReturnParameterImpl(new PointerDataType(bigStruct),
			new VariableStorage(program, program.getRegister("r6")), program);

		ParameterImpl p1 =
			new ParameterImpl(Function.RETURN_PTR_PARAM_NAME, new PointerDataType(bigStruct),
				new VariableStorage(program, program.getRegister("r7")), program);
		ParameterImpl p2 = new ParameterImpl("m2", LongLongDataType.dataType,
			new VariableStorage(program, program.getRegister("r12"), program.getRegister("r11")),
			program);
		ParameterImpl p3 = new ParameterImpl("m3", ByteDataType.dataType,
			new VariableStorage(program, program.getRegister("r9").getAddress(), 1), program);

		f.updateFunction("__stdcall", returnVar, FunctionUpdateType.CUSTOM_STORAGE, true,
			SourceType.USER_DEFINED, p1, p2, p3);

		assertTrue(f.hasCustomVariableStorage());
		assertEquals("__stdcall", f.getCallingConventionName());

		Parameter return1 = f.getReturn();
		assertParameter(returnVar, return1, true);
		assertEquals("r6:4", return1.getVariableStorage().toString());

		Parameter[] parameters = f.getParameters();
		assertEquals(3, parameters.length);

		assertParameter(p1, parameters[0], true);
		assertParameter(p2, parameters[1], true);
		assertParameter(p3, parameters[2], true);

	}

	@Test
	public void testUpdateFunctionDynamicStorage() throws Exception {

		Function f = createTestFunction();

		Structure bigStruct = new StructureDataType("bigStruct", 20);

		ReturnParameterImpl returnVar =
			new ReturnParameterImpl(bigStruct, VariableStorage.UNASSIGNED_STORAGE, program);

		ParameterImpl p1 =
			new ParameterImpl(Function.RETURN_PTR_PARAM_NAME, new PointerDataType(bigStruct),
				new VariableStorage(program, program.getRegister("r7")), program);
		Structure classStruct = VariableUtilities.findOrCreateClassStruct(f);
		ParameterImpl p2 =
			new ParameterImpl(Function.THIS_PARAM_NAME, new PointerDataType(classStruct),
				new VariableStorage(program, program.getRegister("r8")), program);
		ParameterImpl p3 = new ParameterImpl("m2", LongLongDataType.dataType,
			new VariableStorage(program, program.getRegister("r12"), program.getRegister("r11")),
			program);
		ParameterImpl p4 = new ParameterImpl("m3", ByteDataType.dataType,
			new VariableStorage(program, program.getRegister("r9")), program);

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

		Parameter[] parameters = f.getParameters();
		assertEquals(4, parameters.length);

		assertParameter(p1, parameters[0], false);
		assertEquals(0, parameters[0].getOrdinal());
		assertEquals("r12:4 (auto)", parameters[0].getVariableStorage().toString());
		assertParameter(p2, parameters[1], false);
		assertEquals(1, parameters[1].getOrdinal());
		assertEquals("r11:4 (auto)", parameters[1].getVariableStorage().toString());
		assertParameter(p3, parameters[2], false);
		assertEquals(2, parameters[2].getOrdinal());
		assertEquals("Stack[0x0]:8", parameters[2].getVariableStorage().toString());
		assertParameter(p4, parameters[3], false);
		assertEquals(3, parameters[3].getOrdinal());
		assertEquals("r10l:1", parameters[3].getVariableStorage().toString());

	}

	@Test
	public void testUpdateFunctionDynamicStorage1() throws Exception {

		Function f = createTestFunction();

		Structure bigStruct = new StructureDataType("bigStruct", 20);

		ReturnParameterImpl returnVar = new ReturnParameterImpl(new PointerDataType(bigStruct),
			VariableStorage.UNASSIGNED_STORAGE, program);

		ParameterImpl p1 =
			new ParameterImpl(Function.RETURN_PTR_PARAM_NAME, new PointerDataType(bigStruct),
				new VariableStorage(program, program.getRegister("r7")), program);
		Structure classStruct = VariableUtilities.findOrCreateClassStruct(f);
		ParameterImpl p2 =
			new ParameterImpl(Function.THIS_PARAM_NAME, new PointerDataType(classStruct),
				new VariableStorage(program, program.getRegister("r8")), program);
		ParameterImpl p3 = new ParameterImpl("m2", LongLongDataType.dataType,
			new VariableStorage(program, program.getRegister("r12"), program.getRegister("r11")),
			program);
		ParameterImpl p4 = new ParameterImpl("m3", ByteDataType.dataType,
			new VariableStorage(program, program.getRegister("r9")), program);

		// function updated with auto parameters
		f.updateFunction("__thiscall", returnVar, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
			true, SourceType.USER_DEFINED, p1, p2, p3, p4);

		assertTrue(!f.hasCustomVariableStorage());
		assertEquals("__thiscall", f.getCallingConventionName());

		Parameter return1 = f.getReturn();
		assertTrue(return1.isForcedIndirect());
		assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
		assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
		assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

		Parameter[] parameters = f.getParameters();
		assertEquals(4, parameters.length);

		assertParameter(p1, parameters[0], false);
		assertEquals(0, parameters[0].getOrdinal());
		assertEquals("r12:4 (auto)", parameters[0].getVariableStorage().toString());
		assertParameter(p2, parameters[1], false);
		assertEquals(1, parameters[1].getOrdinal());
		assertEquals("r11:4 (auto)", parameters[1].getVariableStorage().toString());
		assertParameter(p3, parameters[2], false);
		assertEquals(2, parameters[2].getOrdinal());
		assertEquals("Stack[0x0]:8", parameters[2].getVariableStorage().toString());
		assertParameter(p4, parameters[3], false);
		assertEquals(3, parameters[3].getOrdinal());
		assertEquals("r10l:1", parameters[3].getVariableStorage().toString());

	}

	@Test
	public void testUpdateFunctionDynamicStorage2() throws Exception {

		Function f = createTestFunction();

		Structure bigStruct = new StructureDataType("bigStruct", 20);

		ReturnParameterImpl returnVar = new ReturnParameterImpl(new PointerDataType(bigStruct),
			VariableStorage.UNASSIGNED_STORAGE, program);

		ParameterImpl p1 =
			new ParameterImpl(Function.RETURN_PTR_PARAM_NAME, new PointerDataType(bigStruct),
				new VariableStorage(program, program.getRegister("r7")), program);
		ParameterImpl p2 = new ParameterImpl("m2", LongLongDataType.dataType,
			new VariableStorage(program, program.getRegister("r12"), program.getRegister("r11")),
			program);
		ParameterImpl p3 = new ParameterImpl("m3", ByteDataType.dataType,
			new VariableStorage(program, program.getRegister("r9")), program);

		f.updateFunction("__thiscall", returnVar, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
			true, SourceType.USER_DEFINED, p1, p2, p3);

		assertTrue(!f.hasCustomVariableStorage());
		assertEquals("__thiscall", f.getCallingConventionName());

		Parameter return1 = f.getReturn();
		assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
		assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
		assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

		Parameter[] parameters = f.getParameters();
		assertEquals(4, parameters.length);

		Structure classStruct = VariableUtilities.findOrCreateClassStruct(f);

		ParameterImpl thisParam = new ParameterImpl(Function.THIS_PARAM_NAME,
			new PointerDataType(classStruct), VariableStorage.UNASSIGNED_STORAGE, program);

		assertParameter(p1, parameters[0], false);
		assertEquals("r12:4 (auto)", parameters[0].getVariableStorage().toString());
		assertParameter(thisParam, parameters[1], false);
		assertEquals("r11:4 (auto)", parameters[1].getVariableStorage().toString());
		assertParameter(p2, parameters[2], false);
		assertEquals("Stack[0x0]:8", parameters[2].getVariableStorage().toString());
		assertParameter(p3, parameters[3], false);
		assertEquals("r10l:1", parameters[3].getVariableStorage().toString());

		// try again with DB params

		f.updateFunction("__thiscall", f.getReturn(), FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
			true, SourceType.USER_DEFINED, f.getParameters());

		assertTrue(!f.hasCustomVariableStorage());
		assertEquals("__thiscall", f.getCallingConventionName());

		return1 = f.getReturn();
		assertTrue(bigStruct.isEquivalent(return1.getFormalDataType()));
		assertTrue(returnVar.getDataType().isEquivalent(returnVar.getDataType()));
		assertEquals("r12:4 (ptr)", return1.getVariableStorage().toString());

		parameters = f.getParameters();
		assertEquals(4, parameters.length);

		assertParameter(p1, parameters[0], false);
		assertEquals(0, parameters[0].getOrdinal());
		assertEquals("r12:4 (auto)", parameters[0].getVariableStorage().toString());
		assertParameter(thisParam, parameters[1], false);
		assertEquals(1, parameters[1].getOrdinal());
		assertEquals("r11:4 (auto)", parameters[1].getVariableStorage().toString());
		assertParameter(p2, parameters[2], false);
		assertEquals(2, parameters[2].getOrdinal());
		assertEquals("Stack[0x0]:8", parameters[2].getVariableStorage().toString());
		assertParameter(p3, parameters[3], false);
		assertEquals(3, parameters[3].getOrdinal());
		assertEquals("r10l:1", parameters[3].getVariableStorage().toString());

		// try again with DB params and custom storage

		f.updateFunction("__thiscall", f.getReturn(), FunctionUpdateType.CUSTOM_STORAGE, true,
			SourceType.USER_DEFINED, f.getParameters());

		assertTrue(f.hasCustomVariableStorage());
		assertEquals("__thiscall", f.getCallingConventionName());

		return1 = f.getReturn();
		assertParameter(returnVar, return1, false);
		assertEquals("r12:4", return1.getVariableStorage().toString());

		parameters = f.getParameters();
		assertEquals(4, parameters.length);

		assertParameter(p1, parameters[0], false);
		assertEquals(0, parameters[0].getOrdinal());
		assertEquals("r12:4", parameters[0].getVariableStorage().toString());
		assertParameter(thisParam, parameters[1], false);
		assertEquals(1, parameters[1].getOrdinal());
		assertEquals("r11:4", parameters[1].getVariableStorage().toString());
		assertParameter(p2, parameters[2], false);
		assertEquals(2, parameters[2].getOrdinal());
		assertEquals("Stack[0x0]:8", parameters[2].getVariableStorage().toString());
		assertParameter(p3, parameters[3], false);
		assertEquals(3, parameters[3].getOrdinal());
		assertEquals("r10l:1", parameters[3].getVariableStorage().toString());

	}

	@Test
	public void testAutoAddingRemovingThisParameter() throws Exception {

		Function f = createTestFunction();
		assertEquals(5, f.getParameters().length);

		assertNull(getUniqueSymbol(program, "this", f));

		f.setCallingConvention("__thiscall");
		assertEquals(6, f.getParameters().length);
		assertEquals("this", f.getParameter(0).getName());
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

		assertNull(getUniqueSymbol(program, "this", f));

		f.setCallingConvention("__stdcall");
		assertEquals(5, f.getParameters().length);
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(0).getDataType()));

		assertNull(getUniqueSymbol(program, "this", f));

		f.setCallingConvention("__thiscall");
		assertEquals(6, f.getParameters().length);
		Parameter param = f.getParameter(0);
		assertTrue(param.isAutoParameter());
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

		assertNull(getUniqueSymbol(program, "this", f));

		f.setCustomVariableStorage(true);

		assertNotNull(getUniqueSymbol(program, "this", f));

		assertEquals(6, f.getParameters().length);
		param = f.getParameter(0);
		assertFalse(param.isAutoParameter());
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

		f.setCustomVariableStorage(false);

		assertNull(getUniqueSymbol(program, "this", f));

		assertEquals(6, f.getParameters().length);
		param = f.getParameter(0);
		assertTrue(param.isAutoParameter());
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

		f.setCustomVariableStorage(true);

		assertNotNull(getUniqueSymbol(program, "this", f));

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

		assertNotNull(getUniqueSymbol(program, "this", f));

		assertEquals(6, f.getParameters().length);
		param = f.getParameter(0);
		assertFalse(param.isAutoParameter());
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

		f.setCallingConvention("__thiscall");

		assertNull(getUniqueSymbol(program, "this", f));

		assertEquals(6, f.getParameters().length);
		param = f.getParameter(0);
		assertTrue(param.isAutoParameter());
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(1).getDataType()));

		f.setCallingConvention("__stdcall");
		assertEquals(5, f.getParameters().length);
		assertTrue(Undefined4DataType.dataType.isEquivalent(f.getParameter(0).getDataType()));

	}

	/*
	 * Test for String getSignature(String)
	 */
	@Test
	public void testGetSignatureString() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		Structure s = new StructureDataType("bar", 20);
		f.setReturnType(s, SourceType.ANALYSIS);
		Parameter p = f.addParameter(new ParameterImpl("p1", s, program), SourceType.IMPORTED);

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
		assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(false, true));

		f.removeVariable(p);

		assertEquals("bar foo(void)", f.getPrototypeString(true, false));
		assertEquals("bar __thiscall foo(void)", f.getPrototypeString(true, true));
		assertEquals("bar * foo(bar * __return_storage_ptr__, void * this)",
			f.getPrototypeString(false, false));
		assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this)",
			f.getPrototypeString(false, true));

		p = f.addParameter(new ParameterImpl("p1", s, program), SourceType.ANALYSIS);

		assertEquals("bar foo(bar p1)", f.getPrototypeString(true, false));
		assertEquals("bar __thiscall foo(bar p1)", f.getPrototypeString(true, true));
		assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(false, false));
		assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(false, true));

		f.setCustomVariableStorage(true);

		assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(true, false));
		assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(true, true));
		assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(false, false));
		assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(false, true));

		f.setCustomVariableStorage(false);

		// forced-indirect round trip not supported for parameter
		assertEquals("bar foo(bar * p1)", f.getPrototypeString(true, false));
		assertEquals("bar __thiscall foo(bar * p1)", f.getPrototypeString(true, true));
		assertEquals("bar * foo(bar * __return_storage_ptr__, void * this, bar * p1)",
			f.getPrototypeString(false, false));
		assertEquals("bar * __thiscall foo(bar * __return_storage_ptr__, void * this, bar * p1)",
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

	@Test
	public void testDataTypeOnRegisterVariable() throws Exception {

		Register reg = program.getProgramContext().getRegister("r7l");
		assertNotNull(reg);

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		ByteDataType bdt = new ByteDataType();
		TypeDef td = null;

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_PARAMETERS);

		int localTransactionID = program.startTransaction("test");
		try {
			bdt = (ByteDataType) program.getDataTypeManager()
					.addDataType(bdt,
						DataTypeConflictHandler.DEFAULT_HANDLER);
			td = new TypedefDataType("byteTD", bdt);
			td = (TypeDef) program.getDataTypeManager()
					.addDataType(td,
						DataTypeConflictHandler.DEFAULT_HANDLER);
			AddRegisterParameterCommand cmd = new AddRegisterParameterCommand(f, reg, "reg_param_0",
				td, 0, SourceType.USER_DEFINED);
			cmd.applyTo(program);
		}
		finally {
			program.endTransaction(localTransactionID, true);
		}

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		Parameter[] params = f.getParameters();
		assertEquals(1, params.length);

		Parameter rp = params[0];
		assertEquals(td, rp.getDataType());
		assertEquals(reg, rp.getRegister());

		// delete the typedef data type
		localTransactionID = program.startTransaction("test");
		try {
			program.getDataTypeManager().remove(td, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		finally {
			program.endTransaction(localTransactionID, true);
		}

		params = f.getParameters();
		assertEquals(1, params.length);
		assertTrue(params[0].isRegisterVariable());
		assertEquals(Undefined1DataType.dataType, params[0].getDataType());
		assertEquals(reg, params[0].getRegister());
	}

	@Test
	public void testSetStackDepthChange() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED, -1);// TODO: no sub-event

		f.setStackPurgeSize(20);
		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals(20, f.getStackPurgeSize());

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
	}

	@Test
	public void testSetStackParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);
		f.setCallingConvention("__stackcall");

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		LocalVariableImpl stackVar = new LocalVariableImpl("TestStack0", dt[0], 4, program);
		stackVar.setComment("My Comment0");

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_PARAMETERS);

		assertTrue(f.addParameter(stackVar, SourceType.USER_DEFINED) instanceof ParameterDB);// causes both symbol created and function change events

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		stackVar = new LocalVariableImpl("TestStack1", dt[1], 8, program);
		stackVar.setComment("My Comment1");

		captureChangeEvent(ChangeManager.DOCR_SYMBOL_ADDED, -1);

		assertTrue(f.addParameter(stackVar, SourceType.USER_DEFINED) instanceof ParameterDB);// causes both symbol created and function change events

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		stackVar = new LocalVariableImpl("TestStack2", dt[2], 12, program);
		stackVar.setComment("My Comment2");
		assertTrue(f.addParameter(stackVar, SourceType.USER_DEFINED) instanceof ParameterDB);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
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

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
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

	@Test
	public void testSetDuplicateStackParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		LocalVariableImpl stackVar = new LocalVariableImpl("TestStack0", dt[0], 4, program);
		stackVar.setComment("My Comment0");
		f.addParameter(stackVar, SourceType.USER_DEFINED);
		stackVar = new LocalVariableImpl("TestStack1", dt[1], 8, program);
		stackVar.setComment("My Comment1");
		f.addParameter(stackVar, SourceType.USER_DEFINED);
		stackVar = new LocalVariableImpl("TestStack2", dt[2], 4, program);// duplicate stack offset
		stackVar.setComment("My Comment2");
		f.addParameter(stackVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
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

	@Test
	public void testSetStackVariable() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		LocalVariableImpl stackVar = new LocalVariableImpl("TestStack0", dt[0], -4, program);
		stackVar.setComment("My Comment0");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
		stackVar = new LocalVariableImpl("TestStack1", dt[1], -8, program);
		stackVar.setComment("My Comment1");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
		stackVar = new LocalVariableImpl("TestStack2", dt[2], -12, program);
		stackVar.setComment("My Comment2");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
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

	@Test
	public void testSetStackVariableOverwrite() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		Structure dt = new StructureDataType("Struct1", 0);
		dt = (Structure) program.getDataTypeManager().addDataType(dt, null);

		LocalVariableImpl stackVar = new LocalVariableImpl("TestStack0", dt, -8, program);
		stackVar.setComment("My Comment0");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

		dt = dt.clone(program.getDataTypeManager());
		dt.add(WordDataType.dataType);

		f = functionManager.getFunctionAt(addr(100));

		stackVar = new LocalVariableImpl("TestStack2", dt, -8, program);
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

	@Test
	public void testSetDuplicateStackVariable() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		LocalVariableImpl stackVar = new LocalVariableImpl("TestStack0", dt[0], -4, program);
		stackVar.setComment("My Comment0");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
		stackVar = new LocalVariableImpl("TestStack1", dt[1], -8, program);
		stackVar.setComment("My Comment1");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);
		stackVar = new LocalVariableImpl("TestStack2", dt[2], -4, program);// duplicate stack offset
		stackVar.setComment("My Comment2");
		f.addLocalVariable(stackVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
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

	@Test
	public void testSetRegisterParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new LongDataType(), new WordDataType(), new Pointer16DataType() };

		Register[] regs =
			new Register[] { functionManager.getProgram().getProgramContext().getRegister("r1"),
				functionManager.getProgram().getProgramContext().getRegister("r2l"),
				functionManager.getProgram().getProgramContext().getRegister("r3l") };

		LocalVariableImpl regVar = new LocalVariableImpl("TestReg0", 0, dt[0], regs[0], program);
		regVar.setComment("My Comment0");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg1", 0, dt[1], regs[1], program);
		regVar.setComment("My Comment1");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg2", 0, dt[2], regs[2], program);
		regVar.setComment("My Comment2");
		f.addParameter(regVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Parameter[] params = f.getParameters();
		assertEquals(3, params.length);
		for (int i = 0; i < 3; i++) {
			Parameter param = params[i];
			assertTrue(param.isRegisterVariable());
			assertEquals("TestReg" + i, param.getName());
			assertEquals(i, param.getOrdinal());
			assertEquals("My Comment" + i, param.getComment());
			assertEquals(f, param.getFunction());
			assertEquals(regs[i], param.getRegister());
			assertTrue(dt[i].isEquivalent(param.getDataType()));
		}
	}

	@Test
	public void testSetDuplicateRegisterParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new LongDataType(), new WordDataType(), new Pointer16DataType() };

		Register[] regs =
			new Register[] { functionManager.getProgram().getProgramContext().getRegister("r1"),
				functionManager.getProgram().getProgramContext().getRegister("r2l"),
				functionManager.getProgram().getProgramContext().getRegister("r1l")
			// same address as regs[0]
			};

		LocalVariableImpl regVar = new LocalVariableImpl("TestReg0", 0, dt[0], regs[0], program);
		regVar.setComment("My Comment0");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg1", 0, dt[1], regs[1], program);
		regVar.setComment("My Comment1");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg2", 0, dt[2], regs[2], program);
		regVar.setComment("My Comment2");
		f.addParameter(regVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Parameter[] params = f.getParameters();
		assertEquals(2, params.length);
		for (int i = 0; i < 2; i++) {
			int n = i + 1;
			Parameter param = params[i];
			assertTrue(param.isRegisterVariable());
			assertEquals("TestReg" + n, param.getName());
			assertEquals(i, param.getOrdinal());
			assertEquals("My Comment" + n, param.getComment());
			assertEquals(f, param.getFunction());
			assertEquals(regs[n], param.getRegister());
			assertTrue(dt[n].isEquivalent(param.getDataType()));
		}
	}

	@Test
	public void testSetRegisterVariable() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		DataType[] dt =
			new DataType[] { new LongDataType(), new WordDataType(), new Pointer16DataType() };

		Register[] regs =
			new Register[] { functionManager.getProgram().getProgramContext().getRegister("r1"),
				functionManager.getProgram().getProgramContext().getRegister("r1l"),
				functionManager.getProgram().getProgramContext().getRegister("r3l") };

		LocalVariableImpl regVar = new LocalVariableImpl("TestReg0", 0, dt[0], regs[0], program);
		regVar.setComment("My Comment0");
		assertTrue(f.addLocalVariable(regVar, SourceType.USER_DEFINED) instanceof LocalVariableDB);
		regVar = new LocalVariableImpl("TestReg1", 4, dt[1], regs[1], program);
		regVar.setComment("My Comment1");
		assertTrue(f.addLocalVariable(regVar, SourceType.USER_DEFINED) instanceof LocalVariableDB);
		regVar = new LocalVariableImpl("TestReg2", 8, dt[2], regs[2], program);
		regVar.setComment("My Comment2");
		assertTrue(f.addLocalVariable(regVar, SourceType.USER_DEFINED) instanceof LocalVariableDB);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
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
			assertEquals(regs[i], var.getRegister());
			assertTrue(dt[i].isEquivalent(var.getDataType()));
		}
	}

	@Test
	public void testSetDuplicateRegisterVariable() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		Register[] regs =
			new Register[] { functionManager.getProgram().getProgramContext().getRegister("r1l"),
				functionManager.getProgram().getProgramContext().getRegister("r1l"),
				functionManager.getProgram().getProgramContext().getRegister("r3l") };

		LocalVariableImpl regVar = new LocalVariableImpl("TestReg0", 4, dt[0], regs[0], program);
		regVar.setComment("My Comment0");
		f.addLocalVariable(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg1", 4, dt[1], regs[1], program);
		regVar.setComment("My Comment1");
		f.addLocalVariable(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg2", 8, dt[2], regs[2], program);
		regVar.setComment("My Comment2");
		f.addLocalVariable(regVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Variable[] vars = f.getLocalVariables();
		assertEquals(2, vars.length);
		for (int i = 0; i < 2; i++) {
			int n = i + 1;
			Variable var = vars[i];
			assertTrue(var.isRegisterVariable());
			assertEquals("TestReg" + n, var.getName());
			assertEquals(n * 4, var.getFirstUseOffset());
			assertEquals("My Comment" + n, var.getComment());
			assertEquals(f, var.getFunction());
			assertEquals(regs[n], var.getRegister());
			assertTrue(dt[n].isEquivalent(var.getDataType()));
		}
	}

	@Test
	public void testSetMemoryParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		LocalVariableImpl memVar = new LocalVariableImpl("TestMem0", 0, dt[0], addr(0), program);
		memVar.setComment("My Comment0");
		f.addParameter(memVar, SourceType.USER_DEFINED);
		memVar = new LocalVariableImpl("TestMem1", 0, dt[1], addr(4), program);
		memVar.setComment("My Comment1");
		f.addParameter(memVar, SourceType.USER_DEFINED);
		memVar = new LocalVariableImpl("TestMem2", 0, dt[2], addr(8), program);
		memVar.setComment("My Comment2");
		f.addParameter(memVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Parameter[] params = f.getParameters();
		assertEquals(3, params.length);
		for (int i = 0; i < 3; i++) {
			Parameter param = params[i];
			assertTrue(param.isMemoryVariable());
			assertEquals("TestMem" + i, param.getName());
			assertEquals(i, param.getOrdinal());
			assertEquals("My Comment" + i, param.getComment());
			assertEquals(f, param.getFunction());
			assertEquals(addr(i * 4), param.getMinAddress());
			assertTrue(dt[i].isEquivalent(param.getDataType()));
		}
	}

	@Test
	public void testSetDuplicateMemoryParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new ByteDataType(), new WordDataType(), new Pointer16DataType() };

		LocalVariableImpl memVar = new LocalVariableImpl("TestMem0", 0, dt[0], addr(0), program);
		memVar.setComment("My Comment0");
		f.addParameter(memVar, SourceType.USER_DEFINED);
		memVar = new LocalVariableImpl("TestMem1", 0, dt[1], addr(4), program);
		memVar.setComment("My Comment1");
		f.addParameter(memVar, SourceType.USER_DEFINED);
		memVar = new LocalVariableImpl("TestMem2", 0, dt[2], addr(0), program);
		memVar.setComment("My Comment2");
		f.addParameter(memVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Parameter[] params = f.getParameters();
		assertEquals(2, params.length);
		assertTrue(params[0].isMemoryVariable());
		assertTrue(params[1].isMemoryVariable());
		assertEquals(addr(4), params[0].getMinAddress());
		assertEquals(addr(0), params[1].getMinAddress());
		for (int i = 0; i < 2; i++) {
			int n = i + 1;
			Parameter param = params[i];
			assertEquals("TestMem" + n, param.getName());
			assertEquals(i, param.getOrdinal());
			assertEquals("My Comment" + n, param.getComment());
			assertEquals(f, param.getFunction());
			assertTrue(dt[n].isEquivalent(param.getDataType()));
		}
	}

	@Test
	public void testRemoveRegisterParameter() throws Exception {
		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		f.setCustomVariableStorage(true);

		DataType[] dt =
			new DataType[] { new LongDataType(), new WordDataType(), new Pointer16DataType() };

		Register[] regs =
			new Register[] { functionManager.getProgram().getProgramContext().getRegister("r1"),
				functionManager.getProgram().getProgramContext().getRegister("r2l"),
				functionManager.getProgram().getProgramContext().getRegister("r3l") };

		LocalVariableImpl regVar = new LocalVariableImpl("TestReg0", 0, dt[0], regs[0], program);
		regVar.setComment("My Comment0");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg1", 0, dt[1], regs[1], program);
		regVar.setComment("My Comment1");
		f.addParameter(regVar, SourceType.USER_DEFINED);
		regVar = new LocalVariableImpl("TestReg2", 0, dt[2], regs[2], program);
		regVar.setComment("My Comment2");
		f.addParameter(regVar, SourceType.USER_DEFINED);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));

		f.removeParameter(1);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		Parameter[] params = f.getParameters();
		assertEquals(2, params.length);
		int n = 0;
		for (int i = 0; i < 2; i++) {
			if (i == 1) {
				n = 2;
			}
			Parameter param = params[i];
			assertTrue(param.isRegisterVariable());
			assertEquals("TestReg" + n, param.getName());
			assertEquals(i, param.getOrdinal());
			assertEquals("My Comment" + n, param.getComment());
			assertEquals(f, param.getFunction());
			assertEquals(regs[n], param.getRegister());
			assertTrue(dt[n].isEquivalent(param.getDataType()));
		}
	}

	@Test
	public void testSetInline() throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertTrue(!f.isInline());

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_INLINE);

		f.setInline(true);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertTrue(f.isInline());

		lastCaptureRecord = null;

		f.setInline(false);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertTrue(!f.isInline());

	}

	@Test
	public void testSetNoReturn() throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertTrue(!f.hasNoReturn());

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_NORETURN);

		f.setNoReturn(true);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertTrue(f.hasNoReturn());

		lastCaptureRecord = null;

		f.setNoReturn(false);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertTrue(!f.hasNoReturn());
	}

	@Test
	public void testSetCallFixup() throws Exception {

		Function f = createFunction("foo", addr(100), new AddressSet(addr(100), addr(200)));
		assertNull(f.getCallFixup());

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_CALL_FIXUP);

		f.setCallFixup("TEST");

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertEquals("TEST", f.getCallFixup());

		lastCaptureRecord = null;

		f.setCallFixup(null);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f = functionManager.getFunctionAt(addr(100));
		assertNull(f.getCallFixup());

	}

	@Test
	public void testSetThunkFunction() throws Exception {

		Function f1 = createFunction("foo1", addr(0x100), new AddressSet(addr(0x100), addr(0x200)));
		assertTrue(!f1.isThunk());
		assertNull(f1.getThunkedFunction(false));

		Function f2 = functionManager.createFunction(null, addr(0x300),
			new AddressSet(addr(0x300), addr(0x400)), SourceType.DEFAULT);
		assertEquals("FUN_00000300", f2.getName());
		assertTrue(!f2.isThunk());
		assertNull(f2.getThunkedFunction(false));

		f1.setReturn(ByteDataType.dataType, VariableStorage.UNASSIGNED_STORAGE,
			SourceType.USER_DEFINED);

		captureFunctionChangeEvent("foo1", ChangeManager.FUNCTION_CHANGED_PARAMETERS);

		f1.addParameter(new ParameterImpl("p1", IntegerDataType.dataType, program),
			SourceType.USER_DEFINED);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
		assertEquals(1, captureRecords.size());

		captureFunctionChangeEvent("FUN_00000300", -1);

		f1.addParameter(new ParameterImpl("p2", IntegerDataType.dataType, program),
			SourceType.USER_DEFINED);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNull(lastCaptureRecord);// no event expected for function "foo2" (not yet a thunk)

		functionManager.invalidateCache(false);
		f1 = functionManager.getFunctionAt(addr(0x100));
		f2 = functionManager.getFunctionAt(addr(0x300));
		assertEquals("byte foo1(int p1, int p2)", f1.getPrototypeString(false, false));
		assertEquals("undefined FUN_00000300()", f2.getPrototypeString(false, false));

		captureFunctionChangeEvent("foo1", ChangeManager.FUNCTION_CHANGED_THUNK);

		f2.setThunkedFunction(f1);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);

		functionManager.invalidateCache(false);
		f1 = functionManager.getFunctionAt(addr(0x100));
		f2 = functionManager.getFunctionAt(addr(0x300));

		assertEquals("foo1", f2.getName());
		assertTrue(f2.isThunk());
		assertEquals(f1, f2.getThunkedFunction(false));

		assertEquals("byte foo1(int p1, int p2)", f1.getPrototypeString(false, false));
		assertEquals("byte foo1(int p1, int p2)", f2.getPrototypeString(false, false));// TODO: Not sure what the correct behavior should be?

		captureChangeEvent(ChangeManager.DOCR_SYMBOL_RENAMED, -1);// two events (both functions)

		f1.setName("fum", SourceType.USER_DEFINED);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
		assertEquals(2, captureRecords.size());

		ProgramChangeRecord pcRec = captureRecords.get(0);
		FunctionSymbol s = (FunctionSymbol) pcRec.getObject();
		assertEquals(addr(0x100), s.getAddress());
		assertEquals("foo1", pcRec.getOldValue());
		assertEquals("fum", pcRec.getNewValue());

		pcRec = captureRecords.get(1);
		s = (FunctionSymbol) pcRec.getObject();
		assertEquals(addr(0x300), s.getAddress());
		assertEquals("foo1", pcRec.getOldValue());
		assertEquals("fum", pcRec.getNewValue());

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_PARAMETERS);// two events (both functions)

		f1.addParameter(new ParameterImpl("p3", IntegerDataType.dataType, program),
			SourceType.USER_DEFINED);// add to "thunked" func

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
		assertEquals(2, captureRecords.size());

		pcRec = captureRecords.get(0);
		Function f = (Function) pcRec.getObject();
		assertEquals("fum", f.getName());
		assertEquals(addr(0x100), f.getEntryPoint());

		pcRec = captureRecords.get(1);
		f = (Function) pcRec.getObject();
		assertTrue(f.isThunk());
		assertEquals("fum", f.getName());
		assertEquals(addr(0x300), f.getEntryPoint());

		captureChangeEvent(ChangeManager.DOCR_FUNCTION_CHANGED,
			ChangeManager.FUNCTION_CHANGED_PARAMETERS);// two events (both functions)

		f2.addParameter(new ParameterImpl("p4", IntegerDataType.dataType, program),
			SourceType.USER_DEFINED);// add to thunk

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
		assertEquals(2, captureRecords.size());

		pcRec = captureRecords.get(0);
		f = (Function) pcRec.getObject();
		assertEquals("fum", f.getName());
		assertEquals(addr(0x100), f.getEntryPoint());

		pcRec = captureRecords.get(1);
		f = (Function) pcRec.getObject();
		assertTrue(f.isThunk());
		assertEquals("fum", f.getName());
		assertEquals(addr(0x300), f.getEntryPoint());

		captureChangeEvent(ChangeManager.DOCR_SYMBOL_RENAMED, -1);

		// Change thunk name (hides thunked function name)
		f2.setName("test", SourceType.USER_DEFINED);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
		assertEquals(1, captureRecords.size());

		pcRec = captureRecords.get(0);
		s = (FunctionSymbol) pcRec.getObject();
		assertEquals(addr(0x300), s.getAddress());
		assertEquals("fum", pcRec.getOldValue());
		assertEquals("test", pcRec.getNewValue());

		assertEquals("test", f2.getName());
		assertEquals("fum", f1.getName());

		assertEquals("byte test(int p1, int p2, int p3, int p4)",
			f2.getPrototypeString(false, false));
		assertEquals("byte fum(int p1, int p2, int p3, int p4)",
			f1.getPrototypeString(false, false));

		// Restore thunk to name to its default (pass-thru thunked function name)
		f2.setName(null, SourceType.DEFAULT);

		program.flushEvents();
		waitForPostedSwingRunnables();
		assertNotNull(lastCaptureRecord);
		assertEquals(2, captureRecords.size());

		pcRec = captureRecords.get(0);
		s = (FunctionSymbol) pcRec.getObject();
		assertEquals(addr(0x300), s.getAddress());
		assertEquals("fum", pcRec.getOldValue());
		assertEquals("test", pcRec.getNewValue());

		assertEquals("fum", f2.getName());
		assertEquals("fum", f1.getName());

		assertEquals("byte fum(int p1, int p2, int p3, int p4)",
			f2.getPrototypeString(false, false));
		assertEquals("byte fum(int p1, int p2, int p3, int p4)",
			f1.getPrototypeString(false, false));

		assertEquals(f2.getName(true), f1.getName(true));

		SymbolTable symbolTable = program.getSymbolTable();
		GhidraClass myClass = symbolTable.createClass(null, "MyClass", SourceType.USER_DEFINED);
		f1.setParentNamespace(myClass);

		f1.setParentNamespace(myClass);

		assertEquals(f2.getName(true), f1.getName(true));

		f1.setCallingConvention(CompilerSpec.CALLING_CONVENTION_thiscall);

		assertEquals("byte fum(MyClass * this, int p1, int p2, int p3, int p4)",
			f2.getPrototypeString(false, false));
		assertEquals("byte fum(MyClass * this, int p1, int p2, int p3, int p4)",
			f1.getPrototypeString(false, false));

		assertEquals(f1.getSymbol(), symbolTable.getSymbol("fum", f1.getEntryPoint(), myClass));
		assertNull(symbolTable.getSymbol("fum", f2.getEntryPoint(), myClass));

		SymbolIterator symbols = symbolTable.getSymbols(myClass);
		assertEquals(f1.getSymbol(), symbols.next());
		assertFalse(symbols.hasNext());

		symbols = symbolTable.getSymbols(program.getGlobalNamespace());
		while (symbols.hasNext()) {
			Symbol sym = symbols.next();
			assertFalse(f2.getSymbol() == sym);
			assertFalse(f2.getSymbol().equals(sym));
		}
	}

	@Test
	public void testPromoteLocalUserLabelsToGlobal() throws Exception {

		Function foo2 = createFunction("foo2", addr(201), new AddressSet(addr(201), addr(249)));

		// Add symbols to verify proper global conversion
		SymbolTable symbolTable = program.getSymbolTable();
		symbolTable.createLabel(addr(220), "LAB_Test", SourceType.USER_DEFINED); // global - should keep
		symbolTable.createLabel(addr(220), "LAB_Test", foo2, SourceType.USER_DEFINED); // local - should remove
		symbolTable.createLabel(addr(220), "LAB_TestA", foo2, SourceType.USER_DEFINED); // local - should keep
		symbolTable.createLabel(addr(220), "LAB_TestB", foo2, SourceType.ANALYSIS); // local - should remove
		symbolTable.createLabel(addr(224), "LAB_Test", foo2, SourceType.USER_DEFINED); // local - should keep

		assertNotNull(symbolTable.getGlobalSymbol("LAB_Test", addr(220)));
		assertNotNull(symbolTable.getSymbol("LAB_Test", addr(220), foo2));
		assertNotNull(symbolTable.getSymbol("LAB_TestA", addr(220), foo2));
		assertNotNull(symbolTable.getSymbol("LAB_TestB", addr(220), foo2));
		assertNotNull(symbolTable.getSymbol("LAB_Test", addr(224), foo2));

		foo2.promoteLocalUserLabelsToGlobal();

		foo2.getSymbol().delete(); // remove function (any remaining local symbols will be removed as well)

		// verify that only two symbols reside at addr(220)
		assertEquals(2, symbolTable.getSymbols(addr(220)).length);

		assertNotNull(symbolTable.getGlobalSymbol("LAB_Test", addr(220)));
		assertNotNull(symbolTable.getGlobalSymbol("LAB_TestA", addr(220)));
		assertNotNull(symbolTable.getGlobalSymbol("LAB_Test", addr(224)));

		assertTrue(program.getSymbolTable()
				.getPrimarySymbol(
					addr(201))
				.getSymbolType() != SymbolType.FUNCTION);
	}

}
