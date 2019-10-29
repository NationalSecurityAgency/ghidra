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
package ghidra.app.plugin.core.function.editor;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.InvalidInputException;

public class FunctionEditorModelTest extends AbstractGenericTest {

	private FunctionEditorModel model;
	private volatile boolean dataChangeCalled;
	private Structure bigStruct;
	private ProgramDB program;
	private DataTypeManagerService service;
	private volatile boolean tableRowsChanged;

	class MyModelChangeListener implements ModelChangeListener {
		@Override
		public void dataChanged() {
			dataChangeCalled = true;
		}

		@Override
		public void tableRowsChanged() {
			tableRowsChanged = true;
		}
	}

	@Before
	public void setUp() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X86);
		builder.createMemory("block1", "1000", 1000);
		Function fun = builder.createEmptyFunction("bob", "1000", 20, new VoidDataType());
		program = builder.getProgram();
		bigStruct = new StructureDataType("bigStruct", 20);
		resolveBigStruct();
		model = new FunctionEditorModel(null /* use default parser*/, fun);
		model.setModelChangeListener(new MyModelChangeListener());
	}

	private void setupX64windows() throws Exception {
		// use different language: x64-windows
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._X64, "windows", null);
		builder.createMemory("block1", "1000", 1000);
		Function fun = builder.createEmptyFunction("bob", "1000", 20, new VoidDataType());
		program = builder.getProgram();
		resolveBigStruct();
		model = new FunctionEditorModel(null /* use default parser*/, fun);
		model.setModelChangeListener(new MyModelChangeListener());
	}

	private void resolveBigStruct() {
		int txId = program.startTransaction("Resolve bigStruct");
		try {
			program.getDataTypeManager().resolve(bigStruct, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testSetName() {
		assertDataChangedCallback(false);
		model.setName("AAA");
		assertDataChangedCallback(true);
		assertEquals("AAA", model.getName());
		assertEquals("void AAA (void)", getSignatureText());
		assertTrue(model.isValid());
	}

	@Test
	public void testSetEmptyName() {
		assertDataChangedCallback(false);
		model.setName("");
		assertDataChangedCallback(true);
		assertEquals("", model.getName());
		assertEquals("void ? (void)", getSignatureText());
		assertTrue(!model.isValid());
		assertEquals("Missing function name", model.getStatusText());
	}

	@Test
	public void testsetRawReturnType() {
		assertDataChangedCallback(false);
		model.setFormalReturnType(new LongDataType());
		assertDataChangedCallback(true);
		assertEquals(new LongDataType().getName(), model.getFormalReturnType().getName());
		assertEquals("long bob (void)", getSignatureText());
		assertTrue(model.isValid());

	}

	@Test
	public void testVarArgs() {
		assertDataChangedCallback(false);
		model.setHasVarArgs(true);
		assertDataChangedCallback(true);
		assertTrue(model.hasVarArgs());
		assertEquals("void bob (...)", getSignatureText());
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());

		// turn them back off

		model.setHasVarArgs(false);
		assertTrue(!model.hasVarArgs());
		assertEquals("void bob (void)", getSignatureText());
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());

	}

	@Test
	public void testCustomStorage() {
		assertFalse(model.canCustomizeStorage());
		model.setUseCustomizeStorage(true);
		assertTrue(model.canCustomizeStorage());
		model.setUseCustomizeStorage(false);
		assertFalse(model.canCustomizeStorage());
	}

	@Test
	public void testInLineAndCallFixup() {
		// if inline is set, call fixup must be -NONE-, and vise-versa
		model.setIsInLine(true);
		assertTrue(model.isInLine());
		assertTrue(model.isValid());
		assertEquals("-NONE-", model.getCallFixupName());

		String callFixupName = model.getCallFixupNames()[0];
		model.setCallFixupName(callFixupName);
		assertEquals(callFixupName, model.getCallFixupName());
		assertTrue(!model.isInLine());

		model.setIsInLine(true);
		assertTrue(model.isInLine());
		assertTrue(model.isValid());
		assertEquals("-NONE-", model.getCallFixupName());

	}

	@Test
	public void testNoReturn() {
		assertTrue(!model.isNoReturn());
		model.setNoReturn(true);
		assertTrue(model.isNoReturn());
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());
	}

	@Test
	public void testAddParams() {
		model.addParameter();
		List<ParamInfo> parameters = model.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("param_1", parameters.get(0).getName());

		model.addParameter();
		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals("param_1", parameters.get(0).getName());
		assertEquals("param_2", parameters.get(1).getName());

		// the last added parameter should be selected. Remember first row is return type
		assertEquals(2, model.getSelectedParameterRows()[0]);
		waitForSwing();
		assertTrue(tableRowsChanged);
	}

	@Test
	public void testRemoveFirstParam() {
		model.addParameter();
		model.addParameter();
		model.addParameter();
		assertEquals(3, model.getParameters().size());

		model.setSelectedParameterRow(new int[0]);

		// none selected, so can't remove
		assertEquals(0, model.getSelectedParameterRows().length);
		assertTrue(!model.canRemoveParameters());

		// select the first entry
		model.setSelectedParameterRow(new int[] { 1 });

		assertEquals(1, model.getSelectedParameterRows().length);
		assertTrue(model.canRemoveParameters());
		model.removeParameters();// remove all selected rows, which is just the first row right now

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals("param_1", parameters.get(0).getName());
		assertEquals("param_2", parameters.get(1).getName());

		// check that the 0 row is still selected
		assertEquals(1, model.getSelectedParameterRows()[0]);
	}

	@Test
	public void testRemoveLastParam() {
		model.addParameter();
		model.addParameter();
		model.addParameter();
		assertEquals(3, model.getParameters().size());

		// select the last entry
		model.setSelectedParameterRow(new int[] { 3 });

		assertEquals(1, model.getSelectedParameterRows().length);
		assertTrue(model.canRemoveParameters());
		model.removeParameters();// remove all selected rows, which is just the first row right now

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals("param_1", parameters.get(0).getName());
		assertEquals("param_2", parameters.get(1).getName());

		// check that the last row is selected
		assertEquals(2, model.getSelectedParameterRows()[0]);
	}

	@Test
	public void testRemoveMultipleParams() {
		model.addParameter();
		model.addParameter();
		model.addParameter();
		assertEquals(3, model.getParameters().size());

		// select the first and last entry
		model.setSelectedParameterRow(new int[] { 1, 3 });

		assertEquals(2, model.getSelectedParameterRows().length);
		assertTrue(model.canRemoveParameters());
		model.removeParameters();// remove all selected rows, which is just the first row right now

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(1, parameters.size());
		assertEquals("param_1", parameters.get(0).getName());

		// check that the only row is selected
		assertEquals(1, model.getSelectedParameterRows()[0]);
	}

	@Test
	public void testRemoveAllParams() {
		model.addParameter();
		model.addParameter();
		model.addParameter();
		assertEquals(3, model.getParameters().size());

		// select all params
		model.setSelectedParameterRow(new int[] { 1, 2, 3 });

		assertEquals(3, model.getSelectedParameterRows().length);
		assertTrue(model.canRemoveParameters());
		model.removeParameters();// remove all selected rows, which is just the first row right now

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(0, parameters.size());

		// check that the selection is empty
		assertEquals(0, model.getSelectedParameterRows().length);
	}

	@Test
	public void testMoveUpDownEnablement() {
		model.addParameter();
		model.addParameter();
		model.addParameter();

		// no selection, both buttons disabled
		model.setSelectedParameterRow(new int[0]);
		assertTrue(!model.canMoveParameterUp());
		assertTrue(!model.canMoveParameterDown());

		// multiple selection, both buttons disabled
		model.setSelectedParameterRow(new int[] { 1, 2 });
		assertTrue(!model.canMoveParameterUp());
		assertTrue(!model.canMoveParameterDown());

		// select the first param, up button disabled, down button enabled
		model.setSelectedParameterRow(new int[] { 1 });
		assertTrue(!model.canMoveParameterUp());
		assertTrue(model.canMoveParameterDown());

		// select the middle row, both buttons enabled
		model.setSelectedParameterRow(new int[] { 2 });
		assertTrue(model.canMoveParameterUp());
		assertTrue(model.canMoveParameterDown());

	}

	@Test
	public void testMoveUp() {
		model.addParameter();
		model.addParameter();
		model.addParameter();

		List<ParamInfo> params = model.getParameters();
		model.setParameterName(params.get(0), "p1");
		model.setParameterName(params.get(1), "p2");
		model.setParameterName(params.get(2), "p3");

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals("p1", parameters.get(0).getName());
		assertEquals("p2", parameters.get(1).getName());
		assertEquals("p3", parameters.get(2).getName());

		// select the last row
		model.setSelectedParameterRow(new int[] { 3 });

		model.moveSelectedParameterUp();

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals("p1", parameters.get(0).getName());
		assertEquals("p3", parameters.get(1).getName());
		assertEquals("p2", parameters.get(2).getName());
		// check the selected row moved up as well
		assertEquals(1, model.getSelectedParameterRows().length);
		assertEquals(2, model.getSelectedParameterRows()[0]);

		model.moveSelectedParameterUp();

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals("p3", parameters.get(0).getName());
		assertEquals("p1", parameters.get(1).getName());
		assertEquals("p2", parameters.get(2).getName());
		// check the selected row moved up as well
		assertEquals(1, model.getSelectedParameterRows().length);
		assertEquals(1, model.getSelectedParameterRows()[0]);
		assertTrue(!model.canMoveParameterUp());
	}

	@Test
	public void testMoveDown() {
		model.addParameter();
		model.addParameter();
		model.addParameter();

		List<ParamInfo> params = model.getParameters();
		model.setParameterName(params.get(0), "p1");
		model.setParameterName(params.get(1), "p2");
		model.setParameterName(params.get(2), "p3");

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals("p1", parameters.get(0).getName());
		assertEquals("p2", parameters.get(1).getName());
		assertEquals("p3", parameters.get(2).getName());

		// select the first row
		model.setSelectedParameterRow(new int[] { 1 });

		model.moveSelectedParameterDown();

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals("p2", parameters.get(0).getName());
		assertEquals("p1", parameters.get(1).getName());
		assertEquals("p3", parameters.get(2).getName());
		// check the selected row moved down as well
		assertEquals(1, model.getSelectedParameterRows().length);
		assertEquals(2, model.getSelectedParameterRows()[0]);

		model.moveSelectedParameterDown();

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals("p2", parameters.get(0).getName());
		assertEquals("p3", parameters.get(1).getName());
		assertEquals("p1", parameters.get(2).getName());
		// check the selected row moved down as well
		assertEquals(1, model.getSelectedParameterRows().length);
		assertEquals(3, model.getSelectedParameterRows()[0]);
		assertTrue(!model.canMoveParameterDown());
	}

	@Test
	public void testNameParameter() {
		model.addParameter();
		model.addParameter();

		List<ParamInfo> parameters = model.getParameters();
		ParamInfo param = parameters.get(0);

		dataChangeCalled = false;
		model.setParameterName(param, "abc");
		assertDataChangedCallback(true);

		parameters = model.getParameters();
		assertEquals("abc", parameters.get(0).getName());

		assertEquals("void bob (undefined abc, undefined param_2)", getSignatureText());
	}

	@Test
	public void testParamNameHasInvalidChars() {
		model.addParameter();
		model.addParameter();

		List<ParamInfo> parameters = model.getParameters();
		ParamInfo param = parameters.get(0);
		model.setParameterName(param, "a b");

		parameters = model.getParameters();
		assertEquals("a b", parameters.get(0).getName());

		assertTrue(!model.isValid());
		assertEquals("Invalid name for parameter 1: a b", model.getStatusText());

		assertEquals("void bob (undefined a b, undefined param_2)", getSignatureText());
	}

	@Test
	public void testDuplicateParamNames() {
		model.addParameter();
		model.addParameter();

		List<ParamInfo> parameters = model.getParameters();
		ParamInfo param = parameters.get(0);
		model.setParameterName(param, "abc");
		model.setParameterName(parameters.get(1), "abc");
		parameters = model.getParameters();
		assertEquals("abc", parameters.get(0).getName());
		assertEquals("abc", parameters.get(1).getName());

		assertTrue(!model.isValid());
		assertEquals("Duplicate parameter name: abc", model.getStatusText());

		assertEquals("void bob (undefined abc, undefined abc)", getSignatureText());
	}

	@Test
	public void testReturnStorageSizeNotMatchReturnTypeSize() throws InvalidInputException {
		model.setUseCustomizeStorage(true);
		assertTrue(model.isValid());

		model.setFormalReturnType(DoubleDataType.dataType);// unconstrained storage
		model.setReturnStorage(new VariableStorage(program, program.getRegister("EAX")));
		assertTrue(model.isValid());
		assertEquals("", model.getStatusText());

		model.setFormalReturnType(LongLongDataType.dataType);// constrained storage
		assertTrue(!model.isValid());
		assertEquals("Insufficient Return Storage (4-bytes) for datatype (8-bytes)",
			model.getStatusText());
	}

	@Test
	public void testInvalidWhenStorageNotSpecified() {
		model.setUseCustomizeStorage(true);
		model.addParameter();
		ParamInfo paramInfo = model.getParameters().get(0);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, paramInfo.getStorage());
		assertTrue(model.isValid());
	}

	@Test
	public void testAutoStorageFix() {
		model.addParameter();
		ParamInfo paramInfo = model.getParameters().get(0);// param_0@Stack[0x4]:4
		model.setUseCustomizeStorage(true);
		Varnode v = paramInfo.getStorage().getFirstVarnode();
		assertEquals(1, v.getSize());
		assertEquals(4, v.getOffset());
		model.setParameterFormalDataType(paramInfo, new Undefined8DataType());
		assertTrue(model.isValid());
		v = paramInfo.getStorage().getFirstVarnode();
		assertEquals(8, v.getSize());
		assertEquals(4, v.getOffset());// assumes little endian
	}

	@Test
	public void testAutoStorageFixReg() throws Exception {
		model.addParameter();
		ParamInfo paramInfo = model.getParameters().get(0);
		model.setUseCustomizeStorage(true);

		model.setParameterFormalDataType(paramInfo, new Undefined2DataType());
		assertTrue(model.getStatusText(), model.isValid());
		Varnode v = paramInfo.getStorage().getFirstVarnode();
		assertEquals(2, v.getSize());
		assertEquals(4, v.getOffset());

		model.setParameterStorage(paramInfo,
			new VariableStorage(program, program.getRegister("AX")));
		assertTrue(model.getStatusText(), model.isValid());
		v = paramInfo.getStorage().getFirstVarnode();
		assertEquals(2, v.getSize());
		assertEquals(program.getRegister("AX"), paramInfo.getStorage().getRegister());

		model.setParameterFormalDataType(paramInfo, new Undefined4DataType());
		assertTrue(model.getStatusText(), model.isValid());
		v = paramInfo.getStorage().getFirstVarnode();
		assertEquals(4, v.getSize());
		assertEquals(program.getRegister("EAX"), paramInfo.getStorage().getRegister());
	}

	@Test
	public void testInsufficientStorageSize() throws Exception {
		model.addParameter();
		ParamInfo paramInfo = model.getParameters().get(0);
		paramInfo.setFormalDataType(Undefined4DataType.dataType);
		model.setUseCustomizeStorage(true);

		model.setParameterStorage(paramInfo,
			new VariableStorage(program, program.getRegister("EAX")));
		assertTrue(model.getStatusText(), model.isValid());
		Varnode v = paramInfo.getStorage().getFirstVarnode();
		assertEquals(4, v.getSize());
		assertEquals(program.getRegister("EAX"), paramInfo.getStorage().getRegister());

		model.setParameterFormalDataType(paramInfo, Undefined.getUndefinedDataType(8));
		assertTrue(!model.isValid());
		assertEquals(
			"Insufficient storage (4-bytes) for datatype (8-bytes) assigned to parameter 1",
			model.getStatusText());
	}

	@Test
	public void testInsufficientStorageSize2() throws Exception {
		model.addParameter();
		ParamInfo paramInfo = model.getParameters().get(0);
		paramInfo.setFormalDataType(Undefined4DataType.dataType);
		model.setUseCustomizeStorage(true);

		model.setParameterStorage(paramInfo,
			new VariableStorage(program, program.getRegister("AX")));
		assertTrue(!model.isValid());
		assertEquals(
			"Insufficient storage (2-bytes) for datatype (4-bytes) assigned to parameter 1",
			model.getStatusText());
	}

	@Test
	public void testTurningOffCustomStorageFixesReturnStorage() throws Exception {
		model.setFormalReturnType(new Undefined4DataType());
		VariableStorage returnStorage = model.getReturnStorage();
		assertNotNull(returnStorage);
		Varnode[] varnodes = returnStorage.getVarnodes();
		assertEquals(1, varnodes.length);
		Varnode varnode = varnodes[0];
		Address address = varnode.getAddress();// check address is EAX
		assertEquals(0, address.getOffset());
		assertEquals("register", address.getAddressSpace().getName());

		// turn on custom storage
		model.setUseCustomizeStorage(true);

		Address other = address.getAddressSpace().getAddress(8);
		model.setReturnStorage(new VariableStorage(program, other, 4));

		returnStorage = model.getReturnStorage();
		assertNotNull(returnStorage);
		varnodes = returnStorage.getVarnodes();
		assertEquals(1, varnodes.length);
		varnode = varnodes[0];
		address = varnode.getAddress();// make sure change took effect
		assertEquals(8, address.getOffset());
		assertEquals("register", address.getAddressSpace().getName());

		// turn off custom storage and check it goes back to EAX
		model.setUseCustomizeStorage(false);

		returnStorage = model.getReturnStorage();
		assertNotNull(returnStorage);
		varnodes = returnStorage.getVarnodes();
		assertEquals(1, varnodes.length);
		varnode = varnodes[0];
		address = varnode.getAddress();// make sure its back to EAX (0)
		assertEquals(0, address.getOffset());
		assertEquals("register", address.getAddressSpace().getName());

	}

	@Test
	public void testChangingSignatureFieldTextSetsParsingMode() {
		assertTrue(!model.isInParsingMode());
		model.setSignatureFieldText("void bob (void)a");
		assertTrue(model.isInParsingMode());
		assertEquals(FunctionEditorModel.PARSING_MODE_STATUS_TEXT, model.getStatusText());

		model.setSignatureFieldText("void bob (void)");
		assertTrue(!model.isInParsingMode());
		assertEquals("", model.getStatusText());

	}

	@Test
	public void testParsingGoodSimpleSignature() throws Exception {
		assertEquals("void bob (void)", getSignatureText());
		assertEquals(0, model.getParameters().size());

		model.setSignatureFieldText("void   bob    (   int   a  ,  int    c)");
		assertTrue(model.isInParsingMode());
		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("void bob (int a, int c)", getSignatureText());
		assertEquals(2, model.getParameters().size());
	}

	@Test
	public void testParsingAnotherGoodSimpleSignature() throws Exception {
		assertTrue(!model.isInParsingMode());
		model.setSignatureFieldText("void bob (int a)");
		assertTrue(model.isInParsingMode());

		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("void bob (int a)", getSignatureText());
	}

	@Test
	public void testParsingSignatureWithVarArgs() throws Exception {
		assertEquals("void bob (void)", getSignatureText());
		assertEquals(0, model.getParameters().size());

		model.setSignatureFieldText("void bob(int a, ...)");
		assertTrue(model.isInParsingMode());
		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("void bob (int a, ...)", getSignatureText());
		assertEquals(1, model.getParameters().size());
		assertTrue(model.hasVarArgs());
	}

	@Test
	public void testParsingSignatureWithForcedIndirect() throws Exception {
		setupX64windows();

		assertFalse(model.canCustomizeStorage());

		assertEquals("void bob (void)", getSignatureText());
		assertEquals(0, model.getParameters().size());
		assertEquals("unknown", model.getCallingConventionName());

		model.setSignatureFieldText("bigStruct bob (bigStruct p1, bigStruct p2)");
		assertTrue(model.isInParsingMode());
		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("bigStruct bob (bigStruct p1, bigStruct p2)", getSignatureText());

		assertTrue(bigStruct.isEquivalent(model.getFormalReturnType()));
		VariableStorage returnStorage = model.getReturnStorage();
		assertTrue(returnStorage.isForcedIndirect());
		assertEquals("RAX:8 (ptr)", returnStorage.toString());

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		assertFalse(model.hasVarArgs());

		ParamInfo paramInfo = parameters.get(0);
		VariableStorage paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isAutoStorage());
		assertEquals("RCX:8 (auto)", paramStorage.toString());
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());

		paramInfo = parameters.get(1);
		paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isForcedIndirect());
		assertEquals("RDX:8 (ptr)", paramStorage.toString());
		assertEquals("p1", paramInfo.getName());

		paramInfo = parameters.get(2);
		paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isForcedIndirect());
		assertEquals("R8:8 (ptr)", paramStorage.toString());
		assertEquals("p2", paramInfo.getName());

	}

	@Test
	public void testParsingSignatureWithForcedIndirectAndAuto() throws Exception {
		setupX64windows();

		assertFalse(model.canCustomizeStorage());

		model.setCallingConventionName("__thiscall");

		assertEquals("void bob ()", getSignatureText());
		List<ParamInfo> parameters = model.getParameters();
		assertEquals(1, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		assertEquals("__thiscall", model.getCallingConventionName());

		ParamInfo paramInfo = parameters.get(0);
		VariableStorage paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isAutoStorage());
		assertEquals("RCX:8 (auto)", paramStorage.toString());
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());

		model.setSignatureFieldText("bigStruct bob (bigStruct p1, bigStruct p2)");
		assertTrue(model.isInParsingMode());
		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("bigStruct bob (bigStruct p1, bigStruct p2)", getSignatureText());

		assertTrue(bigStruct.isEquivalent(model.getFormalReturnType()));
		VariableStorage returnStorage = model.getReturnStorage();
		assertTrue(returnStorage.isForcedIndirect());
		assertEquals("RAX:8 (ptr)", returnStorage.toString());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(2, model.getAutoParamCount());
		assertFalse(model.hasVarArgs());

		paramInfo = parameters.get(0);
		paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isAutoStorage());
		assertEquals("RCX:8 (auto)", paramStorage.toString());
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());

		paramInfo = parameters.get(1);
		paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isAutoStorage());
		assertEquals("RDX:8 (auto)", paramStorage.toString());
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());

		paramInfo = parameters.get(2);
		paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isForcedIndirect());
		assertEquals("R8:8 (ptr)", paramStorage.toString());
		assertEquals("p1", paramInfo.getName());

		paramInfo = parameters.get(3);
		paramStorage = paramInfo.getStorage();
		assertTrue(paramStorage.isForcedIndirect());
		assertEquals("R9:8 (ptr)", paramStorage.toString());
		assertEquals("p2", paramInfo.getName());

	}

	@Test
	public void testParsingBadSignature() throws Exception {
		assertEquals("void bob (void)", getSignatureText());
		assertEquals(0, model.getParameters().size());

		model.setSignatureFieldText("void bob(int a)asdf");
		assertTrue(model.isInParsingMode());
		try {
			model.parseSignatureFieldText();
			Assert.fail("Expected parse exception");
		}
		catch (ParseException e) {
			// expected
		}
	}

	@Test
	public void testParsingSignatureWithInvalid_C_Chars() throws Exception {
		model.setSignatureFieldText("void bob@1234(int a)");
		assertTrue(model.isInParsingMode());

		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("void bob@1234 (int a)", getSignatureText());
	}

	@Test
	public void testApplyFunctionNameChange() throws Exception {
		model.setSignatureFieldText("int joe()");
		model.parseSignatureFieldText();
		model.apply();
		Function function = model.getFunction();
		assertEquals("joe", function.getName());
	}

	@Test
	public void testApplyFunctionChanges() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b)");
		model.parseSignatureFieldText();
		model.apply();
		Function function = model.getFunction();
		assertEquals("joe", function.getName());
		assertEquals("int", function.getReturnType().toString());
		assertEquals(2, function.getParameterCount());
		Parameter[] parameters = function.getParameters();
		assertEquals("a", parameters[0].getName());
		assertEquals("b", parameters[1].getName());
		assertEquals("int", parameters[0].getDataType().getName());
		assertEquals("int", parameters[1].getDataType().getName());
	}

	@Test
	public void testRemoveParameters() throws Exception {
		ProgramBuilder builder = new ProgramBuilder();
		builder.createMemory("block2", "1000", 1000);
		program = builder.getProgram();
		Parameter param = new ParameterImpl("a", new IntegerDataType(), program);
		Function fun = builder.createEmptyFunction("bob", "1000", 20, new VoidDataType(), param);
		assertEquals(1, fun.getParameterCount());
		model = new FunctionEditorModel(null /* use default parser*/, fun);
		model.setModelChangeListener(new MyModelChangeListener());
		model.setSelectedParameterRow(new int[] { 1 });
		model.removeParameters();
		model.apply();
		assertEquals(0, fun.getParameterCount());
	}

	@Test
	public void testChangeParameter() {
		Function function = model.getFunction();
		assertEquals(0, function.getParameterCount());
		model.addParameter();
		model.apply();
		assertEquals(1, function.getParameterCount());
		model.setParameterName(model.getParameters().get(0), "abc");
		assertEquals("param_1", function.getParameter(0).getName());
		model.apply();
		assertEquals("abc", function.getParameter(0).getName());
	}

	@Test
	public void testSettingNameWithSameNameDoesNotSendDataChangeEvent() {
		model.setName("bob");
		assertDataChangedCallback(false);
	}

	@Test
	public void testChangingCallingConvention() {
		List<String> callingConventionNames = model.getCallingConventionNames();
		String callingConventionName = model.getCallingConventionName();
		assertTrue(callingConventionNames.contains(callingConventionName));
		assertEquals("unknown", callingConventionName);
		model.setCallingConventionName(callingConventionNames.get(1));
		assertEquals("default", model.getCallingConventionName());
		model.apply();
		assertEquals("default", model.getFunction().getCallingConventionName());
	}

	@Test
	public void testDisposingModelPreventsEvents() {
		model.dispose();
		model.setName("abc");
		assertDataChangedCallback(false);
	}

	@Test
	public void testSettingReturnStorageTooBig() throws Exception {
		model.setFormalReturnType(ByteDataType.dataType);
		VariableStorage returnStorage = model.getReturnStorage();
		model.setUseCustomizeStorage(true);
		Register register = returnStorage.getRegister();
		model.setReturnStorage(new VariableStorage(program, register.getBaseRegister()));
		assertTrue(!model.isValid());
	}

	@Test
	public void testSettingParamStorageTooBig() throws Exception {
		model.setCallingConventionName(null);
		model.setSignatureFieldText("int joe(char a)");
		model.parseSignatureFieldText();
		model.apply();
		ParamInfo paramInfo = model.getParameters().get(0);
		VariableStorage storage = paramInfo.getStorage();
		model.setUseCustomizeStorage(true);
		model.setParameterStorage(paramInfo,
			new VariableStorage(program, storage.getMinAddress(), storage.size() * 2));
		assertTrue(!model.isValid());
	}

	@Test
	public void testSettingInvalidFunctionName() {
		model.setName("hey there");
		assertTrue(!model.isValid());
	}

	@Test
	public void testSettingReturnTypeToVariableLengthDT() {
		DataType returnType = new StringDataType();
		model.setFormalReturnType(returnType);
		Assert.assertNotEquals(returnType.getName(), model.getFormalReturnType().getName());
	}

	@Test
	public void testSettingReturnTypeToTypeDef() {
		DataType type = new TypedefDataType("td", new IntegerDataType());
		type = type.clone(program.getDataTypeManager());
		model.setFormalReturnType(type);
		assertEquals(type, model.getFormalReturnType());
		assertTrue(model.isValid());
	}

	@Test
	public void testSettingParamTypeToVariableLengthDT() throws Exception {
		model.setCallingConventionName(null);
		model.setSignatureFieldText("int joe(char a)");
		model.parseSignatureFieldText();
		model.apply();
		model.setUseCustomizeStorage(true);
		ParamInfo paramInfo = model.getParameters().get(0);

		DataType type = new StringDataType();
		model.setParameterFormalDataType(paramInfo, type);
		Assert.assertNotEquals(type.getName(),
			model.getParameters().get(0).getDataType().getName());
	}

	@Test
	public void testSettingParamTypeToVoid() throws Exception {
		model.setCallingConventionName(null);
		model.setSignatureFieldText("int joe(char a)");
		model.parseSignatureFieldText();
		model.apply();
		model.setUseCustomizeStorage(true);
		ParamInfo paramInfo = model.getParameters().get(0);
		VoidDataType type = new VoidDataType();
		model.setParameterFormalDataType(paramInfo, type);
		Assert.assertNotEquals(type.getName(),
			model.getParameters().get(0).getDataType().getName());
	}

	@Test
	public void testSettingSameReturnTypeDoesNothing() {
		assertDataChangedCallback(false);
		model.setFormalReturnType(
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "void"));
		assertDataChangedCallback(false);
		model.setFormalReturnType(new IntegerDataType());
		assertDataChangedCallback(true);
	}

	@Test
	public void testDualAutoStorage1() throws Exception {

		assertEquals(0, model.getParameters().size());

		model.addParameter();
		ParamInfo param = model.getParameters().get(0);
		model.setParameterFormalDataType(param, ByteDataType.dataType);

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(1, parameters.size());
		param = parameters.get(0);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("Stack[0x4]:1", param.getStorage().toString());

		DataType struct = new StructureDataType("bigStruct", 100);
		DataType structPtr = PointerDataType.getPointer(struct, program.getDataTypeManager());
		DataType voidPtr =
			PointerDataType.getPointer(VoidDataType.dataType, program.getDataTypeManager());

		model.setCallingConventionName(CompilerSpec.CALLING_CONVENTION_thiscall);

		assertTrue(VoidDataType.dataType.isEquivalent(model.getFormalReturnType()));
		assertFalse(model.getReturnStorage().isForcedIndirect());
		assertEquals("<VOID>", model.getReturnStorage().toString());

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(voidPtr.isEquivalent(param.getDataType()));
		assertEquals("ECX:4 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("Stack[0x4]:1", param.getStorage().toString());

		model.setFormalReturnType(struct);

		assertTrue(struct.isEquivalent(model.getFormalReturnType()));
		assertTrue(model.getReturnStorage().isForcedIndirect());
		assertEquals("EAX:4 (ptr)", model.getReturnStorage().toString());

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(voidPtr.isEquivalent(param.getDataType()));
		assertEquals("ECX:4 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertEquals("Stack[0x4]:4 (auto)", param.getStorage().toString());
		param = parameters.get(2);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("Stack[0x8]:1", param.getStorage().toString());

		model.addParameter();
		param = model.getParameters().get(3);
		assertEquals("param_2", param.getName());
		assertTrue(DefaultDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("Stack[0xc]:1", param.getStorage().toString());

		model.setParameterFormalDataType(param, struct);

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(voidPtr.isEquivalent(param.getDataType()));
		assertEquals("ECX:4 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertEquals("Stack[0x4]:4 (auto)", param.getStorage().toString());
		param = parameters.get(2);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("Stack[0x8]:1", param.getStorage().toString());
		param = parameters.get(3);
		assertEquals("param_2", param.getName());
		assertTrue(struct.isEquivalent(param.getDataType()));
		assertFalse(param.getStorage().isForcedIndirect());
		assertEquals("Stack[0xc]:100", param.getStorage().toString());

		model.setCallingConventionName(CompilerSpec.CALLING_CONVENTION_fastcall);

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertEquals("ECX:4 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("DL:1", param.getStorage().toString());
		param = parameters.get(2);
		assertEquals("param_2", param.getName());
		assertTrue(struct.isEquivalent(param.getDataType()));
		assertFalse(param.getStorage().isForcedIndirect());
		assertEquals("Stack[0x4]:100", param.getStorage().toString());

	}

	@Test
	public void testDualAutoStorage2() throws Exception {

		// use different language: x64-windows
		setupX64windows();
		assertEquals(0, model.getParameters().size());

		model.addParameter();
		ParamInfo param = model.getParameters().get(0);
		model.setParameterFormalDataType(param, ByteDataType.dataType);

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(1, parameters.size());
		param = parameters.get(0);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("CL:1", param.getStorage().toString());

		DataType struct = new StructureDataType("bigStruct", 100);
		DataType structPtr = PointerDataType.getPointer(struct, program.getDataTypeManager());

		DataType voidPtr =
			PointerDataType.getPointer(VoidDataType.dataType, program.getDataTypeManager());

		model.setCallingConventionName(CompilerSpec.CALLING_CONVENTION_thiscall);

		assertTrue(VoidDataType.dataType.isEquivalent(model.getFormalReturnType()));
		assertFalse(model.getReturnStorage().isForcedIndirect());
		assertEquals("<VOID>", model.getReturnStorage().toString());

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(voidPtr.isEquivalent(param.getDataType()));
		assertEquals("RCX:8 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("DL:1", param.getStorage().toString());

		model.setFormalReturnType(struct);

		assertTrue(struct.isEquivalent(model.getFormalReturnType()));
		assertTrue(model.getReturnStorage().isForcedIndirect());
		assertEquals("RAX:8 (ptr)", model.getReturnStorage().toString());

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(voidPtr.isEquivalent(param.getDataType()));
		assertEquals("RCX:8 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertEquals("RDX:8 (auto)", param.getStorage().toString());
		param = parameters.get(2);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("R8B:1", param.getStorage().toString());

		model.addParameter();
		param = model.getParameters().get(3);
		assertEquals("param_2", param.getName());
		assertTrue(DefaultDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("R9B:1", param.getStorage().toString());

		model.setParameterFormalDataType(param, struct);

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, param.getName());
		assertTrue(voidPtr.isEquivalent(param.getDataType()));
		assertEquals("RCX:8 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertEquals("RDX:8 (auto)", param.getStorage().toString());
		param = parameters.get(2);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("R8B:1", param.getStorage().toString());
		param = parameters.get(3);
		assertEquals("param_2", param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertTrue(param.getStorage().isForcedIndirect());
		assertEquals("R9:8 (ptr)", param.getStorage().toString());

		model.setCallingConventionName(CompilerSpec.CALLING_CONVENTION_fastcall);

		parameters = model.getParameters();
		assertEquals(3, parameters.size());
		param = parameters.get(0);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertEquals("RCX:8 (auto)", param.getStorage().toString());
		param = parameters.get(1);
		assertEquals("param_1", param.getName());
		assertTrue(ByteDataType.dataType.isEquivalent(param.getDataType()));
		assertEquals("DL:1", param.getStorage().toString());
		param = parameters.get(2);
		assertEquals("param_2", param.getName());
		assertTrue(structPtr.isEquivalent(param.getDataType()));
		assertTrue(param.getStorage().isForcedIndirect());
		assertEquals("R8:8 (ptr)", param.getStorage().toString());

	}

	@Test
	public void testAutoAddingRemovingThisParameter() {

		model.addParameter();
		ParamInfo param1 = model.getParameters().get(0);
		model.setParameterFormalDataType(param1, ByteDataType.dataType);
		model.setParameterName(param1, "p1");
		assertEquals(1, model.getParameters().size());

		model.setCallingConventionName("__thiscall");

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		ParamInfo paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		VariableStorage storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertEquals("ECX:4 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

		model.setCallingConventionName("__stdcall");

		assertEquals(1, model.getParameters().size());
		assertEquals(0, model.getAutoParamCount());
		assertTrue(ByteDataType.dataType.isEquivalent(model.getParameters().get(0).getDataType()));

		parameters = model.getParameters();
		assertEquals(1, parameters.size());
		paramInfo = parameters.get(0);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

		model.setCallingConventionName("__thiscall");

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertEquals("ECX:4 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

		model.setUseCustomizeStorage(true);// transition 'this' to custom storage

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(0, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertEquals("ECX:4", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

		model.setUseCustomizeStorage(false);

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertEquals("ECX:4 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

		model.setUseCustomizeStorage(true);
		model.setCallingConventionName("__stdcall");// custom 'this' param will be retained

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(0, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertEquals("ECX:4", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

		model.setUseCustomizeStorage(false);// no change to params will occur

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(0, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertEquals("Stack[0x4]:4", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x8]:1", storage.toString());

		model.setCallingConventionName("__thiscall");// 'this' parameter will be consumed and converted to auto

		parameters = model.getParameters();
		assertEquals(2, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertEquals("ECX:4 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(ByteDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("Stack[0x4]:1", storage.toString());

	}

	@Test
	public void testForcedIndirectWithBigTypes() throws Exception {

		setupX64windows();

		model.setSignatureFieldText("bigStruct bob (bigStruct p1, int p2)");
		assertTrue(model.isInParsingMode());
		model.parseSignatureFieldText();
		assertTrue(!model.isInParsingMode());
		assertEquals("bigStruct bob (bigStruct p1, int p2)", getSignatureText());

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(bigStruct));
		VariableStorage storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());
		assertEquals("RAX:8 (ptr)", storage.toString());

		List<ParamInfo> parameters = model.getParameters();
		assertEquals(3, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		ParamInfo paramInfo = parameters.get(0);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(bigStruct));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());
		assertEquals("RDX:8 (ptr)", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p2", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8D:4", storage.toString());

		model.setCallingConventionName("__stdcall");

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(bigStruct));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());

		assertEquals(3, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(bigStruct));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());
		assertEquals("RDX:8 (ptr)", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p2", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8D:4", storage.toString());

		model.setCallingConventionName("__thiscall");

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(bigStruct));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(2, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RDX:8 (auto)", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(bigStruct));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());
		assertEquals("R8:8 (ptr)", storage.toString());
		paramInfo = parameters.get(3);
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R9D:4", storage.toString());

		model.setUseCustomizeStorage(true);

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(new PointerDataType(bigStruct)));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(0, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RDX:8", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8:8", storage.toString());
		paramInfo = parameters.get(3);
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R9D:4", storage.toString());

		model.setUseCustomizeStorage(false);// unable to restore forced-indirect param

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(bigStruct));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(2, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RDX:8 (auto)", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8:8", storage.toString());
		paramInfo = parameters.get(3);
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R9D:4", storage.toString());

		model.setUseCustomizeStorage(true);
		model.setCallingConventionName("__stdcall");// custom 'this' param is retained

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(new PointerDataType(bigStruct)));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(0, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RDX:8", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8:8", storage.toString());
		paramInfo = parameters.get(3);
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R9D:4", storage.toString());

		model.setUseCustomizeStorage(false);
		// no change to 'this', return ptr consumed and unfortunately
		// injected before custom 'this' param
		// TODO: should we be removing 'this' param if not __thiscall ?

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(bigStruct));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(1, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RDX:8", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8:8", storage.toString());
		paramInfo = parameters.get(3);
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R9D:4", storage.toString());

		model.setCallingConventionName("__thiscall");// 'this' param is consumed and converted to auto

		assertTrue(model.getReturnType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(model.getFormalReturnType().isEquivalent(bigStruct));
		storage = model.getReturnStorage();
		assertFalse(storage.isAutoStorage());
		assertTrue(storage.isForcedIndirect());

		parameters = model.getParameters();
		assertEquals(4, parameters.size());
		assertEquals(2, model.getAutoParamCount());
		paramInfo = parameters.get(0);
		assertEquals(Function.THIS_PARAM_NAME, paramInfo.getName());
		assertTrue(
			paramInfo.getDataType().isEquivalent(new PointerDataType(VoidDataType.dataType)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RCX:8 (auto)", storage.toString());
		paramInfo = parameters.get(1);
		assertEquals(Function.RETURN_PTR_PARAM_NAME, paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertTrue(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("RDX:8 (auto)", storage.toString());
		paramInfo = parameters.get(2);
		assertEquals("p1", paramInfo.getName());
		assertTrue(paramInfo.getDataType().isEquivalent(new PointerDataType(bigStruct)));
		assertTrue(paramInfo.getFormalDataType().isEquivalent(new PointerDataType(bigStruct)));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R8:8", storage.toString());
		paramInfo = parameters.get(3);
		assertTrue(paramInfo.getDataType().isEquivalent(IntegerDataType.dataType));
		storage = paramInfo.getStorage();
		assertFalse(storage.isAutoStorage());
		assertFalse(storage.isForcedIndirect());
		assertEquals("R9D:4", storage.toString());

	}

	@Test
	public void testAutoAddingRemovingThisParameterFixesSelection() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c)");
		model.parseSignatureFieldText();
		assertEquals(3, model.getParameters().size());

		model.setSelectedParameterRow(new int[] { 1, 3 });

		model.setCallingConventionName("__thiscall");
		assertEquals(4, model.getParameters().size());
		assertEquals(Function.THIS_PARAM_NAME, model.getParameters().get(0).getName());

		int[] selectedParameterRows = model.getSelectedParameterRows();
		assertEquals(2, selectedParameterRows.length);
		assertEquals(2, selectedParameterRows[0]);
		assertEquals(4, selectedParameterRows[1]);

		model.setCallingConventionName("__stdcall");
		assertEquals(3, model.getParameters().size());

		selectedParameterRows = model.getSelectedParameterRows();
		assertEquals(2, selectedParameterRows.length);
		assertEquals(1, selectedParameterRows[0]);
		assertEquals(3, selectedParameterRows[1]);

	}

	@Test
	public void testGetFunctionNameStartPosition() {
		model.setName("abc def");
		int start = model.getFunctionNameStartPosition();
		assertEquals("abc def",
			model.getFunctionSignatureTextFromModel().substring(start, start + 7));
	}

	@Test
	public void testParsingWorksEvenWithBadFunctionNameIfFunctionNameNotChanged() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c)");
		model.parseSignatureFieldText();
		String strangeName = "as(s)+[]";
		model.setName(strangeName);
		model.apply();  // make sure strangename is applied to the function it will parse against.
		model.setSignatureFieldText("int " + strangeName + "(int aa, short b, int d)");
		model.parseSignatureFieldText();
		assertEquals(strangeName, model.getName());
		assertEquals("d", model.getParameters().get(2).getName());
	}

	@Test
	public void testParsingWorksWithNamePatternDuplication() throws Exception {
		int txId = program.startTransaction("Add TypeDef jjjjjj");
		try {
			DataType dt = new TypedefDataType("jjjjjj", ByteDataType.dataType);
			program.getDataTypeManager().resolve(dt, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		model.setSignatureFieldText("jjjjjj j(int jj, int jjj, int jjjj)");
		model.parseSignatureFieldText();
		assertEquals("j", model.getName());
		assertEquals("jjjj", model.getParameters().get(2).getName());
	}

	@Test
	public void testResetSignatureFieldText() {
		String sigText = model.getFunctionSignatureTextFromModel();
		model.setSignatureFieldText("abc ");
		assertTrue(model.isInParsingMode());
		model.resetSignatureTextField();
		assertFalse(model.isInParsingMode());
		assertEquals(sigText, model.getFunctionSignatureTextFromModel());
	}

	@Test
	public void testCopyStorageByNameWhenParsing() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c)");
		model.parseSignatureFieldText();

		model.setUseCustomizeStorage(true);
		VariableStorage paramStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage paramStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage paramStorage3 = model.getParameters().get(2).getStorage();

		model.setSignatureFieldText("int joe(int b, int c, int a)");
		model.parseSignatureFieldText();
		VariableStorage newParamStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage newParamStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage newParamStorage3 = model.getParameters().get(2).getStorage();

		assertEquals(paramStorage1, newParamStorage3);
		assertEquals(paramStorage2, newParamStorage1);
		assertEquals(paramStorage3, newParamStorage2);
	}

	@Test
	public void testCopyStorageByOrdinal() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c)");
		model.parseSignatureFieldText();

		model.setUseCustomizeStorage(true);
		VariableStorage paramStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage paramStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage paramStorage3 = model.getParameters().get(2).getStorage();

		model.setSignatureFieldText("int joe(int d, int e, int f)");
		model.parseSignatureFieldText();
		VariableStorage newParamStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage newParamStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage newParamStorage3 = model.getParameters().get(2).getStorage();

		assertEquals(paramStorage1, newParamStorage1);
		assertEquals(paramStorage2, newParamStorage2);
		assertEquals(paramStorage3, newParamStorage3);
	}

	@Test
	public void testCopyStorageByNameAndOrdinal() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c, int d)");
		model.parseSignatureFieldText();

		model.setUseCustomizeStorage(true);
		VariableStorage paramStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage paramStorage2 = model.getParameters().get(1).getStorage();

		model.setSignatureFieldText("int joe(int e, int f, int b, int g)");
		model.parseSignatureFieldText();
		VariableStorage newParamStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage newParamStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage newParamStorage3 = model.getParameters().get(2).getStorage();
		VariableStorage newParamStorage4 = model.getParameters().get(3).getStorage();

		assertEquals(paramStorage1, newParamStorage1);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, newParamStorage2);
		assertEquals(paramStorage2, newParamStorage3);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, newParamStorage4);
	}

	@Test
	public void testCopyStorageByNameAndOrdinal2() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c, int d)");
		model.parseSignatureFieldText();

		model.setUseCustomizeStorage(true);
		VariableStorage paramStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage paramStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage paramStorage3 = model.getParameters().get(2).getStorage();

		model.setSignatureFieldText("int joe(int e, int c, int f, int g)");
		model.parseSignatureFieldText();
		VariableStorage newParamStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage newParamStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage newParamStorage3 = model.getParameters().get(2).getStorage();
		VariableStorage newParamStorage4 = model.getParameters().get(3).getStorage();

		assertEquals(paramStorage1, newParamStorage1);
		assertEquals(paramStorage3, newParamStorage2);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, newParamStorage3);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, newParamStorage4);
	}

	@Test
	public void testCopyStorageQuitsWhenSizesDontMatch() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c)");
		model.parseSignatureFieldText();

		model.setUseCustomizeStorage(true);
		VariableStorage paramStorage1 = model.getParameters().get(0).getStorage();

		model.setSignatureFieldText("int joe(int d, short e, int f)");
		model.parseSignatureFieldText();
		VariableStorage newParamStorage1 = model.getParameters().get(0).getStorage();
		VariableStorage newParamStorage2 = model.getParameters().get(1).getStorage();
		VariableStorage newParamStorage3 = model.getParameters().get(2).getStorage();

		assertEquals(paramStorage1, newParamStorage1);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, newParamStorage2);
		assertEquals(VariableStorage.UNASSIGNED_STORAGE, newParamStorage3);
	}

	@Test
	public void testApplyUseCustomStorage() throws Exception {
		model.setSignatureFieldText("int joe(int a, int b, int c)");
		model.parseSignatureFieldText();
		model.apply();

		model = new FunctionEditorModel(null /* use default parser*/, model.getFunction());
		model.setModelChangeListener(new MyModelChangeListener());

		assertFalse(model.getFunction().hasCustomVariableStorage());
		model.setUseCustomizeStorage(true);
		model.apply();
		assertTrue(model.getFunction().hasCustomVariableStorage());

	}

	@Test
	public void testSetInLine() {
		model.setIsInLine(false);
		assertDataChangedCallback(false);// already isInLine is false so make sure no event sent

		model.setIsInLine(true);
		assertTrue(model.isInLine());
		model.apply();
		assertTrue(model.getFunction().isInline());
		model.setIsInLine(false);
		assertFalse(model.isInLine());
		model.apply();
		assertFalse(model.getFunction().isInline());
	}

	@Test
	public void testCantDeleteReturnValueInTable() {
		model.setSelectedParameterRow(new int[] { 0 });// select return value row
		assertFalse(model.canRemoveParameters());
	}

	@Test
	public void testCantMoveThisParameterUpOrDown() {
		model.setCallingConventionName("__thiscall");
		model.setSelectedParameterRow(new int[] { 1 });// select this parameter row
		assertFalse(model.canMoveParameterUp());
		assertFalse(model.canMoveParameterDown());

	}

	// this test was to reproduce a bug where if you setAllowCustomStoarge=true, then edited the
	// return type, you got a stack trace when validating the model.
	@Test
	public void testPar() throws Exception {
		model.setUseCustomizeStorage(true);
		model.setSignatureFieldText("int bob(int a)");
		model.parseSignatureFieldText();
		assertEquals("int", model.getFormalReturnType().getName());

	}

	private void assertDataChangedCallback(boolean expectedValue) {
		waitForSwing();
		if (expectedValue && !dataChangeCalled) {
			Assert.fail("Expected dataChanged callback, but did not happen!");
		}
		if (!expectedValue && dataChangeCalled) {
			Assert.fail("Did not expect dataChanged callback, but it happened!");
		}
	}

	private String getSignatureText() {
		return model.getFunctionSignatureTextFromModel();
	}

}
