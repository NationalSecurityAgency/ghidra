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
package ghidra.app.merge.listing;

import static org.junit.Assert.*;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalFunctionMerger1Test extends AbstractExternalMergerTest {

	// *** NotepadMergeListingTest ***

	// External Refs
	// 01001000: op0 to ADVAPI32.DLL IsTextUnicode 77dc4f85
	// 01001004: op0 to ADVAPI32.DLL RegCreateKeyW 77db90b0
	// 01001008: op0 to ADVAPI32.DLL RegQueryValueExW 77db8078
	// 0100100c: op0 to ADVAPI32.DLL RegSetValueExW 77db9348
	// 01001010: op0 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
	// 01001014: op0 to ADVAPI32.DLL RegQueryValueExA 77db858e
	// 01001018: op0 to ADVAPI32.DLL RegCloseKey 77db7d4d
	// 010010c0: op0 to KERNEL32.DLL LocalFree 77e9499c
	// 010010c4: op0 to KERNEL32.DLL GetProcAddress 77e9564b
	// 010013cc: no ref (has string)
	// 010013d8: no ref (has string)
	// 010013f0: no ref (has string)

	// Mem Refs
	// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
	// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary
	// 01001aec: op1 to 01001398 AddrTable010080c0Element36 DATA primary
	// 01001b5f: op0 to 010061e3 FUN_010061e3 UNCONDITIONAL_CALL primary

	// Stack Refs
	// 01001a55: op1 no ref to stack offset 0x10
	// 01001af5: op0 to stack offset -0x24a
	// 01001b03: op1 to stack offset -0x24c
	// 01002125: op0 to stack offset -0x10
	// 010024ea: op1 no ref to stack offset 0x10
	// 01002510: op0 no ref to stack offset 0x8
	// 01002a05: op0 no ref to stack offset -0x18

	protected static final Reference ExternalReference = null;

	/**
	 *
	 * @param arg0
	 */
	public ExternalFunctionMerger1Test() {
		super();
	}

	@Test
	public void testAddExternalFunctionInBothDemangledMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					externalManager.addExtFunction(externalLibrary, "mangled",
						addr(program, "77db1020"), SourceType.IMPORTED);

				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.IMPORTED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation = externalManager.addExtFunction(
						externalLibrary, "mangled", addr(program, "77db1020"), SourceType.IMPORTED);
					externalLocation.setName(externalLibrary, "apples", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
//		Symbol mangled = getUniqueSymbol(resultProgram, "mangled", externalLibrary);
//		assertNotNull(mangled);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertNotNull(apples);
		ExternalLocation externalLocation =
			resultProgram.getExternalManager().getExternalLocation(apples);
		assertEquals("mangled", externalLocation.getOriginalImportedName());
	}

	@Test
	public void testAddExternalFunctionInBothDemangleLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation = externalManager.addExtFunction(
						externalLibrary, "mangled", addr(program, "77db1020"), SourceType.IMPORTED);
					externalLocation.setName(externalLibrary, "apples", SourceType.USER_DEFINED);

				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.IMPORTED);

					ExternalManager externalManager = program.getExternalManager();
					externalManager.addExtFunction(externalLibrary, "mangled",
						addr(program, "77db1020"), SourceType.IMPORTED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);

		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertNotNull(apples);
		ExternalLocation externalLocation =
			resultProgram.getExternalManager().getExternalLocation(apples);
		assertEquals("mangled", externalLocation.getOriginalImportedName());
	}

	@Test
	public void testAddDifferentNamedExternalFunctionInBothDemangleBoth() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "mangled1",
							addr(program, "77db1020"), SourceType.IMPORTED);
					externalLocation.setName(externalLibrary, "apples", SourceType.USER_DEFINED);

				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.IMPORTED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "mangled2",
							addr(program, "77db1020"), SourceType.IMPORTED);
					externalLocation.setName(externalLibrary, "oranges", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict",
			ExternalFunctionMerger.KEEP_BOTH_BUTTON_NAME);

		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);

		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertNotNull(apples);

		Symbol oranges = getUniqueSymbol(resultProgram, "oranges", externalLibrary);
		assertNotNull(oranges);

		ExternalLocation externalLoc1 =
			resultProgram.getExternalManager().getExternalLocation(apples);
		assertEquals("mangled1", externalLoc1.getOriginalImportedName());

		ExternalLocation externalLoc2 =
			resultProgram.getExternalManager().getExternalLocation(oranges);
		assertEquals("mangled2", externalLoc2.getOriginalImportedName());
	}

	@Test
	public void testAddDiffExternalFunctionChooseLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);
					Namespace myNamespace = symbolTable.createNameSpace(externalLibrary,
						"MyNamespace", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation = externalManager.addExtFunction(myNamespace,
						"apples", addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);
					Namespace myNamespace = symbolTable.createNameSpace(externalLibrary,
						"MyNamespace", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation = externalManager.addExtFunction(myNamespace,
						"apples", addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("Length", new CharDataType(), program);
					parameter1.setComment("Latest Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Namespace myNamespace =
			(Namespace) getUniqueSymbol(resultProgram, "MyNamespace", externalLibrary).getObject();
		assertNotNull(myNamespace);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", myNamespace);
		Symbol applesConflict = getUniqueSymbol(resultProgram, "apples_conflict1", myNamespace);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		assertNull(applesConflict);
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals("P1", parameter.getName());
		checkDataType(new DWordDataType(), parameter.getDataType());

		assertEquals("Test Parameter Comment", parameter.getComment());
	}

	@Test
	public void testExternalFunctionChangeVsRemoveConflict() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction = createExternalFunction(program, applesPath,
						addr(program, "77db1234"), new FloatDataType(), SourceType.IMPORTED);
					applesFunction.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new DWordDataType(), 8, program);
					parameter2.setComment("Other Comment");
					applesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setComment("Once upon a time...");
					applesFunction.setNoReturn(true);

					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					parameter1.setComment("Long ago in a land far, far away");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				assertEquals("Once upon a time...", applesFunction.getComment());

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				assertEquals(null, orangesFunction.getComment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.getSymbol().delete();// Remove the function, but not the external location.

					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.getSymbol().delete();// Remove the function, but not the external location.
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertEquals(false, applesLocation.isFunction());
				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertEquals(false, orangesLocation.isFunction());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals("Once upon a time...", applesFunction.getComment());

		Parameter parameter1 = applesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameter1.getDataType());
		assertEquals("Test Parameter Comment", parameter1.getComment());
		assertEquals("P1", parameter1.getName());

		Parameter parameter2 = applesFunction.getParameter(1);
		checkDataType(new DWordDataType(), parameter2.getDataType());
		assertEquals("Other Comment", parameter2.getComment());
		assertEquals("P2", parameter2.getName());
		assertEquals(8, parameter2.getStackOffset());

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertEquals(false, orangesLocation.isFunction());
	}

	@Test
	public void testExternalFunctionChangeParameterDetailsConflictPickLatest() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction = createExternalFunction(program, applesPath,
						addr(program, "77db1234"), new FloatDataType(), SourceType.IMPORTED);
					applesFunction.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new DWordDataType(), 8, program);
					parameter2.setComment("Other Comment");
					applesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					Parameter applesParameter1 = applesFunction.getParameter(0);
					applesParameter1.setComment("Once upon a time...");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				Parameter applesParameter1 = applesFunction.getParameter(0);
				assertEquals("Once upon a time...", applesParameter1.getComment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					Parameter applesParameter1 = applesFunction.getParameter(0);
					applesParameter1.setComment("This is a sample parameter comment.");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				Parameter applesParameter1 = applesFunction.getParameter(0);
				assertEquals("This is a sample parameter comment.", applesParameter1.getComment());
				assertEquals("P1", applesParameter1.getName());
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals(null, applesFunction.getComment());

		Parameter parameter1 = applesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameter1.getDataType());
		assertEquals("Once upon a time...", parameter1.getComment());
		assertEquals("P1", parameter1.getName());

		Parameter parameter2 = applesFunction.getParameter(1);
		checkDataType(new DWordDataType(), parameter2.getDataType());
		assertEquals("Other Comment", parameter2.getComment());
		assertEquals("P2", parameter2.getName());
		assertEquals(8, parameter2.getStackOffset());
	}

	@Test
	public void testExternalFunctionChangeParameterDetailsConflictPickMy() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function applesFunction = createExternalFunction(program, applesPath,
						addr(program, "77db1234"), new FloatDataType(), SourceType.IMPORTED);
					applesFunction.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					applesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new DWordDataType(), 8, program);
					parameter2.setComment("Other Comment");
					applesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					Parameter applesParameter1 = applesFunction.getParameter(0);
					applesParameter1.setComment("Once upon a time...");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				Parameter applesParameter1 = applesFunction.getParameter(0);
				assertEquals("Once upon a time...", applesParameter1.getComment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					Parameter applesParameter1 = applesFunction.getParameter(0);
					applesParameter1.setComment("This is a sample parameter comment.");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertTrue(applesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				Parameter applesParameter1 = applesFunction.getParameter(0);
				assertEquals("This is a sample parameter comment.", applesParameter1.getComment());
				assertEquals("P1", applesParameter1.getName());
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertTrue(applesLocation.isFunction());
		Function applesFunction = applesLocation.getFunction();
		assertEquals(2, applesFunction.getParameterCount());
		assertEquals(null, applesFunction.getComment());

		Parameter parameter1 = applesFunction.getParameter(0);
		checkDataType(new DWordDataType(), parameter1.getDataType());
		assertEquals("This is a sample parameter comment.", parameter1.getComment());
		assertEquals("P1", parameter1.getName());

		Parameter parameter2 = applesFunction.getParameter(1);
		checkDataType(new DWordDataType(), parameter2.getDataType());
		assertEquals("Other Comment", parameter2.getComment());
		assertEquals("P2", parameter2.getName());
		assertEquals(8, parameter2.getStackOffset());
	}

	@Test
	public void testExternalFunctionAddDiffParameterConflictPickLatest() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					parameter1.setComment("Long ago in a land far, far away");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				assertEquals(null, orangesFunction.getComment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 = new ParameterImpl("value",
						new PointerDataType(new ByteDataType()), 4, program);
					parameter1.setComment("Four score and seven years ago...");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				Parameter orangesParameter1 = orangesFunction.getParameter(0);
				assertEquals("Four score and seven years ago...", orangesParameter1.getComment());
				assertEquals("value", orangesParameter1.getName());
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST, KEEP_LATEST, KEEP_LATEST });
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new ByteDataType(), parameter1.getDataType());
		assertEquals("Long ago in a land far, far away", parameter1.getComment());
		assertEquals("stuff", parameter1.getName());

	}

	@Test
	public void testExternalFunctionAddDiffParameterConflictPickMy() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					parameter1.setComment("Long ago in a land far, far away");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				assertEquals(null, orangesFunction.getComment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 = new ParameterImpl("value",
						new PointerDataType(new ByteDataType()), 4, program);
					parameter1.setComment("Four score and seven years ago...");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				Parameter orangesParameter1 = orangesFunction.getParameter(0);
				assertEquals("Four score and seven years ago...", orangesParameter1.getComment());
				assertEquals("value", orangesParameter1.getName());
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_MY, KEEP_LATEST, KEEP_MY });
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new ByteDataType(), parameter1.getDataType());
		assertEquals("Four score and seven years ago...", parameter1.getComment());
		assertEquals("value", parameter1.getName());

	}

	@Test
	public void testExternalFunctionAddDiffParameterDetailsConflictPickMy() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					parameter1.setComment("Long ago in a land far, far away");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				assertEquals(null, orangesFunction.getComment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("value", new ByteDataType(), 4, program);
					parameter1.setComment("Four score and seven years ago...");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
				Parameter orangesParameter1 = orangesFunction.getParameter(0);
				assertEquals("Four score and seven years ago...", orangesParameter1.getComment());
				assertEquals("value", orangesParameter1.getName());
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_MY, KEEP_MY });// Name, comment
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new ByteDataType(), parameter1.getDataType());
		assertEquals("Four score and seven years ago...", parameter1.getComment());
		assertEquals("value", parameter1.getName());

	}

	@Test
	public void testExternalFunctionAddDiffRegParameterSigConflictPickLatest() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("r0l", parameter1.getRegister().getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals("r1l", parameter2.getRegister().getName());
	}

	@Test
	public void testExternalFunctionAddDiffRegParameterSigConflictPickMy() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("r1l", parameter1.getRegister().getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals("r0l", parameter2.getRegister().getName());
	}

	@Test
	public void testExternalFunctionChangeNonVsCustomStorageConflictPickLatest() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("r0l", parameter1.getRegister().getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals("r1l", parameter2.getRegister().getName());
	}

	@Test
	public void testExternalFunctionChangeNonVsCustomStorageConflictPickMy() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
	}

	@Test
	public void testExternalFunctionAddSameStackParamsNoConflict() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
	}

	@Test
	public void testExternalFunctionAddNonVsCustomStoragePickLatest() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(false);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
	}

	@Test
	public void testExternalFunctionAddNonVsCustomStoragePickMy() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(false);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals(resultProgram.getRegister("r0l"), parameter1.getRegister());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals(resultProgram.getRegister("r1l"), parameter2.getRegister());

	}

	@Test
	public void testExternalFunctionAddNonVsCustomStorage() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				AddressSpace stackSpace = program.getAddressFactory().getStackSpace();
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(false);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, stackSpace.getAddress(4), 2), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, stackSpace.getAddress(8), 2), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				AddressSpace stackSpace = program.getAddressFactory().getStackSpace();
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, stackSpace.getAddress(4), 2), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, stackSpace.getAddress(8), 2), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertNull(parameter1.getRegister());
		assertEquals(4, parameter1.getStackOffset());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertNull(parameter2.getRegister());
		assertEquals(8, parameter2.getStackOffset());
	}

	@Test
	public void testExternalFunctionAddSameCustomParamsNoConflict() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalFunction(program, orangesPath, addr(program, "00cc5566"),
						new DWordDataType(), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("r1l")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("r0l", parameter1.getRegister().getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals("r1l", parameter2.getRegister().getName());
	}

	@Test
	public void testExternalFunctionDynamicVsCustomStorageChangePickLatest() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function fun = createExternalFunction(program, orangesPath,
						addr(program, "00cc5566"), new DWordDataType(), SourceType.USER_DEFINED);
					fun.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("DX")), program);
					fun.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(false);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter = orangesFunction.getParameter(0);
					parameter.setDataType(new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), true,
						SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertFalse(orangesFunction.hasCustomVariableStorage());
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("Stack[0x4]:2", parameter1.getVariableStorage().toString());
	}

	@Test
	public void testExternalFunctionDynamicVsCustomStorageChangePickMy() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function fun = createExternalFunction(program, orangesPath,
						addr(program, "00cc5566"), new DWordDataType(), SourceType.USER_DEFINED);
					fun.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("DX")), program);
					fun.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setCustomVariableStorage(false);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter = orangesFunction.getParameter(0);
					parameter.setDataType(new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), true,
						SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(1, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Parameters Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
		assertTrue(orangesFunction.hasCustomVariableStorage());
		assertEquals(1, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("BX:2", parameter1.getVariableStorage().toString());
	}

}
