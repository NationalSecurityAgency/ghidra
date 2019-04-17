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
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalFunctionMerger2Test extends AbstractExternalMergerTest {

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
	public ExternalFunctionMerger2Test() {
		super();
	}

	@Test
	public void testFunctionParamNameVsDataTypeNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setDataType(new FloatDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("MyParameter", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());

		assertEquals("Test Parameter Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionParamChangeNameDataTypeComment1() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("LatestParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new FloatDataType(), SourceType.ANALYSIS);
					parameter1.setComment("Latest Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new DoubleDataType(), SourceType.ANALYSIS);
					parameter1.setComment("My Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY, KEEP_LATEST });
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("LatestParameter", parameter1.getName());
		checkDataType(new DoubleDataType(), parameter1.getDataType());

		assertEquals("Latest Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionParamChange_NameKeepLatest_CommentKeepMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("LatestParameter", SourceType.USER_DEFINED);
					parameter1.setComment("Latest Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					parameter1.setComment("My Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY });
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("LatestParameter", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("My Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionParamChange_NameKeepMy_CommentKeepLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("LatestParameter", SourceType.USER_DEFINED);
					parameter1.setComment("Latest Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					parameter1.setComment("My Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_MY, KEEP_LATEST });
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("MyParameter", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("Latest Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionParamChange_NameKeepLatest_DataTypeKeepMy_CommentKeepMy()
			throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("LatestParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new FloatDataType(), SourceType.ANALYSIS);
					parameter1.setComment("Latest Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new ArrayDataType(new CharDataType(), 4, 1),
						SourceType.ANALYSIS);
					parameter1.setComment("My Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY, KEEP_MY });
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("LatestParameter", parameter1.getName());
		checkDataType(new ArrayDataType(new CharDataType(), 4, 1), parameter1.getDataType());

		assertEquals("My Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionParamChange_NameKeepMy_DataTypeKeepLatest_CommentKeepLatest()
			throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("LatestParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new FloatDataType(), SourceType.ANALYSIS);
					parameter1.setComment("Latest Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new ArrayDataType(new CharDataType(), 4, 1),
						SourceType.ANALYSIS);
					parameter1.setComment("My Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_MY, KEEP_LATEST, KEEP_LATEST });
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("MyParameter", parameter1.getName());
		checkDataType(new FloatDataType(), parameter1.getDataType());

		assertEquals("Latest Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionParamChangeNameDataTypeComment2() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("LatestParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new FloatDataType(), SourceType.ANALYSIS);
					parameter1.setComment("Latest Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					Parameter parameter1 = function.getParameter(0);
					parameter1.setName("MyParameter", SourceType.USER_DEFINED);
					parameter1.setDataType(new DoubleDataType(), SourceType.ANALYSIS);
					parameter1.setComment("My Comment");
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve Function Parameter Conflict",
			new int[] { INFO_ROW, KEEP_MY, KEEP_MY, KEEP_MY });
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("MyParameter", parameter1.getName());
		checkDataType(new DoubleDataType(), parameter1.getDataType());

		assertEquals("My Comment", parameter1.getComment());
	}

	@Test
	public void testExtLabelRefAddDiffConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", null, SourceType.USER_DEFINED, 0, RefType.DATA);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);
		checkExternalAddress(extLocOranges, "77db1020");

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals(addr(resultProgram, "77db1020"),
			((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testTransformLabelIntoFunctionNoConflict() throws Exception {
		final String[] grapesPath = new String[] { "user32.dll", "Fruit", "grapes" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, grapesPath, null, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					Function function = externalLocation.createFunction();
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					Function function = externalLocation.createFunction();
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Function function = getExternalFunction(resultProgram, grapesPath);
		checkDataType(DataType.DEFAULT, function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("P1", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("Test Parameter Comment", parameter1.getComment());
	}

	@Test
	public void testTransformFunctionIntoLabelIntoFunctionNoConflict() throws Exception {
		final String[] grapesPath = new String[] { "user32.dll", "Fruit", "grapes" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation =
						createExternalLabel(program, grapesPath, null, SourceType.USER_DEFINED);
					Function function = externalLocation.createFunction();
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					externalLocation.getSymbol().delete();
					externalLocation =
						createExternalLabel(program, grapesPath, null, SourceType.USER_DEFINED);
					externalLocation.setDataType(ByteDataType.dataType);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					externalLocation.getSymbol().delete();
					externalLocation =
						createExternalLabel(program, grapesPath, null, SourceType.USER_DEFINED);
					externalLocation.setDataType(ByteDataType.dataType);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation externalLocation = getExternalLocation(resultProgram, grapesPath);
		assertTrue("Did not find external label location",
			externalLocation != null && !externalLocation.isFunction());
		checkDataType(ByteDataType.dataType, externalLocation.getDataType());
	}

	@Test
	public void testTransformLabelIntoFunctionVsLabelNameChangeNoConflict() throws Exception {
		final String[] grapesPath = new String[] { "user32.dll", "Fruit", "grapes" };
		final String[] countPath = new String[] { "user32.dll", "Fruit", "count" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, grapesPath, null, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					Function function = externalLocation.createFunction();
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					externalLocation.setLocation("count", externalLocation.getAddress(),
						SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation grapesLocation = getExternalLocation(resultProgram, grapesPath);
		assertNull(grapesLocation);
		Function function = getExternalFunction(resultProgram, countPath);
		checkDataType(DataType.DEFAULT, function.getReturnType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("P1", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("Test Parameter Comment", parameter1.getComment());
	}

	@Test
	public void testTransformLabelIntoFunctionNoAddressVsLabelNameConflict() throws Exception {
		final String[] grapesPath = new String[] { "user32.dll", "Fruit", "grapes" };
		final String[] berriesPath = new String[] { "user32.dll", "Fruit", "berries" };
		final String[] countPath = new String[] { "user32.dll", "Fruit", "count" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, grapesPath, null, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					Function function = externalLocation.createFunction();
					function.setName("berries", SourceType.USER_DEFINED);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					externalLocation.setLocation("count", externalLocation.getAddress(),
						SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Remove Conflict", MY_BUTTON);// Keep count vs remove.
		waitForMergeCompletion();

		ExternalLocation grapesLocation = getExternalLocation(resultProgram, grapesPath);
		assertNull(grapesLocation);
		ExternalLocation berriesLocation = getExternalLocation(resultProgram, berriesPath);
		assertNotNull(berriesLocation);
		ExternalLocation countLocation = getExternalLocation(resultProgram, countPath);
		assertNotNull(countLocation);
		Function berriesFunction = berriesLocation.getFunction();
		assertNotNull(berriesLocation.getFunction());
		assertNull(countLocation.getFunction());
		checkDataType(DataType.DEFAULT, berriesFunction.getReturnType());
		assertEquals(1, berriesFunction.getParameterCount());
		Parameter parameter1 = berriesFunction.getParameter(0);
		assertEquals("P1", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("Test Parameter Comment", parameter1.getComment());
	}

	@Test
	public void testTransformLabelIntoFunctionWithAddressVsLabelNameConflictPickLatest()
			throws Exception {
		final String[] grapesPath = new String[] { "user32.dll", "Fruit", "grapes" };
		final String[] berriesPath = new String[] { "user32.dll", "Fruit", "berries" };
		final String[] countPath = new String[] { "user32.dll", "Fruit", "count" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, grapesPath, addr(program, "77db4321"),
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					Function function = externalLocation.createFunction();
					function.setName("berries", SourceType.USER_DEFINED);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					externalLocation.setLocation("count", externalLocation.getAddress(),
						SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });// Name Conflict
		waitForMergeCompletion();

		ExternalLocation grapesLocation = getExternalLocation(resultProgram, grapesPath);
		assertNull(grapesLocation);
		ExternalLocation berriesLocation = getExternalLocation(resultProgram, berriesPath);
		assertNotNull(berriesLocation);
		ExternalLocation countLocation = getExternalLocation(resultProgram, countPath);
		assertNull(countLocation);
		Function berriesFunction = berriesLocation.getFunction();
		assertNotNull(berriesLocation.getFunction());
		checkDataType(DataType.DEFAULT, berriesFunction.getReturnType());
		assertEquals(1, berriesFunction.getParameterCount());
		Parameter parameter1 = berriesFunction.getParameter(0);
		assertEquals("P1", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("Test Parameter Comment", parameter1.getComment());
	}

	@Test
	public void testTransformLabelIntoFunctionWithAddressVsLabelNameConflictPickMy()
			throws Exception {
		final String[] grapesPath = new String[] { "user32.dll", "Fruit", "grapes" };
		final String[] berriesPath = new String[] { "user32.dll", "Fruit", "berries" };
		final String[] countPath = new String[] { "user32.dll", "Fruit", "count" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, grapesPath, addr(program, "77db4321"),
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					Function function = externalLocation.createFunction();
					function.setName("berries", SourceType.USER_DEFINED);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, grapesPath);
					externalLocation.setLocation("count", externalLocation.getAddress(),
						SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });// Name Conflict
		waitForMergeCompletion();

		ExternalLocation grapesLocation = getExternalLocation(resultProgram, grapesPath);
		assertNull(grapesLocation);
		ExternalLocation berriesLocation = getExternalLocation(resultProgram, berriesPath);
		assertNull(berriesLocation);
		ExternalLocation countLocation = getExternalLocation(resultProgram, countPath);
		assertNotNull(countLocation);
		Function countFunction = countLocation.getFunction();
		assertNotNull(countLocation.getFunction());
		checkDataType(DataType.DEFAULT, countFunction.getReturnType());
		assertEquals(1, countFunction.getParameterCount());
		Parameter parameter1 = countFunction.getParameter(0);
		assertEquals("P1", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals("Test Parameter Comment", parameter1.getComment());
	}

	@Test
	public void testFunctionStackOverlapConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Library externalLibrary =
						symbolTable.createExternalLibrary("user32.dll", SourceType.USER_DEFINED);

					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.addExtFunction(externalLibrary, "apples",
							addr(program, "77db1020"), SourceType.USER_DEFINED);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();
					function.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 = new ParameterImpl("P2", new DWordDataType(), 8, program);
					parameter2.setComment("Other Comment");
					function.addParameter(parameter2, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 =
					getExternalFunction(program, new String[] { "user32.dll", "apples" });
				Parameter p1 = function1.getParameter(0);
				Parameter p2 = function1.getParameter(1);
				assertEquals("Test Parameter Comment", p1.getComment());
				assertEquals("Other Comment", p2.getComment());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", externalLibrary);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();
					function.setCustomVariableStorage(true);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 6, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
					Parameter parameter2 =
						new ParameterImpl("P2", new DWordDataType(), 10, program);
					parameter2.setComment("Other Comment");
					function.addParameter(parameter2, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		resultProgram = mtf.getResultProgram();// destination program
		Function function1 =
			getExternalFunction(resultProgram, new String[] { "user32.dll", "apples" });
		Parameter p1 = function1.getParameter(0);
		Parameter p2 = function1.getParameter(1);
		assertEquals("Test Parameter Comment", p1.getComment());
		assertEquals("Other Comment", p2.getComment());

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		Namespace externalLibrary =
			(Namespace) resultProgram.getSymbolTable().getLibrarySymbol("user32.dll").getObject();
		assertNotNull(externalLibrary);
		Symbol apples = getUniqueSymbol(resultProgram, "apples", externalLibrary);
		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
		Function function = (Function) apples.getObject();
		checkDataType(new ByteDataType(), function.getReturnType());
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("P1", parameter1.getName());
		checkDataType(new DWordDataType(), parameter1.getDataType());

		assertEquals(6, parameter1.getStackOffset());
		assertEquals("Test Parameter Comment", parameter1.getComment());
		Parameter parameter2 = function.getParameter(1);
		assertEquals("P2", parameter2.getName());
		checkDataType(new DWordDataType(), parameter2.getDataType());

		assertEquals(10, parameter2.getStackOffset());
		assertEquals("Other Comment", parameter2.getComment());
	}

	@Test
	public void testFunctionChangeReturnTypeConflictPickLatest() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function function = createExternalFunction(program, applesPath,
						addr(program, "77db1020"), new FloatDataType(), SourceType.ANALYSIS);
					assertNotNull(function);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function = getExternalFunction(program, applesPath);
					function.setReturnType(new WordDataType(), SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 = getExternalFunction(program, applesPath);
				assertEquals(0, function1.getParameterCount());
				checkDataType(new WordDataType(), function1.getReturnType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function = getExternalFunction(program, applesPath);
					function.setReturnType(new PointerDataType(new ByteDataType()),
						SourceType.IMPORTED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 = getExternalFunction(program, applesPath);
				assertEquals(0, function1.getParameterCount());
				checkDataType(new PointerDataType(new ByteDataType()), function1.getReturnType());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Return Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		Function function = getExternalFunction(resultProgram, applesPath);
		assertEquals(0, function.getParameterCount());
		checkDataType(new WordDataType(), function.getReturnType());
	}

	@Test
	public void testFunctionChangeReturnTypeToTypedefConflictPickMy() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function function = createExternalFunction(program, applesPath,
						addr(program, "77db1020"), new FloatDataType(), SourceType.ANALYSIS);
					assertNotNull(function);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function = getExternalFunction(program, applesPath);
					function.setReturnType(new LongDataType(), SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 = getExternalFunction(program, applesPath);
				assertEquals(0, function1.getParameterCount());
				checkDataType(new LongDataType(), function1.getReturnType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				CategoryPath path = new CategoryPath("/");
				DataType typedefDT = new TypedefDataType(path, "long", new LongDataType(),
					program.getDataTypeManager());
				boolean commit = false;
				try {
					Function function = getExternalFunction(program, applesPath);
					function.setReturnType(typedefDT, SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 = getExternalFunction(program, applesPath);
				assertEquals(0, function1.getParameterCount());
				checkDataType(typedefDT, function1.getReturnType());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Return Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Function function = getExternalFunction(resultProgram, applesPath);
		assertEquals(0, function.getParameterCount());
		CategoryPath path = new CategoryPath("/");
		DataType typedefDT = new TypedefDataType(path, "long.conflict", new LongDataType(),
			resultProgram.getDataTypeManager());
		checkDataType(typedefDT, function.getReturnType());
	}

	@Test
	public void testFunctionChangeReturnTypeConflictPickMy() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function function = createExternalFunction(program, applesPath,
						addr(program, "77db1020"), new FloatDataType(), SourceType.ANALYSIS);
					assertNotNull(function);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function function = getExternalFunction(program, applesPath);
					function.setReturnType(new WordDataType(), SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 = getExternalFunction(program, applesPath);
				assertEquals(0, function1.getParameterCount());
				checkDataType(new WordDataType(), function1.getReturnType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function function = getExternalFunction(program, applesPath);
					function.setReturnType(new PointerDataType(new ByteDataType()),
						SourceType.IMPORTED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				Function function1 = getExternalFunction(program, applesPath);
				assertEquals(0, function1.getParameterCount());
				checkDataType(new PointerDataType(new ByteDataType()), function1.getReturnType());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Return Conflict", MY_BUTTON);
		waitForMergeCompletion();

		Function function = getExternalFunction(resultProgram, applesPath);
		assertEquals(0, function.getParameterCount());
		checkDataType(new PointerDataType(new ByteDataType()), function.getReturnType());
	}

	@Test
	public void testExternalFunctionRemoveVsChangeConflict() throws Exception {
		final String[] applesPath = new String[] { "user32.dll", "Class1", "apples" };
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
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

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.getSymbol().delete();// Remove the function, but not the external location.

					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.getSymbol().delete();// Remove the function, but not the external location.

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				assertNotNull(applesLocation);
				assertEquals(false, applesLocation.isFunction());
				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertEquals(false, orangesLocation.isFunction());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function applesFunction = getExternalFunction(program, applesPath);
					applesFunction.setComment("Once upon a time...");
					applesFunction.setNoReturn(true);

					Function orangesFunction = getExternalFunction(program, orangesPath);
					Parameter parameter1 =
						new ParameterImpl("stuff", new ByteDataType(), 4, program);
					parameter1.setComment("Long ago in a land far, far away");
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation applesLocation = getExternalLocation(program, applesPath);
				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(applesLocation);
				assertNotNull(orangesLocation);
				assertTrue(applesLocation.isFunction());
				assertTrue(orangesLocation.isFunction());
				Function applesFunction = applesLocation.getFunction();
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, applesFunction.getParameterCount());
				assertEquals(1, orangesFunction.getParameterCount());
				assertEquals("Once upon a time...", applesFunction.getComment());
				assertEquals(null, orangesFunction.getComment());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(MY_BUTTON);

		waitForMergeCompletion();

		ExternalLocation applesLocation = getExternalLocation(resultProgram, applesPath);
		assertNotNull(applesLocation);
		assertEquals(false, applesLocation.isFunction());

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
	public void testExternalFunctionSignatureSourceChangeConflict() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function function =
						createExternalFunction(program, orangesPath, addr(program, "00cc5566"));
					assertEquals(SourceType.DEFAULT, function.getSignatureSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setSignatureSource(SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
//				Function orangesFunction = orangesLocation.getFunction();
//				assertEquals(2, orangesFunction.getParameterCount());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setSignatureSource(SourceType.ANALYSIS);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
//				Function orangesFunction = orangesLocation.getFunction();
//				assertEquals(2, orangesFunction.getParameterCount());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation orangesLocation = getExternalLocation(resultProgram, orangesPath);
		assertNotNull(orangesLocation);
		assertTrue(orangesLocation.isFunction());
		Function orangesFunction = orangesLocation.getFunction();
//		assertEquals(2, orangesFunction.getParameterCount());
		assertEquals(null, orangesFunction.getComment());
		assertEquals(SourceType.USER_DEFINED, orangesFunction.getSignatureSource());
	}

	@Test
	public void testExternalFunctionSigSourceAndParamsNoConflict() throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function function =
						createExternalFunction(program, orangesPath, addr(program, "00cc5566"));
					assertEquals(SourceType.DEFAULT, function.getSignatureSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setSignatureSource(SourceType.USER_DEFINED);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("AX")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setSignatureSource(SourceType.ANALYSIS);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("AX")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
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
		assertEquals(SourceType.USER_DEFINED, orangesFunction.getSignatureSource());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("AX", parameter1.getRegister().getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals("BX", parameter2.getRegister().getName());
	}

	@Test
	public void testExternalFunctionParamChangeSignatureSourceConflictChooseHighestPriority()
			throws Exception {
		final String[] orangesPath = new String[] { "user32.dll", "NamespaceA", "oranges" };

		mtf.initialize("NotepadMergeListingTest_X86", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Function function =
						createExternalFunction(program, orangesPath, addr(program, "00cc5566"));
					assertEquals(SourceType.DEFAULT, function.getSignatureSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setSignatureSource(SourceType.USER_DEFINED);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("AX")), program);
					orangesFunction.addParameter(parameter1, SourceType.USER_DEFINED);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), program);
					orangesFunction.addParameter(parameter2, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				ExternalLocation orangesLocation = getExternalLocation(program, orangesPath);
				assertNotNull(orangesLocation);
				assertTrue(orangesLocation.isFunction());
				Function orangesFunction = orangesLocation.getFunction();
				assertEquals(2, orangesFunction.getParameterCount());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function orangesFunction = getExternalFunction(program, orangesPath);
					orangesFunction.setSignatureSource(SourceType.ANALYSIS);
					orangesFunction.setCustomVariableStorage(true);

					Parameter parameter1 = new ParameterImpl("junk", new WordDataType(),
						new VariableStorage(program, program.getRegister("AX")), program);
					orangesFunction.addParameter(parameter1, SourceType.ANALYSIS);

					Parameter parameter2 = new ParameterImpl("punk", new WordDataType(),
						new VariableStorage(program, program.getRegister("BX")), program);
					orangesFunction.addParameter(parameter2, SourceType.IMPORTED);

					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
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
		assertEquals(SourceType.USER_DEFINED, orangesFunction.getSignatureSource());

		Parameter parameter1 = orangesFunction.getParameter(0);
		checkDataType(new WordDataType(), parameter1.getDataType());
		assertEquals("junk", parameter1.getName());
		assertEquals("AX", parameter1.getRegister().getName());

		Parameter parameter2 = orangesFunction.getParameter(1);
		checkDataType(new WordDataType(), parameter2.getDataType());
		assertEquals("punk", parameter2.getName());
		assertEquals("BX", parameter2.getRegister().getName());
	}

}
