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

import ghidra.program.database.OriginalProgramModifierListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalMergerRemoveTest extends AbstractExternalMergerTest {

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
	public ExternalMergerRemoveTest() {
		super();
	}

	@Test
	public void testExternalLabelRemoveFromLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", null, SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// No changes
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalLabelRemoveFromMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", null, SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalLabel(program, "Modify My Program", "user32.dll", "Blue");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalLabelRemoveFromBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", null, SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalLabel(program, "Modify My Program", "user32.dll", "Blue");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalDataTypeRemoveFromLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// No changes
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
	}

	@Test
	public void testExternalDataTypeRemoveFromMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
	}

	@Test
	public void testExternalDataTypeRemoveFromBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020");
			}

		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
	}

	@Test
	public void testExternalAddressRemoveFromLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// No changes
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}

	@Test
	public void testExternalAddressRemoveFromMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify My Program", "user32.dll", "Blue");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}

	@Test
	public void testExternalAddressRemoveFromBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify My Program", "user32.dll", "Blue");
			}

		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}

	@Test
	public void testExternalFunctionRemoveFromLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeExternalFunctionLocation(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// No changes
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
		FunctionIterator externalFunctions =
			resultProgram.getFunctionManager().getExternalFunctions();
		assertEquals(false, externalFunctions.hasNext());
	}

	@Test
	public void testExternalFunctionRemoveFromMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalFunctionLocation(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		SymbolTable symbolTable = resultProgram.getSymbolTable();
		Symbol s = symbolTable.getLibrarySymbol("user32.dll");
		if (s != null) {
			Symbol symbol = getUniqueSymbol(resultProgram, "Blue", (Namespace) s.getObject());
			assertNull(symbol);
		}

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
		FunctionIterator externalFunctions =
			resultProgram.getFunctionManager().getExternalFunctions();
		assertEquals(false, externalFunctions.hasNext());
	}

	@Test
	public void testExternalFunctionRemoveFromBoth() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeExternalFunctionLocation(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalFunctionLocation(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020");
			}

		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
		FunctionIterator externalFunctions =
			resultProgram.getFunctionManager().getExternalFunctions();
		assertEquals(false, externalFunctions.hasNext());
	}

	@Test
	public void testExternalDataTypeRemoveLatestChangeMyChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setDataType(new FloatDataType());// Change data type; not its size.
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new FloatDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Data Type Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
	}

	@Test
	public void testExternalDataTypeRemoveLatestChangeMyChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setDataType(new FloatDataType());// Change data type; not its size.
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new FloatDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Data Type Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new FloatDataType()));
	}

	@Test
	public void testExternalDataTypeChangeLatestRemoveMyChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setDataType(new FloatDataType());// Change data type; not its size.
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new FloatDataType()));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Data Type Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new FloatDataType()));
	}

	@Test
	public void testExternalDataTypeChangeLatestRemoveMyChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setDataType(new FloatDataType());// Change data type; not its size.
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new FloatDataType()));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeDataTypeFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue", "77db1020");
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Data Type Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNull(dataType);
	}

	@Test
	public void testExternalLabelChangeLatestRemoveMyChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setLocation("Red", externalLocation.getAddress(),
						externalLocation.getSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Red");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Red", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new DWordDataType()));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue");
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Red", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalLabelChangeLatestRemoveMyChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setLocation("Red", externalLocation.getAddress(),
						externalLocation.getSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Red");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Red", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new DWordDataType()));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue");
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNull(externalLocation);
		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalLabelRemoveLatestChangeMyChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setLocation("Red", externalLocation.getAddress(),
						externalLocation.getSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Red");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Red", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new DWordDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNull(externalLocation);
		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalLabelRemoveLatestChangeMyChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change DataType
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					externalLocation.setLocation("Red", externalLocation.getAddress(),
						externalLocation.getSource());
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Red");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Red", externalLocation.toString());
				DataType dataType = externalLocation.getDataType();
				assertNotNull(dataType);
				assertTrue(dataType.isEquivalent(new DWordDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Red", externalLocation.toString());
		assertEquals(addr(resultProgram, "77db1020"), externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalFunctionRemoveLatestChangeMyChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				changeExternalFunctionIntoExternalLabel(program,
					new String[] { "user32.dll", "Blue" });
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertTrue(function.getReturnType().isEquivalent(new FloatDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertFalse(externalLocation.isFunction());
		FunctionIterator externalFunctions =
			resultProgram.getFunctionManager().getExternalFunctions();
		assertEquals(false, externalFunctions.hasNext());
	}

	@Test
	public void testExternalFunctionRemoveLatestChangeMyChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				changeExternalFunctionIntoExternalLabel(program,
					new String[] { "user32.dll", "Blue" });

				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function externalLocation =
						createExternalFunction(program, new String[] { "user32.dll", "Red" },
							addr(program, "77db1450"), null, SourceType.USER_DEFINED);
					assertNotNull(externalLocation);
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
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertTrue(function.getReturnType().isEquivalent(new FloatDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertTrue(function.getReturnType().isEquivalent(new FloatDataType()));
		ExternalLocation externalLocation2 =
			externalManager.getUniqueExternalLocation("user32.dll", "Red");
		assertNotNull(externalLocation2);
	}

	@Test
	public void testExternalFunctionChangeLatestRemoveMyChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					function.addParameter(parameter1, SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				checkFunctionReturnType(function, DataType.DEFAULT);
				Parameter parameter = function.getParameter(0);
				assertEquals("P1", parameter.getName());
				checkParameterDataType(parameter, new DWordDataType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				changeExternalFunctionIntoExternalLabel(program,
					new String[] { "user32.dll", "Blue" });
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		checkFunctionReturnType(function, DataType.DEFAULT);
		Parameter parameter = function.getParameter(0);
		assertEquals("P1", parameter.getName());
		checkParameterDataType(parameter, new DWordDataType());
	}

	@Test
	public void testExternalFunctionChangeLatestRemoveMyChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalFunction(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), program);
					function.addParameter(parameter1, SourceType.ANALYSIS);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				checkFunctionReturnType(function, DataType.DEFAULT);
				Parameter parameter = function.getParameter(0);
				assertEquals("P1", parameter.getName());
				checkParameterDataType(parameter, new DWordDataType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				changeExternalFunctionIntoExternalLabel(program,
					new String[] { "user32.dll", "Blue" });
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Remove Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertFalse(externalLocation.isFunction());
		FunctionIterator externalFunctions =
			resultProgram.getFunctionManager().getExternalFunctions();
		assertEquals(false, externalFunctions.hasNext());
	}

	@Test
	public void testExternalAddressRemoveFromLatestChangeInMyKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				changeMemAddressForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1130");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}

	@Test
	public void testExternalAddressRemoveFromLatestChangeInMyKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				changeMemAddressForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1130");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		checkExternalAddress(externalLocation, "77db1130");
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}

	@Test
	public void testExternalAddressRemoveFromMyChangeInLatestKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				changeMemAddressForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		checkExternalAddress(externalLocation, "77db1130");
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}

	@Test
	public void testExternalAddressRemoveFromMyChangeInLatestKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				createExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1020", new DWordDataType(), SourceType.USER_DEFINED);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				changeMemAddressForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				removeAddressFromExternalLabel(program, "Modify Latest Program", "user32.dll",
					"Blue");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		assertEquals("user32.dll::Blue", externalLocation.toString());
		assertNull(externalLocation.getAddress());
		assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
		DataType dataType = externalLocation.getDataType();
		assertNotNull(dataType);
		assertTrue(dataType.isEquivalent(new DWordDataType()));
	}
}
