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
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalMergerChangeTest extends AbstractExternalMergerTest {

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
	public ExternalMergerChangeTest() {
		super();
	}

	@Test
	public void testExternalLabelChangeLatest() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
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
		checkExternalAddress(externalLocation, "77db1130");
	}

	@Test
	public void testExternalLabelChangeMy() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1130");
	}

	@Test
	public void testExternalLabelChangeBothChooseMy() throws Exception {

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
			public void modifyLatest(ProgramDB program)
					throws InvalidInputException, CircularDependencyException {
				int txId = program.startTransaction("test");
				ExternalManager externalManager = program.getExternalManager();
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				externalLocation.setName(externalLocation.getParentNameSpace(), "joe",
					SourceType.USER_DEFINED);
				program.endTransaction(txId, true);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program)
					throws InvalidInputException, CircularDependencyException {
				int txId = program.startTransaction("test");
				ExternalManager externalManager = program.getExternalManager();
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				externalLocation.setName(externalLocation.getParentNameSpace(), "bob",
					SourceType.USER_DEFINED);
				program.endTransaction(txId, true);
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "bob");
		assertNotNull(externalLocation);

		externalLocation = externalManager.getUniqueExternalLocation("user32.dll", "joe");
		assertNull(externalLocation);
	}

	@Test
	public void testExternalLabelChangeBothSame() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1130");
	}

	@Test
	public void testExternalLabelChangeBothAddressConflictChooseLatest() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1150");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1150");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });// address
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1130");
	}

	@Test
	public void testExternalLabelChangeBothAddressConflictChooseMy() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1150");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1150");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });// non-custom storage
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1150");
	}

	@Test
	public void testExternalLabelChangeVsRemoveAddressConflictChooseLatest() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					null);

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNull(address);
//				checkExternalAddress(externalLocation, "77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1150");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1150");
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });// address
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, null);
	}

	@Test
	public void testExternalLabelChangeBothAddressSame() throws Exception {

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
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external memory address
				setAddressForExternalLabel(program, "Modify Original Program", "user32.dll", "Blue",
					"77db1130");

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1130");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1130");
	}

	@Test
	public void testExternalLabelChangeBothDataTypeConflictChooseLatest() throws Exception {

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
				// change external data type
				setDataTypeForExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new ByteDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new ByteDataType());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Data Type Conflict", LATEST_BUTTON);// Float vs Byte data type
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());
	}

	@Test
	public void testExternalLabelChangeBothDataTypeConflictChooseMy() throws Exception {

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
				// change external data type
				setDataTypeForExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new ByteDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new ByteDataType());
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Data Type Conflict", MY_BUTTON);// Float vs Byte data type
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new ByteDataType());
	}

	@Test
	public void testExternalLabelChangeBothDataTypeSame() throws Exception {

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
				// change external data type
				setDataTypeForExternalLabel(program, "Modify Latest Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());
	}

	@Test
	public void testExternalLabelAddFunctionVersusDataTypeChooseLatest() throws Exception {

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
				// change external label into function
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.createFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
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
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Versus Data Type Conflict", LATEST_BUTTON);// Float data type vs function
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		assertNull(externalLocation.getDataType());
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		Parameter parameter2 = function.getParameter(1);
		assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
		assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
	}

	@Test
	public void testExternalLabelAddFunctionVersusDataTypeChooseMy() throws Exception {

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
				// change external label into function
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.createFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
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
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Versus Data Type Conflict", MY_BUTTON);// Float data type vs function
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());
		Function function = externalLocation.getFunction();
		assertNull(function);
	}

	@Test
	public void testExternalLabelAddDataTypeVersusFunctionChooseLatest() throws Exception {

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
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external label into function
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.createFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
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
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Versus Data Type Conflict", LATEST_BUTTON);// Float data type vs function
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());
		Function function = externalLocation.getFunction();
		assertNull(function);
	}

	@Test
	public void testExternalLabelAddDataTypeVersusFunctionChooseMy() throws Exception {

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
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// change external label into function
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.createFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
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
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Versus Data Type Conflict", MY_BUTTON);// Float data type vs function
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		assertNull(externalLocation.getDataType());
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		Parameter parameter2 = function.getParameter(1);
		assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
		assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
	}

	@Test
	public void testExternalFunctionChangeParamsConflictChooseLatest() throws Exception {

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
				try {
					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Symbol symbol = externalLocation.getSymbol();
					boolean symbolRemoved = symbol.delete();
					assertTrue(symbolRemoved);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}

				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// add parameters to function.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
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
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Versus Data Type Conflict", LATEST_BUTTON);// Float data type vs function
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		checkExternalDataType(externalLocation, new FloatDataType());
		Function function = externalLocation.getFunction();
		assertNull(function);
	}

	@Test
	public void testExternalFunctionChangeParamsConflictChooseMy() throws Exception {

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
				try {
					ExternalManager externalManager = program.getExternalManager();
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Symbol symbol = externalLocation.getSymbol();
					boolean symbolRemoved = symbol.delete();
					assertTrue(symbolRemoved);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				// change external data type
				setDataTypeForExternalLabel(program, "Modify My Program", "user32.dll", "Blue",
					"77db1020", new FloatDataType());

				ExternalManager externalManager = program.getExternalManager();
				assertTrue(externalManager.contains("user32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("user32.dll", "Blue");
				assertNotNull(externalLocation);
				assertEquals("user32.dll" + "::" + "Blue", externalLocation.toString());
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				checkExternalDataType(externalLocation, new FloatDataType());
				Function function = externalLocation.getFunction();
				assertNull(function);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				// add parameters to function.
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				ExternalManager externalManager = program.getExternalManager();
				try {
					ExternalLocation externalLocation =
						externalManager.getUniqueExternalLocation("user32.dll", "Blue");
					assertNotNull(externalLocation);
					Function function = externalLocation.getFunction();
					try {
						Parameter parameter1 =
							new ParameterImpl("P1", new DWordDataType(), program);
						function.addParameter(parameter1, SourceType.ANALYSIS);
						Parameter parameter2 = new ParameterImpl("P2", new ByteDataType(), program);
						function.addParameter(parameter2, SourceType.USER_DEFINED);
					}
					catch (InvalidInputException e) {
						e.printStackTrace();
						Assert.fail();
					}
					catch (DuplicateNameException e) {
						e.printStackTrace();
						Assert.fail();
					}
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
				Address address = externalLocation.getAddress();
				assertNotNull(address);
				checkExternalAddress(externalLocation, "77db1020");
				assertNull(externalLocation.getDataType());
				Function function = externalLocation.getFunction();
				assertNotNull(function);
				assertEquals(2, function.getParameterCount());
				Parameter parameter1 = function.getParameter(0);
				Parameter parameter2 = function.getParameter(1);
				assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
				assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve External Function Versus Data Type Conflict", MY_BUTTON);// Float data type vs function
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "Blue");
		assertNotNull(externalLocation);
		checkExternalAddress(externalLocation, "77db1020");
		assertNull(externalLocation.getDataType());
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		Parameter parameter2 = function.getParameter(1);
		assertTrue(parameter1.getDataType().isEquivalent(new DWordDataType()));
		assertTrue(parameter2.getDataType().isEquivalent(new ByteDataType()));
	}

	@Test
	public void testChangeNamespaceVersusAddFunction() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createExternalFunction(program,
						new String[] { "user32.dll", "OriginalNamespace", "Foo" },
						addr(program, "77db1020"));
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
					Namespace externalNamespace = getExternalNamespace(program,
						new String[] { "user32.dll", "OriginalNamespace" });
					externalNamespace.getSymbol().setName("ChangedNamespace",
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
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createExternalFunction(program,
						new String[] { "user32.dll", "ChangedNamespace" },
						addr(program, "77db1130"));
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
		assertTrue(externalManager.contains("user32.dll"));
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("user32.dll", "ChangedNamespace");
		assertNotNull(externalLocation);
		assertTrue(externalLocation.getSymbol() instanceof FunctionSymbol);
		assertEquals("ChangedNamespace", externalLocation.getLabel());
		Namespace namespace =
			getExternalNamespace(resultProgram, new String[] { "user32.dll", "ChangedNamespace" });
		assertNotNull(namespace);

	}

	@Test
	public void testExternalLabelChangeVersusNamespaceRename() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "Blue" };
		final String[] namespacePath = new String[] { "user32.dll", "Class1" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, applesPath, addr(program, "77db1020"),
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
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					externalLocation.setLocation("pink", externalLocation.getAddress(),
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation =
					getExternalLocation(program, new String[] { "user32.dll", "Class1", "pink" });
				assertNotNull(externalLocation);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Namespace externalNamespace = getExternalNamespace(program, namespacePath);
					externalNamespace.getSymbol().setName("OtherNamespace",
						SourceType.USER_DEFINED);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation = getExternalLocation(program,
					new String[] { "user32.dll", "OtherNamespace", "Blue" });
				assertNotNull(externalLocation);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalLocation externalLocation = getExternalLocation(resultProgram,
			new String[] { "user32.dll", "OtherNamespace", "pink" });
		assertNotNull(externalLocation);
	}

	@Test
	public void testExternalLabelMoveToDifferentNamespacesPickLatest() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "Blue" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, applesPath, addr(program, "77db1020"),
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
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					Symbol symbol = externalLocation.getSymbol();
					Namespace namespaceAA = createExternalNamespace(program,
						new String[] { "user32.dll", "NamespaceAA" }, SourceType.USER_DEFINED);
					symbol.setNamespace(namespaceAA);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation = getExternalLocation(program,
					new String[] { "user32.dll", "NamespaceAA", "Blue" });
				assertNotNull(externalLocation);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					Symbol symbol = externalLocation.getSymbol();
					Namespace namespaceAA = createExternalNamespace(program,
						new String[] { "user32.dll", "NamespaceBB" }, SourceType.USER_DEFINED);
					symbol.setNamespace(namespaceAA);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation = getExternalLocation(program,
					new String[] { "user32.dll", "NamespaceBB", "Blue" });
				assertNotNull(externalLocation);
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		ExternalLocation externalLocation1 =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "Class1", "Blue" });
		assertNull(externalLocation1);
		ExternalLocation externalLocationAA = getExternalLocation(resultProgram,
			new String[] { "user32.dll", "NamespaceAA", "Blue" });
		assertNotNull(externalLocationAA);
		ExternalLocation externalLocationBB = getExternalLocation(resultProgram,
			new String[] { "user32.dll", "NamespaceBB", "Blue" });
		assertNull(externalLocationBB);
		assertEquals(addr(resultProgram, "77db1020"), externalLocationAA.getAddress());
		assertEquals(SourceType.USER_DEFINED, externalLocationAA.getSource());
	}

	@Test
	public void testExternalLabelMoveToDifferentNamespacesPickMy() throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "Blue" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, applesPath, addr(program, "77db1020"),
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
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					Symbol symbol = externalLocation.getSymbol();
					Namespace namespaceAA = createExternalNamespace(program,
						new String[] { "user32.dll", "NamespaceAA" }, SourceType.USER_DEFINED);
					symbol.setNamespace(namespaceAA);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation = getExternalLocation(program,
					new String[] { "user32.dll", "NamespaceAA", "Blue" });
				assertNotNull(externalLocation);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					Symbol symbol = externalLocation.getSymbol();
					Namespace namespaceAA = createExternalNamespace(program,
						new String[] { "user32.dll", "NamespaceBB" }, SourceType.USER_DEFINED);
					symbol.setNamespace(namespaceAA);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation = getExternalLocation(program,
					new String[] { "user32.dll", "NamespaceBB", "Blue" });
				assertNotNull(externalLocation);
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		ExternalLocation externalLocation1 =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "Class1", "Blue" });
		assertNull(externalLocation1);
		ExternalLocation externalLocationAA = getExternalLocation(resultProgram,
			new String[] { "user32.dll", "NamespaceAA", "Blue" });
		assertNull(externalLocationAA);
		ExternalLocation externalLocationBB = getExternalLocation(resultProgram,
			new String[] { "user32.dll", "NamespaceBB", "Blue" });
		assertNotNull(externalLocationBB);
		assertEquals(addr(resultProgram, "77db1020"), externalLocationBB.getAddress());
		assertEquals(SourceType.USER_DEFINED, externalLocationBB.getSource());
	}

	@Test
	public void testExternalLabelMoveToDifferentNamespacesAndLocationConflictsWithNamespacePickMy()
			throws Exception {

		final String[] applesPath = new String[] { "user32.dll", "Class1", "Blue" };

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					createExternalLabel(program, applesPath, addr(program, "77db1020"),
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

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					Symbol symbol = externalLocation.getSymbol();
					Namespace namespaceAA = createExternalNamespace(program,
						new String[] { "user32.dll", "AA" }, SourceType.USER_DEFINED);
					symbol.setNamespace(namespaceAA);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocation =
					getExternalLocation(program, new String[] { "user32.dll", "AA", "Blue" });
				assertNotNull(externalLocation);
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					createExternalLabel(program, new String[] { "user32.dll", "AA" }, null,
						SourceType.USER_DEFINED);
					ExternalLocation externalLocation = getExternalLocation(program, applesPath);
					Symbol symbol = externalLocation.getSymbol();
					Namespace namespaceAA = createExternalNamespace(program,
						new String[] { "user32.dll", "NamespaceBB" }, SourceType.USER_DEFINED);
					symbol.setNamespace(namespaceAA);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ExternalLocation externalLocationAA =
					getExternalLocation(program, new String[] { "user32.dll", "AA" });
				assertNotNull(externalLocationAA);
				ExternalLocation externalLocation = getExternalLocation(program,
					new String[] { "user32.dll", "NamespaceBB", "Blue" });
				assertNotNull(externalLocation);
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
			new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		ExternalLocation externalLocation1 =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "Class1", "Blue" });
		assertNull(externalLocation1);
		ExternalLocation externalLocationAA =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "AA" });
		assertNull(externalLocationAA);
		ExternalLocation externalLocationAABlue =
			getExternalLocation(resultProgram, new String[] { "user32.dll", "AA", "Blue" });
		assertNull(externalLocationAABlue);
		ExternalLocation externalLocationBB = getExternalLocation(resultProgram,
			new String[] { "user32.dll", "NamespaceBB", "Blue" });
		assertNotNull(externalLocationBB);
		assertEquals(addr(resultProgram, "77db1020"), externalLocationBB.getAddress());
		assertEquals(SourceType.USER_DEFINED, externalLocationBB.getSource());
	}
}
