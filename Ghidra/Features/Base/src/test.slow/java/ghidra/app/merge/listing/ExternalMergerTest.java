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

import ghidra.app.cmd.function.CreateExternalFunctionCmd;
import ghidra.app.cmd.refs.SetExternalRefCmd;
import ghidra.program.database.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class ExternalMergerTest extends AbstractExternalMergerTest {

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
	public ExternalMergerTest() {
		super();
	}

	@Test
	public void testExtLabelRefAddSameNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testAddDiffRefsToSameExternalNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", null, SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001538"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001538"), "advapi32.dll",
						"oranges", null, SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		ReferenceIterator referencesTo =
			refMgr.getReferencesTo(extLocOranges.getExternalSpaceAddress());
		assertTrue(referencesTo.hasNext());
		Reference reference = referencesTo.next();
		Address fromAddress = reference.getFromAddress();
		assertEquals(addr("0x1001504"), fromAddress);
		assertTrue(referencesTo.hasNext());
		reference = referencesTo.next();
		fromAddress = reference.getFromAddress();
		assertEquals(addr("0x1001538"), fromAddress);

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelRefAddDiffConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", null, SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"apples", null, SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		// NOTE: Duplicate external program address is not treated as conflict, bot external
		// locations will be added.
		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON);// Add Conflict
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocApples =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		assertNotNull(extLocApples);

		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelRefAddDiffConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", null, SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"apples", null, SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		// NOTE: Duplicate external program address is not treated as conflict, bot external
		// locations will be added.
		chooseButtonAndApply("Resolve Reference Conflict", MY_BUTTON);// Add Conflict
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocApples =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		assertNotNull(extLocApples);

		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::apples",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelOnlyRefChangeSameNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x01234567"), RefType.COMPUTED_CALL_TERMINATOR);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::grapes",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x01234567"), RefType.COMPUTED_CALL_TERMINATOR);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals(RefType.COMPUTED_CALL_TERMINATOR, refs[0].getReferenceType());
				assertEquals("advapi32.dll::grapes",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocGrapes =
			externalManager.getUniqueExternalLocation("advapi32.dll", "grapes");
		assertNotNull(extLocGrapes);
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::grapes",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelOnlyRefChangeDiffConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "apples",
						addr(program, "0x01234567"), RefType.COMPUTED_CALL_TERMINATOR);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::apples",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x01234567"), RefType.COMPUTED_CALL_TERMINATOR);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::grapes",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocApples =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		assertNotNull(extLocApples);
		ExternalLocation extLocGrapes =
			externalManager.getUniqueExternalLocation("advapi32.dll", "grapes");
		assertNull(extLocGrapes);
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals(RefType.COMPUTED_CALL_TERMINATOR, refs[0].getReferenceType());
		assertEquals("advapi32.dll::apples",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelOnlyRefChangeDiffConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "apples",
						addr(program, "0x01234567"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::apples",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x01234567"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);

				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::grapes",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocApples =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		assertNull(extLocApples);
		ExternalLocation extLocGrapes =
			externalManager.getUniqueExternalLocation("advapi32.dll", "grapes");
		assertNotNull(extLocGrapes);
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::grapes",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelOnlyRefChangeDiffConflictKeepLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "apples",
						addr(program, "0x01234567"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::apples",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x01234567"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::grapes",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocApples =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		assertNotNull(extLocApples);
		ExternalLocation extLocGrapes =
			externalManager.getUniqueExternalLocation("advapi32.dll", "grapes");
		assertNull(extLocGrapes);
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::apples",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelOnlyRefChangeDiffConflictKeepMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "apples",
						addr(program, "0x01234567"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::apples",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x01234567"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
				assertEquals(1, refs.length);
				assertEquals("advapi32.dll::grapes",
					((ExternalReference) refs[0]).getExternalLocation().toString());
				assertEquals("01234567",
					((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
				assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocApples =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		assertNull(extLocApples);
		ExternalLocation extLocGrapes =
			externalManager.getUniqueExternalLocation("advapi32.dll", "grapes");
		assertNotNull(extLocGrapes);
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::grapes",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelAndAddressRefChangeSameNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x11111111"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x11111111"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation extLocGrapes =
			externalManager.getUniqueExternalLocation("advapi32.dll", "grapes");
		assertNotNull(extLocGrapes);
		ExternalLocation extLocOranges =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(extLocOranges);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::grapes",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("11111111",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelAndAddressRefChangeDiffConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "apples",
						addr(program, "0x11111111"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x87654321"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::apples",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("11111111",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelAndAddressRefChangeDiffConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "apples",
						addr(program, "0x11111111"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(1, refs.length);
					assertTrue(refs[0].isExternalReference());
					changeExternalReferenceLabel(program, (ExternalReference) refs[0], "grapes",
						addr(program, "0x87654321"), RefType.DATA);

//					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
//						"grapes", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
//						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::grapes",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("87654321",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtAddressRefAddSameNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);

					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll", null,
						addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);

					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll", null,
						addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::EXT_77db1020",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1020",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtAddressRefAddDiffConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);

					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll", null,
						addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);

					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll", null,
						addr(program, "0x77db1130"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::EXT_77db1020",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1020",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtAddressRefAddDiffConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);

					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll", null,
						addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);

					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll", null,
						addr(program, "0x77db1130"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::EXT_77db1130",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1130",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelRefAddSameAddressNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1020",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelRefAddDiffAddressConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1130"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1020",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelRefAddDiffAddressConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1130"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1130",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
	}

	@Test
	public void testExtLabelRefAddDiffLibraryPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "usr32.dll", "oranges",
						addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("advapi32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1020",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation latestExtLoc =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNotNull(latestExtLoc);
		ExternalLocation myExtLoc =
			externalManager.getUniqueExternalLocation("usr32.dll", "oranges");
		assertNull(myExtLoc);
	}

	@Test
	public void testExtLabelRefAddDiffLibraryConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "advapi32.dll",
						"oranges", addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0,
						RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x1001504"), "usr32.dll", "oranges",
						addr(program, "0x77db1020"), SourceType.USER_DEFINED, 0, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		assertEquals("usr32.dll::oranges",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db1020",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation latestExtLoc =
			externalManager.getUniqueExternalLocation("advapi32.dll", "oranges");
		assertNull(latestExtLoc);
		ExternalLocation myExtLoc =
			externalManager.getUniqueExternalLocation("usr32.dll", "oranges");
		assertNotNull(myExtLoc);
	}

	@Test
	public void testExtFunctionRefAddSameNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals("undefined oranges()", function.getPrototypeString(false, false));
	}

	@Test
	public void testExtFunctionRefAddLatestOnlyNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// Do nothing
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals("undefined oranges()", function.getPrototypeString(false, false));
	}

	@Test
	public void testExtFunctionRefAddMyOnlyNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Do nothing
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					assertNotNull(function);
					function.setSignatureSource(SourceType.USER_DEFINED);
					assertEquals("undefined oranges(void)",
						function.getPrototypeString(false, false));
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(SourceType.USER_DEFINED, function.getSignatureSource());
		assertEquals("undefined oranges(void)", function.getPrototypeString(false, false));
	}

	@Test
	public void testExtFunctionRefAddParamChooseLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					Parameter parameter = new ParameterImpl("P1", new DWordDataType(), 4, program);
					function.addParameter(parameter, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals("undefined oranges(dword P1)", function.getPrototypeString(false, false));
	}

	@Test
	public void testExtFunctionRefAddParamChooseMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					Parameter parameter = new ParameterImpl("P1", new DWordDataType(), 4, program);
					function.addParameter(parameter, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					assertNotNull(function);
					assertEquals("undefined oranges()", function.getPrototypeString(false, false));
					assertEquals(SourceType.DEFAULT, function.getSignatureSource());
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals(SourceType.DEFAULT, function.getSignatureSource());
		assertEquals("undefined oranges()", function.getPrototypeString(false, false));
	}

	@Test
	public void testExtFunctionRefAddParamConflictPickLatest() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					Parameter parameter = new ParameterImpl("P1", new DWordDataType(), 4, program);
					function.addParameter(parameter, SourceType.USER_DEFINED);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					Parameter parameter = new ParameterImpl("Size", new ByteDataType(), 4, program);
					function.addParameter(parameter, SourceType.USER_DEFINED);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals("undefined oranges(dword P1)", function.getPrototypeString(false, false));
	}

	@Test
	public void testExtFunctionRefAddParamConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					Parameter parameter = new ParameterImpl("P1", new DWordDataType(), 4, program);
					function.addParameter(parameter, SourceType.USER_DEFINED);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001504"), 0);
					assertEquals(0, refs.length);
					Reference ref = refMgr.addExternalReference(addr(program, "0x1001504"),
						"advapi32.dll", "oranges", addr(program, "0x77db1020"),
						SourceType.USER_DEFINED, 0, RefType.DATA);
					ExternalLocation externalLocation =
						((ExternalReference) ref).getExternalLocation();
					Symbol symbol = externalLocation.getSymbol();
					Address address = symbol.getAddress();
					CreateExternalFunctionCmd createExternalFunctionCmd =
						new CreateExternalFunctionCmd(symbol);
					boolean created = createExternalFunctionCmd.applyTo(program);
					if (!created) {
						Assert.fail("Create function failed in Latest setup!");
					}
					FunctionManager functionManager = program.getFunctionManager();
					Function function = functionManager.getFunctionAt(address);
					Parameter parameter = new ParameterImpl("Size", new ByteDataType(), 8, program);
					function.addParameter(parameter, SourceType.USER_DEFINED);
					assertNotNull(function);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve External Add Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x1001504"), 0);
		assertEquals(1, refs.length);
		ExternalLocation externalLocation = ((ExternalReference) refs[0]).getExternalLocation();
		assertEquals("advapi32.dll::oranges", externalLocation.toString());
		assertEquals("77db1020", externalLocation.getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
		Function function = externalLocation.getFunction();
		assertNotNull(function);
		assertEquals("undefined oranges(byte Size)", function.getPrototypeString(false, false));
	}

	@Test
	public void testBothRemoveExtFunctionNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				ExternalManager externalManager = program.getExternalManager();
				try {
					externalManager.addExtFunction("advapi32.dll", "apples",
						addr(program, "77db1020"), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				assertTrue(externalManager.contains("advapi32.dll"));
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
				assertNotNull(externalLocation);
				assertEquals(true, externalLocation.isFunction());

				assertEquals("advapi32.dll::apples", externalLocation.toString());
				assertEquals(addr(program, "77db1020"), externalLocation.getAddress());
				assertTrue(externalLocation.getSource() == SourceType.USER_DEFINED);
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				ExternalManager externalManager = program.getExternalManager();
				FunctionManager functionManager = program.getFunctionManager();
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
				assertNotNull(externalLocation);
				Address externalSpaceAddress = externalLocation.getExternalSpaceAddress();
				assertNotNull(externalSpaceAddress);
				try {
					boolean removed = functionManager.removeFunction(externalSpaceAddress);
					assertTrue(removed);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				assertTrue(externalManager.contains("advapi32.dll"));
				externalLocation =
					externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
				Symbol symbol = externalLocation.getSymbol();
				SymbolType symbolType = symbol.getSymbolType();
				assertEquals(SymbolType.LABEL, symbolType);

				assertNull(functionManager.getFunctionAt(externalSpaceAddress));
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				ExternalManager externalManager = program.getExternalManager();
				FunctionManager functionManager = program.getFunctionManager();
				ExternalLocation externalLocation =
					externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
				assertNotNull(externalLocation);
				Address externalSpaceAddress = externalLocation.getExternalSpaceAddress();
				assertNotNull(externalSpaceAddress);
				try {
					functionManager.removeFunction(externalSpaceAddress);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				assertTrue(externalManager.contains("advapi32.dll"));
				externalLocation =
					externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
				Symbol symbol = externalLocation.getSymbol();
				SymbolType symbolType = symbol.getSymbolType();
				assertEquals(SymbolType.LABEL, symbolType);

				assertNull(functionManager.getFunctionAt(externalSpaceAddress));
			}
		});

		resultProgram = mtf.getResultProgram();// destination program
		ExternalManager externalManager = resultProgram.getExternalManager();
		ExternalLocation externalLocation =
			externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		externalLocation = externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		Symbol symbol = externalLocation.getSymbol();
		assertNull(externalLocation.getFunction());
		SymbolType symbolType = symbol.getSymbolType();
		assertEquals(SymbolType.LABEL, symbolType);
		Address externalSpaceAddress = externalLocation.getExternalSpaceAddress();
		assertNotNull(externalSpaceAddress);

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		externalLocation = externalManager.getUniqueExternalLocation("advapi32.dll", "apples");
		symbol = externalLocation.getSymbol();
		assertNull(externalLocation.getFunction());
		symbolType = symbol.getSymbolType();
		assertEquals(SymbolType.LABEL, symbolType);

		FunctionManager functionManager = resultProgram.getFunctionManager();
		assertNull(functionManager.getFunctionAt(externalSpaceAddress));
	}

	@Test
	public void testChangeDiffExternalFunction2ChooseLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function function = createExternalFunction(program,
						new String[] { "user32.dll", "MyNamespace", "apples" },
						addr(program, "77db1020"), new DWordDataType(), SourceType.USER_DEFINED);
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function function = getExternalFunction(program,
						new String[] { "user32.dll", "MyNamespace", "apples" });

					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P2", new DWordDataType(), 4, program);
					parameter1.setComment("Latest Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function function = getExternalFunction(program,
						new String[] { "user32.dll", "MyNamespace", "apples" });

					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					Register register = program.getRegister("r0");
					Parameter parameter1 =
						new ParameterImpl("Length", new CharDataType(), register, program);
					parameter1.setComment("My Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Return Conflict", LATEST_BUTTON);// Return Type
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY, KEEP_LATEST });
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
		checkFunctionReturnType(function, new ByteDataType());
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("P1", parameter1.getName());
		assertEquals("Test Parameter Comment", parameter1.getComment());
		checkParameterDataType(parameter1, new DWordDataType());
		Parameter parameter2 = function.getParameter(1);
		assertEquals("P2", parameter2.getName());
		assertEquals("Latest Parameter Comment", parameter2.getComment());
		checkParameterDataType(parameter2, new CharDataType());
	}

	@Test
	public void testChangeDiffExternalFunction2ChooseMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					Function function = createExternalFunction(program,
						new String[] { "user32.dll", "MyNamespace", "apples" },
						addr(program, "77db1020"), new DWordDataType(), SourceType.USER_DEFINED);
					assertNotNull(function);
					Parameter parameter1 = new ParameterImpl("P1", new DWordDataType(), 4, program);
					parameter1.setComment("Test Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					Function function = getExternalFunction(program,
						new String[] { "user32.dll", "MyNamespace", "apples" });

					assertNotNull(function);
					function.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					Parameter parameter1 = new ParameterImpl("P2", new DWordDataType(), 4, program);
					parameter1.setComment("Latest Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					Function function = getExternalFunction(program,
						new String[] { "user32.dll", "MyNamespace", "apples" });

					assertNotNull(function);
					function.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					Register register = program.getRegister("r0");
					Parameter parameter1 =
						new ParameterImpl("Length", new CharDataType(), register, program);
					parameter1.setComment("My Parameter Comment");
					function.addParameter(parameter1, SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Function Return Conflict", MY_BUTTON);// Return Type
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY, KEEP_LATEST, KEEP_MY });
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
		checkFunctionReturnType(function, new FloatDataType());
		assertEquals(2, function.getParameterCount());
		Parameter parameter1 = function.getParameter(0);
		assertEquals("P1", parameter1.getName());
		assertEquals("Test Parameter Comment", parameter1.getComment());
		checkParameterDataType(parameter1, new DWordDataType());
		Parameter parameter2 = function.getParameter(1);
		assertEquals("Length", parameter2.getName());
		assertEquals("My Parameter Comment", parameter2.getComment());
		checkParameterDataType(parameter2, new DWordDataType());
	}

	@Test
	public void testChangeExternalParameterNameChooseMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
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
			public void modifyLatest(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					SymbolType librarySymbolType = librarySymbol.getSymbolType();
					assertEquals(SymbolType.LIBRARY, librarySymbolType);
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol namespaceSymbol =
						getUniqueSymbol(program, "MyNamespace", externalLibrary);
					SymbolType namespaceSymbolType = namespaceSymbol.getSymbolType();
					assertEquals(SymbolType.NAMESPACE, namespaceSymbolType);
					Namespace myNamespace = (Namespace) namespaceSymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", myNamespace);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					assertNotNull(function);
					Parameter parameter = function.getParameter(0);
					parameter.setName("Strength", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					SymbolType librarySymbolType = librarySymbol.getSymbolType();
					assertEquals(SymbolType.LIBRARY, librarySymbolType);
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol namespaceSymbol =
						getUniqueSymbol(program, "MyNamespace", externalLibrary);
					SymbolType namespaceSymbolType = namespaceSymbol.getSymbolType();
					assertEquals(SymbolType.NAMESPACE, namespaceSymbolType);
					Namespace myNamespace = (Namespace) namespaceSymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", myNamespace);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					assertNotNull(function);
					Parameter parameter = function.getParameter(0);
					parameter.setName("Power", SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY });
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
		checkFunctionReturnType(function, new ByteDataType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals("Power", parameter.getName());
		assertEquals("Test Parameter Comment", parameter.getComment());
		checkParameterDataType(parameter, new DWordDataType());
	}

	@Test
	public void testChangeExternalParameterCommentChooseMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
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
			public void modifyLatest(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol namespaceSymbol =
						getUniqueSymbol(program, "MyNamespace", externalLibrary);
					SymbolType namespaceSymbolType = namespaceSymbol.getSymbolType();
					assertEquals(SymbolType.NAMESPACE, namespaceSymbolType);
					Namespace myNamespace = (Namespace) namespaceSymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", myNamespace);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					assertNotNull(function);
					Parameter parameter = function.getParameter(0);
					parameter.setComment("Modified Latest comment.");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					SymbolTable symbolTable = program.getSymbolTable();
					Symbol librarySymbol = symbolTable.getLibrarySymbol("user32.dll");
					SymbolType librarySymbolType = librarySymbol.getSymbolType();
					assertEquals(SymbolType.LIBRARY, librarySymbolType);
					Library externalLibrary = (Library) librarySymbol.getObject();

					Symbol namespaceSymbol =
						getUniqueSymbol(program, "MyNamespace", externalLibrary);
					SymbolType namespaceSymbolType = namespaceSymbol.getSymbolType();
					assertEquals(SymbolType.NAMESPACE, namespaceSymbolType);
					Namespace myNamespace = (Namespace) namespaceSymbol.getObject();

					Symbol functionSymbol = getUniqueSymbol(program, "apples", myNamespace);
					SymbolType functionSymbolType = functionSymbol.getSymbolType();
					assertEquals(SymbolType.FUNCTION, functionSymbolType);
					Function function = (Function) functionSymbol.getObject();

					assertNotNull(function);
					Parameter parameter = function.getParameter(0);
					parameter.setComment("Changed My comment.");
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY });
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
		checkFunctionReturnType(function, new ByteDataType());
		assertEquals(1, function.getParameterCount());
		Parameter parameter = function.getParameter(0);
		assertEquals("P1", parameter.getName());
		assertEquals("Changed My comment.", parameter.getComment());
		checkParameterDataType(parameter, new DWordDataType());
	}

//	public void testChangeDiffExternalThunkFunction2ChooseMy() throws Exception {
//		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {
//			// FIXME Finish this.
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			@Override
//			public void modifyOriginal(ProgramDB program) {
//				int txId = program.startTransaction("Modify Original Program");
//				boolean commit = false;
//				try {
//					Function applesFunction =
//						program.getFunctionManager().getFunctionAt(addr(program, "01003250"));
////						createFunction(program, new String[] { "user32.dll", "MyNamespace",
////							"apples" });
//
//					Function orangesFunction =
//						createExternalFunction(program, new String[] { "user32.dll", "MyNamespace",
//							"oranges" });
//
//					assertNotNull(applesFunction);
//					assertNotNull(orangesFunction);
//
//					applesFunction.setThunkedFunction(orangesFunction);
//
////					function.setReturnType(new ByteDataType());
////					Parameter parameter1 =
////						new StackParameterImpl("P1", new DWordDataType(), 4,
////							"Test Parameter Comment", 0, SourceType.USER_DEFINED);
////					function.addParameter(parameter1, SourceType.USER_DEFINED);
//					String applesName = applesFunction.getName(true);
//					String orangesName = orangesFunction.getName(true);
//					System.out.println("apples=" + applesName + "    oranges=" + orangesName);
//					commit = true;
//				}
//				catch (Exception e) {
//					Assert.fail(e.getMessage());
//				}
//				finally {
//					program.endTransaction(txId, commit);
//				}
//				SymbolTable symtab = program.getSymbolTable();
//				FunctionManager functionManager = program.getFunctionManager();
//				Namespace externalLibrary =
//					(Namespace) symtab.getLibrarySymbol("user32.dll").getObject();
//				assertNotNull(externalLibrary);
//				Namespace myNamespace =
//					(Namespace) symtab.getUniqueSymbol("MyNamespace", externalLibrary).getObject();
//				assertNotNull(myNamespace);
//				FunctionIterator externalFunctions = functionManager.getExternalFunctions();
//				Function extFunction = externalFunctions.next();
//				Function apples = extFunction;
//				Symbol oranges = symtab.getUniqueSymbol("oranges", myNamespace);
//				System.out.println("apples=" + apples.getName(true) + "    oranges=" +
//					oranges.getName(true));
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			@Override
//			public void modifyLatest(ProgramDB program) {
////				int txId = program.startTransaction("Modify Latest Program");
////				boolean commit = false;
////				try {
////					SymbolTable symbolTable = program.getSymbolTable();
////					Symbol librarySymbol =
////						symbolTable.getLibrarySymbol("user32.dll");
////					SymbolType librarySymbolType = librarySymbol.getSymbolType();
////					assertEquals(SymbolType.LIBRARY, librarySymbolType);
////					Library externalLibrary = (Library) librarySymbol.getObject();
////
////					Symbol namespaceSymbol = symbolTable.getUniqueSymbol("MyNamespace", externalLibrary);
////					SymbolType namespaceSymbolType = namespaceSymbol.getSymbolType();
////					assertEquals(SymbolType.NAMESPACE, namespaceSymbolType);
////					Namespace myNamespace = (Namespace) namespaceSymbol.getObject();
////
////					Symbol functionSymbol = symbolTable.getUniqueSymbol("apples", myNamespace);
////					SymbolType functionSymbolType = functionSymbol.getSymbolType();
////					assertEquals(SymbolType.FUNCTION, functionSymbolType);
////					Function function = (Function) functionSymbol.getObject();
////
////					assertNotNull(function);
////					function.setReturnType(new ByteDataType());
////					Parameter parameter1 =
////						new StackParameterImpl("P1", new DWordDataType(), 4,
////							"Test Parameter Comment", 0, SourceType.USER_DEFINED);
////					function.addParameter(parameter1, SourceType.USER_DEFINED);
////					commit = true;
////				}
////				catch (Exception e) {
////					Assert.fail(e.getMessage());
////				}
////				finally {
////					program.endTransaction(txId, commit);
////				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			@Override
//			public void modifyPrivate(ProgramDB program) {
////				int txId = program.startTransaction("Modify My Program");
////				boolean commit = false;
////				try {
////					SymbolTable symbolTable = program.getSymbolTable();
////					Symbol librarySymbol =
////						symbolTable.getLibrarySymbol("user32.dll");
////					SymbolType librarySymbolType = librarySymbol.getSymbolType();
////					assertEquals(SymbolType.LIBRARY, librarySymbolType);
////					Library externalLibrary = (Library) librarySymbol.getObject();
////
////					Symbol namespaceSymbol = symbolTable.getUniqueSymbol("MyNamespace", externalLibrary);
////					SymbolType namespaceSymbolType = namespaceSymbol.getSymbolType();
////					assertEquals(SymbolType.NAMESPACE, namespaceSymbolType);
////					Namespace myNamespace = (Namespace) namespaceSymbol.getObject();
////
////					Symbol functionSymbol = symbolTable.getUniqueSymbol("apples", myNamespace);
////					SymbolType functionSymbolType = functionSymbol.getSymbolType();
////					assertEquals(SymbolType.FUNCTION, functionSymbolType);
////					Function function = (Function) functionSymbol.getObject();
////
////					assertNotNull(function);
////					function.setReturnType(new ByteDataType());
////					function.setReturnType(new FloatDataType());
////					Register register = program.getRegister("AX");
////					Parameter parameter1 =
////						new RegisterParameterImpl(register, "Length", new AsciiDataType(),
////							"My Parameter Comment", 0, SourceType.USER_DEFINED);
////					function.addParameter(parameter1, SourceType.USER_DEFINED);
////					commit = true;
////				}
////				catch (Exception e) {
////					Assert.fail(e.getMessage());
////				}
////				finally {
////					program.endTransaction(txId, commit);
////				}
//			}
//		});
//
//		executeMerge(ASK_USER);
////		chooseRadioButton(MY_BUTTON);
////		chooseVariousOptions(new int[] { INFO_ROW, KEEP_MY });
//		waitForMergeCompletion(5000);
//
////		Namespace externalLibrary =
////			(Namespace) resultProgram.getSymbolTable().getUniqueSymbol("user32.dll",
////				resultProgram.getGlobalNamespace()).getObject();
////		assertNotNull(externalLibrary);
////		Namespace myNamespace =
////			(Namespace) resultProgram.getSymbolTable().getUniqueSymbol("MyNamespace", externalLibrary).getObject();
////		assertNotNull(myNamespace);
////		SymbolTable symtab = resultProgram.getSymbolTable();
////		Symbol apples = symtab.getUniqueSymbol("thunk_oranges", myNamespace);
////		Symbol oranges = symtab.getUniqueSymbol("oranges", myNamespace);
////		assertEquals(SymbolType.FUNCTION, apples.getSymbolType());
////		assertEquals(SymbolType.FUNCTION, oranges.getSymbolType());
////		Function function = (Function) apples.getObject();
////		assertEquals(true, function.isThunk());
////		checkFunctionReturnType(function, new FloatDataType());
////		assertEquals(1, function.getParameterCount());
////		Parameter parameter = function.getParameter(0);
////		assertEquals("Length", parameter.getName());
////		assertEquals("My Parameter Comment", parameter.getComment());
////		checkParameterDataType(parameter, new AsciiDataType());
////		assertTrue(parameter.isRegisterVariable());
//	}

///	public void testExtRefRemoveNoConflict() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//					commit = true;
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//					refs = refMgr.getReferencesFrom(addr(program, "0x10010c0"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//					commit = true;
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
//		assertEquals(0, refs.length);
//
//		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
//		assertEquals(0, refs.length);
//
//		refs = refMgr.getReferencesFrom(addr("0x10010c0"), 0);
//		assertEquals(0, refs.length);
//	}
//
//	public void testExtRefRemoveVsChangePickLatest() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001004"), extLoc.getLibraryName(), "test" + extLoc.getLabel(),
//							extLoc.getAddress(), SourceType.DEFAULT, 0, refs[0].getReferenceType());
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001000"), extLoc.getLibraryName(), "test",
//							extLoc.getAddress(), SourceType.DEFAULT, 0, refs[0].getReferenceType());
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(LATEST_BUTTON);
//		chooseRadioButton(LATEST_BUTTON);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
//		assertEquals(0, refs.length);
//
//		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
//		assertEquals(1, refs.length);
//		ExternalManagerDB extMgr = (ExternalManagerDB)resultProgram.getExternalManager();
//		ExternalLocation extLoc = extMgr.getExtLocation(refs[0].getToAddress());
//		String name = extLoc.getLabel();
//		assertTrue(name.startsWith("test"));
//	}
//
//	public void testExtRefRemoveVsChangePickMy() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001004"), extLoc.getLibraryName(), "test" + extLoc.getLabel(),
//							extLoc.getAddress(), SourceType.DEFAULT, 0, refs[0].getReferenceType());
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001000"), extLoc.getLibraryName(), "test",
//							extLoc.getAddress(), SourceType.DEFAULT, 0, refs[0].getReferenceType());
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					refMgr.delete(refs[0]);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(MY_BUTTON);
//		chooseRadioButton(MY_BUTTON);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
//		assertEquals(1, refs.length);
//		ExternalManagerDB extMgr = (ExternalManagerDB)resultProgram.getExternalManager();
//		ExternalLocation extLoc = extMgr.getExtLocation(refs[0].getToAddress());
//		String name = extLoc.getLabel();
//		assertTrue(name.startsWith("test"));
//
//		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
//		assertEquals(0, refs.length);
//	}
//
//	public void testExtRefChangePickLatest() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001000"), extLoc.getLibraryName(), "testLatest",
//							extLoc.getAddress(), SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001004"), extLoc.getLibraryName(), "getName",
//							extLoc.getAddress(), SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001000"), extLoc.getLibraryName(), "bud",
//							null, SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001004"), extLoc.getLibraryName(), "testMy",
//							extLoc.getAddress(), SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(LATEST_BUTTON);
//		chooseRadioButton(LATEST_BUTTON);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("testLatest", ((ExternalReference)refs[0]).getExternalLocation().getLabel());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//
//		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("getName", ((ExternalReference)refs[0]).getExternalLocation().getLabel());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//	}
//
//	public void testExtRefChangePickMy() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001000"), extLoc.getLibraryName(), "testLatest",
//							extLoc.getAddress(), SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001004"), extLoc.getLibraryName(), "getName",
//							extLoc.getAddress(), SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
//					assertEquals(1, refs.length);
//					ExternalLocation extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001000"), extLoc.getLibraryName(), "bud",
//							null, SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
//					assertEquals(1, refs.length);
//					extLoc = ((ExternalReference)refs[0]).getExternalLocation();
//					refMgr.addExternalReference(
//							addr(program, "0x1001004"), extLoc.getLibraryName(), "testMy",
//							extLoc.getAddress(), SourceType.USER_DEFINED, 0, refs[0].getReferenceType());
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(MY_BUTTON);
//		chooseRadioButton(MY_BUTTON);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("bud", ((ExternalReference)refs[0]).getExternalLocation().getLabel());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//
//		refs = refMgr.getReferencesFrom(addr("01001004"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("testMy", ((ExternalReference)refs[0]).getExternalLocation().getLabel());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//	}
//
//	public void testExtRefAddSameNoConflict() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref  (undefined byte code unit)
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013cc"), "USER32.DLL", "printf",
//							addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013d8"), "ADVAPI32.DLL", "getName",
//							null, SourceType.DEFAULT, -1, RefType.DATA);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013cc"), "USER32.DLL", "printf",
//							addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013d8"), "ADVAPI32.DLL", "getName",
//							null, SourceType.DEFAULT, -1, RefType.DATA);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("USER32.DLL::printf", ((ExternalReference)refs[0]).getExternalLocation().toString());
//		assertEquals("01234567", ((ExternalReference)refs[0]).getExternalLocation().getAddress().toString());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//
//		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
//		assertEquals(1, refs.length);
//		assertEquals("ADVAPI32.DLL::getName", ((ExternalReference)refs[0]).getExternalLocation().toString());
//		assertNull(((ExternalReference)refs[0]).getExternalLocation().getAddress());
//		assertTrue(refs[0].getSource() != SourceType.USER_DEFINED);
//	}
//
//	public void testExtRefAddDiffPickLatest() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref  (undefined byte code unit)
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013cc"), "USER32.DLL", "printf",
//							addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013d8"), "ADVAPI32.DLL", "getName",
//							null, SourceType.DEFAULT, -1, RefType.DATA);
//
//					commit = true;
//				}
//				catch (Exception e) {
//					Assert.fail(e.getMessage());
//				}
//				finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013cc"), "USER32.DLL", "printf",
//							null, SourceType.USER_DEFINED, 0, RefType.DATA);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013d8"), "USER32.DLL", "getName",
//							null, SourceType.USER_DEFINED, -1, RefType.DATA);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(LATEST_BUTTON);
//		chooseRadioButton(LATEST_BUTTON);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("USER32.DLL::printf", ((ExternalReference)refs[0]).getExternalLocation().toString());
//		assertEquals("01234567", ((ExternalReference)refs[0]).getExternalLocation().getAddress().toString());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//
//		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
//		assertEquals(1, refs.length);
//		assertEquals("ADVAPI32.DLL::getName", ((ExternalReference)refs[0]).getExternalLocation().toString());
//		assertNull(((ExternalReference)refs[0]).getExternalLocation().getAddress());
//		assertTrue(refs[0].getSource() != SourceType.USER_DEFINED);
//	}
//
//	public void testExtRefAddDiffPickMy() throws Exception {
//	// External Refs
//	// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
//	// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
//	// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
//	// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
//	// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
//	// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
//	// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
//	// 0100101c: no ref  (undefined byte code unit)
//	// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
//	// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
//	// 010013cc: no ref (has string)
//	// 010013d8: no ref (has string)
//	// 010013f0: no ref (has string)
//
//		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyLatest(ProgramDB program) {
//				int txId = program.startTransaction("Modify Latest Program");
//				boolean commit = false;
//				try {
//					Listing listing = program.getListing();
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					Address addr = addr(program, "0x10013cc");
//					listing.getCodeUnitAt(addr);
//					refs = refMgr.getReferencesFrom(addr, 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013cc"), "USER32.DLL", "printf",
//							addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
//					assertEquals(0, refs.length);
//					refMgr.addExternalReference(
//							addr(program, "0x10013d8"), "ADVAPI32.DLL", "getName",
//							null, SourceType.DEFAULT, -1, RefType.DATA);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//
//			/* (non-Javadoc)
//			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
//			 */
//			public void modifyPrivate(ProgramDB program) {
//				int txId = program.startTransaction("Modify My Program");
//				boolean commit = false;
//				try {
//					ReferenceManager refMgr = program.getReferenceManager();
//					Reference[] refs;
//
//					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
//					assertEquals(0, refs.length);
//					Reference newRef = refMgr.addExternalReference(
//							addr(program, "0x10013cc"), "USER32.DLL", "printf",
//							null, SourceType.USER_DEFINED, 0, RefType.DATA);
//					assertNull(((ExternalReference)newRef).getExternalLocation().getAddress());
//
//					refs = refMgr.getReferencesFrom(addr(program, "010013d8"), 0);
//					assertEquals(0, refs.length);
//					newRef = refMgr.addExternalReference(
//							addr(program, "0x10013d8"), "USER32.DLL", "getName",
//							null, SourceType.USER_DEFINED, -1, RefType.DATA);
//
//					commit = true;
//				} catch (Exception e) {
//					Assert.fail(e.getMessage());
//				} finally {
//					program.endTransaction(txId, commit);
//				}
//			}
//		});
//
//		executeMerge(ASK_USER);
//		chooseRadioButton(MY_BUTTON);
//		chooseRadioButton(MY_BUTTON);
//		waitForMergeCompletion(5000);
//
//		ReferenceManager refMgr = resultProgram.getReferenceManager();
//		Reference[] refs;
//		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
//		assertEquals(1, refs.length);
//		assertEquals("USER32.DLL::printf", ((ExternalReference)refs[0]).getExternalLocation().toString());
//		assertNull(((ExternalReference)refs[0]).getExternalLocation().getAddress());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//
//		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
//		assertEquals(1, refs.length);
//		assertEquals("USER32.DLL::getName", ((ExternalReference)refs[0]).getExternalLocation().toString());
//		assertNull(((ExternalReference)refs[0]).getExternalLocation().getAddress());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);
//	}

	private void changeExternalReferenceLabel(ProgramDB program,
			ExternalReference externalReference, String label, Address extAddress,
			RefType refType) {

		ExternalLocation externalLocation = externalReference.getExternalLocation();
		String libraryName = externalLocation.getLibraryName();
		addExtRefAndName(program, externalReference.getFromAddress(),
			externalReference.getOperandIndex(), libraryName, label, extAddress, refType);
	}

	private boolean addExtRefAndName(Program p, Address fromAddr, int opIndex, String libraryName,
			String label, Address addr, RefType refType) {

		SetExternalRefCmd setExternalRefCmd = new SetExternalRefCmd(fromAddr, opIndex, libraryName,
			label, addr, refType, SourceType.USER_DEFINED);
		return setExternalRefCmd.applyTo(p);

	}

}
