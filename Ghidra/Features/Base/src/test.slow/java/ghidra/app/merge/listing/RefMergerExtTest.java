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
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class RefMergerExtTest extends AbstractExternalMergerTest {

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

	/**
	 *
	 * @param arg0
	 */
	public RefMergerExtTest() {
		super();
	}

	@Test
	public void testExtRefRemoveNoConflict() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs;
				refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
				assertEquals(1, refs.length);
				refMgr.delete(refs[0]);
				refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
				assertEquals(1, refs.length);
				refMgr.delete(refs[0]);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] refs;
				refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
				assertEquals(1, refs.length);
				refMgr.delete(refs[0]);
				refs = refMgr.getReferencesFrom(addr(program, "0x10010c0"), 0);
				assertEquals(1, refs.length);
				refMgr.delete(refs[0]);
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("0x10010c0"), 0);
		assertEquals(0, refs.length);
	}

	@Test
	public void testExtRefRemoveVsChangePickLatest() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					// Remove the ref.
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					// Change the ref.
					ExternalLocation extLoc = ((ExternalReference) refs[0]).getExternalLocation();
					refMgr.addExternalReference(addr(program, "0x1001004"), extLoc.getLibraryName(),
						"test" + extLoc.getLabel(), extLoc.getAddress(), SourceType.USER_DEFINED, 0,
						RefType.COMPUTED_CALL);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					// Change the ref.
					ExternalLocation extLoc = ((ExternalReference) refs[0]).getExternalLocation();
					refMgr.addExternalReference(addr(program, "0x1001000"), extLoc.getLibraryName(),
						"test", extLoc.getAddress(), SourceType.USER_DEFINED, 0,
						refs[0].getReferenceType());

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					// Remove the ref.
					refMgr.delete(refs[0]);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
		assertEquals(1, refs.length);
		assertEquals(RefType.COMPUTED_CALL, refs[0].getReferenceType());
		ExternalManagerDB extMgr = (ExternalManagerDB) resultProgram.getExternalManager();
		ExternalLocation extLoc = extMgr.getExtLocation(refs[0].getToAddress());
		String name = extLoc.getLabel();
		assertTrue(name.startsWith("test"));
	}

	@Test
	public void testExtRefRemoveVsChangePickMy() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					// Remove the ref.
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					// Change the ref.
					ExternalLocation extLoc = ((ExternalReference) refs[0]).getExternalLocation();
					refMgr.addExternalReference(addr(program, "0x1001004"), extLoc.getLibraryName(),
						"test" + extLoc.getLabel(), extLoc.getAddress(), SourceType.IMPORTED, 0,
						refs[0].getReferenceType());
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

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					// Change the ref.
					ExternalLocation extLoc = ((ExternalReference) refs[0]).getExternalLocation();
					refMgr.addExternalReference(addr(program, "0x1001000"), extLoc.getLibraryName(),
						"test", extLoc.getAddress(), SourceType.ANALYSIS, 0,
						refs[0].getReferenceType());

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					// Remove the ref.
					refMgr.delete(refs[0]);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
		assertEquals(1, refs.length);
		ExternalManagerDB extMgr = (ExternalManagerDB) resultProgram.getExternalManager();
		ExternalLocation extLoc = extMgr.getExtLocation(refs[0].getToAddress());
		String name = extLoc.getLabel();
		assertTrue(name.startsWith("test"));

		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
		assertEquals(0, refs.length);
	}

	@Test
	public void testExtRefChangePickLatest() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalLabel(program, new String[] { "Library", "Namespace", "Label1" },
						addr(program, "77db1020"), SourceType.ANALYSIS);

					createExternalLabel(program, new String[] { "Library", "Namespace", "Label2" },
						addr(program, "77db1130"), SourceType.ANALYSIS);

					createExternalLabel(program, new String[] { "Library", "Namespace", "Foo" },
						addr(program, "77db1020"), SourceType.ANALYSIS);

					createExternalLabel(program, new String[] { "Library", "Namespace", "Bar" },
						addr(program, "77db1130"), SourceType.ANALYSIS);
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

					ExternalLocation extLoc1 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Label1" });
					ExternalLocation extLoc2 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Label2" });

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					Address fromAddress = refs[0].getFromAddress();
					int operandIndex = refs[0].getOperandIndex();
					RefType referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc1,
						extLoc1.getSource(), referenceType);

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					fromAddress = refs[0].getFromAddress();
					operandIndex = refs[0].getOperandIndex();
					referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc2,
						extLoc2.getSource(), referenceType);
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

					ExternalLocation extLoc1 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Foo" });
					ExternalLocation extLoc2 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Bar" });

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					Address fromAddress = refs[0].getFromAddress();
					int operandIndex = refs[0].getOperandIndex();
					RefType referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc1,
						extLoc1.getSource(), referenceType);

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					fromAddress = refs[0].getFromAddress();
					operandIndex = refs[0].getOperandIndex();
					referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc2,
						extLoc2.getSource(), referenceType);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Reference Conflict", LATEST_BUTTON);
		chooseRadioButton("Resolve Reference Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
		assertEquals(1, refs.length);
		assertEquals("Label1", ((ExternalReference) refs[0]).getExternalLocation().getLabel());
		assertTrue(refs[0].getSource() == SourceType.ANALYSIS);

		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
		assertEquals(1, refs.length);
		assertEquals("Label2", ((ExternalReference) refs[0]).getExternalLocation().getLabel());
		assertTrue(refs[0].getSource() == SourceType.ANALYSIS);
	}

	@Test
	public void testExtRefChangePickMy() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					createExternalLabel(program, new String[] { "Library", "Namespace", "Label1" },
						addr(program, "77db1020"), SourceType.ANALYSIS);

					createExternalLabel(program, new String[] { "Library", "Namespace", "Label2" },
						addr(program, "77db1130"), SourceType.ANALYSIS);

					createExternalLabel(program, new String[] { "Library", "Namespace", "Foo" },
						addr(program, "77db1020"), SourceType.ANALYSIS);

					createExternalLabel(program, new String[] { "Library", "Namespace", "Bar" },
						addr(program, "77db1130"), SourceType.ANALYSIS);
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

					ExternalLocation extLoc1 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Label1" });
					ExternalLocation extLoc2 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Label2" });

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					Address fromAddress = refs[0].getFromAddress();
					int operandIndex = refs[0].getOperandIndex();
					RefType referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc1,
						extLoc1.getSource(), referenceType);

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					fromAddress = refs[0].getFromAddress();
					operandIndex = refs[0].getOperandIndex();
					referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc2,
						extLoc2.getSource(), referenceType);
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

					ExternalLocation extLoc1 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Foo" });
					ExternalLocation extLoc2 = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Bar" });

					refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					Address fromAddress = refs[0].getFromAddress();
					int operandIndex = refs[0].getOperandIndex();
					RefType referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc1,
						extLoc1.getSource(), referenceType);

					refs = refMgr.getReferencesFrom(addr(program, "0x1001004"), 0);
					assertEquals(1, refs.length);
					fromAddress = refs[0].getFromAddress();
					operandIndex = refs[0].getOperandIndex();
					referenceType = refs[0].getReferenceType();
					refMgr.delete(refs[0]);
					refMgr.addExternalReference(fromAddress, operandIndex, extLoc2,
						extLoc2.getSource(), referenceType);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Reference Conflict", MY_BUTTON);
		chooseRadioButton("Resolve Reference Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
		assertEquals(1, refs.length);
		assertEquals("Foo", ((ExternalReference) refs[0]).getExternalLocation().getLabel());
		assertTrue(refs[0].getSource() == SourceType.ANALYSIS);

		refs = refMgr.getReferencesFrom(addr("0x1001004"), 0);
		assertEquals(1, refs.length);
		assertEquals("Bar", ((ExternalReference) refs[0]).getExternalLocation().getLabel());
		assertTrue(refs[0].getSource() == SourceType.ANALYSIS);
	}

	@Test
	public void testExtRefChangeRefTypeConflictPickMy() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) {
				try {
					ExternalLocation extLoc = createExternalLabel(program,
						new String[] { "Library", "Namespace", "Label1" },
						addr(program, "77db1020"), SourceType.ANALYSIS);

					ReferenceManager refMgr = program.getReferenceManager();

					Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001000"), 0);
					assertEquals(1, refs.length);
					Address fromAddress = refs[0].getFromAddress();
					int operandIndex = refs[0].getOperandIndex();
					refMgr.delete(refs[0]);

					refMgr.addExternalReference(fromAddress, operandIndex, extLoc,
						extLoc.getSource(), RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();

					ExternalLocation extLoc = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Label1" });

					refMgr.addExternalReference(addr(program, "0x1001000"), 0, extLoc,
						extLoc.getSource(), RefType.COMPUTED_CALL);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();

					ExternalLocation extLoc = getExternalLocation(program,
						new String[] { "Library", "Namespace", "Label1" });

					refMgr.addExternalReference(addr(program, "0x1001000"), 0, extLoc,
						extLoc.getSource(), RefType.COMPUTED_CALL_TERMINATOR);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Reference Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001000"), 0);
		assertEquals(1, refs.length);
		assertEquals(RefType.COMPUTED_CALL_TERMINATOR, refs[0].getReferenceType());
		assertEquals("Label1", ((ExternalReference) refs[0]).getExternalLocation().getLabel());
		assertTrue(refs[0].getSource() == SourceType.ANALYSIS);
	}

	@Test
	public void testExtRefAddSameNoConflict() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL",
						"getName", null, SourceType.IMPORTED, -1, RefType.DATA);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL",
						"getName", null, SourceType.IMPORTED, -1, RefType.DATA);
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
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("ADVAPI32.DLL::getName",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertTrue(refs[0].getSource() != SourceType.USER_DEFINED);
	}

	@Test
	public void testExtRefAddDiffPickLatest() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db82ac"), SourceType.DEFAULT, -1, RefType.DATA);
					// There is already an external ref called "ADVAPI32.DLL::RegOpenKeyExA" for 77db82ac.
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("ADVAPI32.DLL::RegOpenKeyExA",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals(addr(resultProgram, "77db82ac"),
			((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertEquals(SourceType.DEFAULT, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiffPickMy() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db82ac"), SourceType.DEFAULT, -1, RefType.DATA);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Reference Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::getName",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
//		assertEquals(SourceType.USER_DEFINED, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiff2PickLatest() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db2233"), SourceType.DEFAULT, -1, RefType.DATA);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		// The two external locations are not in conflict and can both exist
		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("ADVAPI32.DLL::EXT_77db2233",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals(addr(resultProgram, "77db2233"),
			((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertEquals(SourceType.DEFAULT, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiff2PickMy() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db2233"), SourceType.DEFAULT, -1, RefType.DATA);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Reference Conflict", MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::getName",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
//		assertEquals(SourceType.USER_DEFINED, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiff2KeepBothLatestRef() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db2233"), SourceType.DEFAULT, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation externalLocation1 =
					getExternalLocation(program, new String[] { "USER32.DLL", "printf" });
				assertNotNull(externalLocation1);
				ExternalLocation externalLocation2 =
					getExternalLocation(program, new String[] { "ADVAPI32.DLL", "EXT_77db2233" });
				assertNotNull(externalLocation2);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				ExternalLocation externalLocation2 =
					getExternalLocation(program, new String[] { "USER32.DLL", "getName" });
				assertNotNull(externalLocation2);
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Reference Conflict", LATEST_BUTTON);// Since kept both, now choose reference conflict.
		waitForMergeCompletion();

		ExternalLocation externalLocation1 =
			getExternalLocation(resultProgram, new String[] { "ADVAPI32.DLL", "EXT_77db2233" });
		assertNotNull(externalLocation1);
		ExternalLocation externalLocation2 =
			getExternalLocation(resultProgram, new String[] { "USER32.DLL", "getName" });
		assertNotNull(externalLocation2);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("ADVAPI32.DLL::EXT_77db2233",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db2233",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
//		assertEquals(SourceType.USER_DEFINED, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiff2KeepBothMyRef() throws Exception {
		// External Refs
		// 01001000: op1 to ADVAPI32.DLL IsTextUnicode 77dc4f85
		// 01001004: op1 to ADVAPI32.DLL RegCreateKeyW 77db90b0
		// 01001008: op1 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op1 to ADVAPI32.DLL RegSetValueExW 77db9348
		// 01001010: op1 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
		// 01001014: op1 to ADVAPI32.DLL RegQueryValueExA 77db858e
		// 01001018: op1 to ADVAPI32.DLL RegCloseKey 77db7d4d
		// 0100101c: no ref  (undefined byte code unit)
		// 010010c0: op1 to KERNEL32.DLL LocalFree 77e9499c
		// 010010c4: op1 to KERNEL32.DLL GetProcAddress 77e9564b
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)
		// 010013f0: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db2233"), SourceType.DEFAULT, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}

				ExternalLocation externalLocation1 =
					getExternalLocation(program, new String[] { "USER32.DLL", "printf" });
				assertNotNull(externalLocation1);
				ExternalLocation externalLocation2 =
					getExternalLocation(program, new String[] { "ADVAPI32.DLL", "EXT_77db2233" });
				assertNotNull(externalLocation2);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
				ExternalLocation externalLocation2 =
					getExternalLocation(program, new String[] { "USER32.DLL", "getName" });
				assertNotNull(externalLocation2);
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton("Resolve Reference Conflict", MY_BUTTON);// Since kept both, now choose reference conflict.
		waitForMergeCompletion();

		ExternalLocation externalLocation1 =
			getExternalLocation(resultProgram, new String[] { "ADVAPI32.DLL", "EXT_77db2233" });
		assertNotNull(externalLocation1);
		ExternalLocation externalLocation2 =
			getExternalLocation(resultProgram, new String[] { "USER32.DLL", "getName" });
		assertNotNull(externalLocation2);

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
//		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::getName",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
//		assertEquals(SourceType.USER_DEFINED, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiff2MergeBothKeepVarious1() throws Exception {
		// External Refs
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db2233"), SourceType.DEFAULT, -1, RefType.DATA);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		chooseButtonAndApply("Resolve Reference Conflict", MY_BUTTON);
		// NOTE: Locations are not considered conflicts since both get added
//		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
//			new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY });// Namespace, Name
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::getName",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertNull(((ExternalReference) refs[0]).getExternalLocation().getAddress());
		assertEquals(SourceType.USER_DEFINED, refs[0].getSource());
	}

	@Test
	public void testExtRefAddDiff2MergeBothKeepVarious2() throws Exception {
		// External Refs
		// 010013cc: no ref (has string)
		// 010013d8: no ref (has string)

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "ADVAPI32.DLL", null,
						addr(program, "77db2233"), SourceType.DEFAULT, -1, RefType.DATA);
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10013cc"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013cc"), "USER32.DLL", "printf",
						null, SourceType.USER_DEFINED, 0, RefType.DATA);

					refs = refMgr.getReferencesFrom(addr(program, "0x10013d8"), 0);
					assertEquals(0, refs.length);
					refMgr.addExternalReference(addr(program, "0x10013d8"), "USER32.DLL", "getName",
						null, SourceType.USER_DEFINED, -1, RefType.DATA);
				}
				catch (Exception e) {
					Assert.fail(e.getMessage());
				}
			}
		});

		executeMerge(ASK_USER);
		// NOTE: Locations are not considered conflicts since both get added
		chooseButtonAndApply("Resolve Reference Conflict", LATEST_BUTTON);
//		chooseVariousOptionsForConflictType("Resolve External Detail Conflict",
//			new int[] { INFO_ROW, KEEP_MY, KEEP_LATEST });// Namespace, Name
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10013cc"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("0x10013d8"), -1);
		assertEquals(1, refs.length);
		assertEquals("ADVAPI32.DLL::EXT_77db2233",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("77db2233",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertEquals(SourceType.DEFAULT, refs[0].getSource());
	}

}
