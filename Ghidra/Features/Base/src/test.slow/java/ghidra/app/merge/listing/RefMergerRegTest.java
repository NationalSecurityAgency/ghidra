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

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the merge of the versioned program's listing.
 */
public class RefMergerRegTest extends AbstractListingMergeManagerTest {

	// *** NotepadMergeListingTest ***

	// External Refs
	// 01001000: op0 to ADVAPI32.DLL IsTextUnicode 77dc4f85
	// 01001004: op0 to ADVAPI32.DLL RegCreateKeyW 77db90b0
	// 01001008: op0 to ADVAPI32.DLL RegQueryValueExW 77db8078
	// 0100100c: op0 to ADVAPI32.DLL RegSetValueExW 77db9348
	// 01001010: op0 to ADVAPI32.DLL RegOpenKeyExA 77db82ac
	// 01001014: op0 to ADVAPI32.DLL RegQueryValueExA 77db858e
	// 01001018: op0 to ADVAPI32.DLL RegCloseKey 77db7d4d
	// 0100101c: no ref
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

	// Register Refs
	// 0x10018a6: op0 has reg ref to ESI.
	// 0x100295a: op1 has reg ref to CX.
	// 0x1002cf5: op0 has reg ref to EDI; op1 has reg ref to EAX.
	// 0x10033fe: op0 both have reg ref to EDI.

	public RefMergerRegTest() {
		super();
	}

@Test
    public void testRegRefRemoveNoConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

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
					refs = refMgr.getReferencesFrom(addr(program, "010018a6"), 0); // Remove ref only here
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Remove different refs
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Remove same refs
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					commit = true;
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
					refs = refMgr.getReferencesFrom(addr(program, "0100295a"), 1); // Remove ref only here
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 0); // Remove different refs
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Remove same refs
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("0100295a"), 1);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 0);
		assertEquals(0, refs.length);
		refs = refMgr.getReferencesFrom(addr("01002d0b"), 1);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("010033fe"), 0);
		assertEquals(0, refs.length);
	}

@Test
    public void testRegRefRemoveVsChangeNoConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

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

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.addStackReference(addr(program, "0x10018a6"), 0, -0x4, RefType.WRITE,
						SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.addStackReference(addr(program, "0x1002d0b"), 1, -0x8, RefType.DATA,
						SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					commit = true;
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.addStackReference(addr(program, "0x100295a"), 1, -0x8, RefType.READ,
						SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.addStackReference(addr(program, "0x10033fe"), 0, -0xc, RefType.DATA,
						SourceType.DEFAULT);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());

		refs = refMgr.getReferencesFrom(addr("0100295a"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());

		refs = refMgr.getReferencesFrom(addr("010033fe"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());
	}

@Test
    public void testRegRefRemoveVsChangeConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

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

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					commit = true;
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

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.READ);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		ProgramContext context = resultProgram.getProgramContext();
		Register ediReg = context.getRegister("EDI");
		Register esiReg = context.getRegister("ESI");

		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(esiReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("0100295a"), 1);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 1);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("010033fe"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());
	}

@Test
    public void testChangeRegRefNoConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register eaxReg = context.getRegister("EAX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1002d0b"), 1, eaxReg,
						RefType.DATA, SourceType.DEFAULT);

					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register eaxReg = context.getRegister("EAX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Change Ref register
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x100295a"), 1, eaxReg,
						RefType.DATA, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Change Ref Type
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.READ);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		ProgramContext context = resultProgram.getProgramContext();
		Register eaxReg = context.getRegister("EAX");
		Register ediReg = context.getRegister("EDI");
		Register esiReg = context.getRegister("ESI");

		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(esiReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("0100295a"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.DEFAULT);
		assertEquals(eaxReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.DEFAULT);
		assertEquals(eaxReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("010033fe"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());
	}

@Test
    public void testChangeToSameRegRefNoConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register eaxReg = context.getRegister("EAX");
					Register ecxReg = context.getRegister("ECX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1002d0b"), 1, eaxReg,
						RefType.DATA, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x100295a"), 1, ecxReg,
						RefType.DATA, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Remove ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.READ);

					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register eaxReg = context.getRegister("EAX");
					Register ecxReg = context.getRegister("ECX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0); // Change ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1); // Change ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1002d0b"), 1, eaxReg,
						RefType.DATA, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1); // Remove ref
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x100295a"), 1, ecxReg,
						RefType.DATA, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0); // Remove ref
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.READ);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		ProgramContext context = resultProgram.getProgramContext();
		Register cxReg = context.getRegister("CX");
		Register eaxReg = context.getRegister("EAX");
		Register ediReg = context.getRegister("EDI");
		Register esiReg = context.getRegister("ESI");

		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(esiReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("0100295a"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(cxReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(eaxReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("010033fe"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());
	}

@Test
    public void testChangeRegRefConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register eaxReg = context.getRegister("EAX");
					Register ediReg = context.getRegister("EDI");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0);
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1);
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1002d0b"), 1, eaxReg,
						RefType.DATA, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x10033fe"), 0, ediReg,
						RefType.DATA, SourceType.DEFAULT);

					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register ecxReg = context.getRegister("ECX");
					Register esiReg = context.getRegister("ESI");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x10018a6"), 0, esiReg,
						RefType.WRITE, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x100295a"), 1);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x100295a"), 1, ecxReg,
						RefType.WRITE, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d0b"), 1);
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.WRITE);

					refs = refMgr.getReferencesFrom(addr(program, "0x10033fe"), 0);
					assertEquals(1, refs.length);
					refMgr.updateRefType(refs[0], RefType.READ);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
// For now we no longer want to detect source type differences since they can't be changed anyway.
//		chooseRadioButton(LATEST_BUTTON_NAME);
//		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
//		chooseRadioButton(LATEST_BUTTON_NAME);
//		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		ProgramContext context = resultProgram.getProgramContext();
		Register cxReg = context.getRegister("CX");
		Register eaxReg = context.getRegister("EAX");
		Register ediReg = context.getRegister("EDI");
		Register esiReg = context.getRegister("ESI");

		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(esiReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("0100295a"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(cxReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01002d0b"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(eaxReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("010033fe"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
		assertEquals(ediReg.getAddress(), refs[0].getToAddress());
	}

@Test
    public void testChangeToRegRefNoConflict() throws Exception {
		// Stack Refs
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// Memory Refs
		// 01001aec: op1 to 01001398 AddrTable010080c0Element36 DATA primary
		// 01001b5f: op0 to 010061e3 FUN_010061e3 UNCONDITIONAL_CALL primary
		// External Refs
		// 01001008: op0 to ADVAPI32.DLL RegQueryValueExW 77db8078
		// 0100100c: op0 to ADVAPI32.DLL RegSetValueExW 77db9348
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register ebpReg = context.getRegister("EBP");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					// Change stack ref to reg ref
					// 01001af5: op0 to stack offset -0x24a
					refs = refMgr.getReferencesFrom(addr(program, "0x1001af5"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1001af5"), 0, ebpReg,
						RefType.DATA, SourceType.IMPORTED);

					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register ebpReg = context.getRegister("EBP");
					Register axReg = context.getRegister("AX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					// Change stack ref to reg ref
					// 01001b03: op1 to stack offset -0x24c
					refs = refMgr.getReferencesFrom(addr(program, "0x1001b03"), 1);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1001b03"), 1, ebpReg,
						RefType.DATA, SourceType.IMPORTED);

					// Change mem ref to a reg ref
					// 01001aec: op1 to 01001398 AddrTable010080c0Element36 DATA primary
					refs = refMgr.getReferencesFrom(addr(program, "0x1001aec"), 1);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addRegisterReference(addr(program, "0x1001aec"), 1, axReg, RefType.DATA,
						SourceType.ANALYSIS);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		ProgramContext context = resultProgram.getProgramContext();
		Register ebpReg = context.getRegister("EBP");
		Register axReg = context.getRegister("AX");

		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.IMPORTED);
		assertEquals(ebpReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("0x1001b03"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.IMPORTED);
		assertEquals(ebpReg.getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("0x1001aec"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.ANALYSIS);
		assertEquals(axReg.getAddress(), refs[0].getToAddress());

	}

@Test
    public void testChangeFromRegRefConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

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

					// Change reg ref to mem ref
					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refMgr.addMemoryReference(addr(program, "0x10018a6"),
						addr(program, "0x10018ae"), RefType.COMPUTED_JUMP, SourceType.DEFAULT, 0);

					commit = true;
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

					// Change reg ref to mem ref
					refs = refMgr.getReferencesFrom(addr(program, "0x10018a6"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					try {
						refMgr.addExternalReference(addr(program, "0x10018a6"), "USER32.DLL",
							"printf", addr(program, "0x01234567"), SourceType.USER_DEFINED, 0,
							RefType.DATA);
					}
					catch (DuplicateNameException e) {
						Assert.fail(e.getMessage());
					}
					catch (InvalidInputException e) {
						Assert.fail(e.getMessage());
					}

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;

		refs = refMgr.getReferencesFrom(addr("0x10018a6"), 0);
		assertEquals(1, refs.length);
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].getSource() == SourceType.USER_DEFINED);

	}

@Test
    public void testRegRefAddNoConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register esiReg = context.getRegister("ESI");
					Register eaxReg = context.getRegister("EAX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018cd"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x10018cd"), 0, esiReg,
						RefType.READ, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d18"), 1);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002d18"), 1, eaxReg,
						RefType.READ, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1003409"), 0);
					assertEquals(0, refs.length);
					refMgr.addStackReference(addr(program, "0x1003409"), 0, -0x4, RefType.READ,
						SourceType.USER_DEFINED);
					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register cxReg = context.getRegister("CX");
					Register eaxReg = context.getRegister("EAX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x1002965"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002965"), 0, cxReg,
						RefType.WRITE, SourceType.USER_DEFINED);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d18"), 1);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002d18"), 1, eaxReg,
						RefType.READ, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1003404"), 0);
					assertEquals(0, refs.length);
					refMgr.addStackReference(addr(program, "0x1003404"), 0, -0x4, RefType.WRITE,
						SourceType.USER_DEFINED);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10018cd"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01002965"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01002d18"), 0);
		assertEquals(0, refs.length);
		refs = refMgr.getReferencesFrom(addr("01002d18"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01003404"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01003409"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
	}

@Test
    public void testRegRefAddConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register esiReg = context.getRegister("ESI");
					Register cxReg = context.getRegister("CX");
					Register eaxReg = context.getRegister("EAX");
					Register ediReg = context.getRegister("EDI");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018cd"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x10018cd"), 0, esiReg,
						RefType.READ, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002965"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002965"), 0, cxReg, RefType.READ,
						SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d18"), 1);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002d18"), 1, eaxReg,
						RefType.READ, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1003409"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1003409"), 0, ediReg,
						RefType.READ, SourceType.DEFAULT);

					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register esiReg = context.getRegister("ESI");
					Register cxReg = context.getRegister("CX");
					Register eaxReg = context.getRegister("EAX");
					Register ediReg = context.getRegister("EDI");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018cd"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x10018cd"), 0, esiReg,
						RefType.WRITE, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002965"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002965"), 0, cxReg,
						RefType.WRITE, SourceType.DEFAULT);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d18"), 1);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1002d18"), 1, eaxReg,
						RefType.DATA, SourceType.USER_DEFINED);

					refs = refMgr.getReferencesFrom(addr(program, "0x1003409"), 0);
					assertEquals(0, refs.length);
					refMgr.addRegisterReference(addr(program, "0x1003409"), 0, ediReg,
						RefType.DATA, SourceType.USER_DEFINED);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10018cd"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01002965"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.WRITE, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01002d18"), 0);
		assertEquals(0, refs.length);
		refs = refMgr.getReferencesFrom(addr("01002d18"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01003409"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
	}

@Test
    public void testRegRefAddNonRegConflict() throws Exception {
		// Register Refs
		// 0x10018a6: op0 has reg ref to ESI.
		// 0x100295a: op1 has reg ref to CX.
		// 0x1002d0b: op0 has reg ref to EDI; op1 has reg ref to EAX.
		// 0x10033fe: op0 both have reg ref to EDI.

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ProgramContext context = program.getProgramContext();
					Register esiReg = context.getRegister("ESI");
					Register cxReg = context.getRegister("CX");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;
					Reference newRef;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018cd"), 0);
					assertEquals(0, refs.length);
					newRef =
						refMgr.addRegisterReference(addr(program, "0x10018cd"), 0, esiReg,
							RefType.READ, SourceType.DEFAULT);
					assertNotNull(newRef);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002965"), 0);
					assertEquals(0, refs.length);
					newRef =
						refMgr.addRegisterReference(addr(program, "0x1002965"), 0, cxReg,
							RefType.READ, SourceType.DEFAULT);
					assertNotNull(newRef);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d18"), 1);
					assertEquals(0, refs.length);
					newRef =
						refMgr.addStackReference(addr(program, "0x1002d18"), 1, -0x8, RefType.READ,
							SourceType.DEFAULT);
					assertNotNull(newRef);

					refs = refMgr.getReferencesFrom(addr(program, "0x1003409"), 0);
					assertEquals(0, refs.length);
//					newRef = refMgr.addStackReference(addr(program, "0x1003409"), 0, -0x8, RefType.READ, false);
					newRef =
						refMgr.addMemoryReference(addr(program, "0x1003409"),
							addr(program, "0x1001000"), RefType.READ, SourceType.DEFAULT, 0);
					assertNotNull(newRef);

					commit = true;
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
					ProgramContext context = program.getProgramContext();
					Register eaxReg = context.getRegister("EAX");
					Register ediReg = context.getRegister("EDI");
					ReferenceManager refMgr = program.getReferenceManager();
					Reference[] refs;
					Reference newRef;

					refs = refMgr.getReferencesFrom(addr(program, "0x10018cd"), 0);
					assertEquals(0, refs.length);
					newRef =
						refMgr.addStackReference(addr(program, "0x10018cd"), 0, -0x8, RefType.READ,
							SourceType.DEFAULT);
					assertNotNull(newRef);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002965"), 0);
					assertEquals(0, refs.length);
//					newRef = refMgr.addStackReference(addr(program, "0x1002965"), 0, -0x8, RefType.READ, false);
					newRef =
						refMgr.addMemoryReference(addr(program, "0x1002965"),
							addr(program, "0x10018cf"), RefType.CONDITIONAL_JUMP,
							SourceType.DEFAULT, 0);
					assertNotNull(newRef);

					refs = refMgr.getReferencesFrom(addr(program, "0x1002d18"), 1);
					assertEquals(0, refs.length);
					newRef =
						refMgr.addRegisterReference(addr(program, "0x1002d18"), 1, eaxReg,
							RefType.READ, SourceType.USER_DEFINED);
					assertNotNull(newRef);

					refs = refMgr.getReferencesFrom(addr(program, "0x1003409"), 0);
					assertEquals(0, refs.length);
					newRef =
						refMgr.addRegisterReference(addr(program, "0x1003409"), 0, ediReg,
							RefType.READ, SourceType.USER_DEFINED);
					assertNotNull(newRef);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		chooseRadioButton(LATEST_BUTTON_NAME);
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10018cd"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01002965"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isMemoryAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01002d18"), 0);
		assertEquals(0, refs.length);
		refs = refMgr.getReferencesFrom(addr("01002d18"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isStackAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(false, refs[0].getSource() == SourceType.USER_DEFINED);

		refs = refMgr.getReferencesFrom(addr("01003409"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].getToAddress().isRegisterAddress());
		assertEquals(RefType.READ, refs[0].getReferenceType());
		assertEquals(true, refs[0].getSource() == SourceType.USER_DEFINED);
	}

}
