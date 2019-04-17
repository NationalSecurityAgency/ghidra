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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class RefMergerStackTest extends AbstractListingMergeManagerTest {

	// *** NotepadMergeListingTest ***

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
	public RefMergerStackTest() {
		super();
	}

	private void changeStackRefOffset(ProgramDB program, String fromAddr, int opIndex, int offset) {
		Address fromAddress = addr(program, fromAddr);
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] refs = refMgr.getReferencesFrom(addr(program, fromAddr), opIndex);
		assertEquals(1, refs.length);
		refMgr.addStackReference(fromAddress, opIndex, offset, refs[0].getReferenceType(),
			refs[0].getSource());
	}

	private void changeStackRefOffset(ProgramDB program, String fromAddr, int opIndex, int offset,
			SourceType source) {
		Address fromAddress = addr(program, fromAddr);
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] refs = refMgr.getReferencesFrom(addr(program, fromAddr), opIndex);
		assertEquals(1, refs.length);
		refMgr.addStackReference(fromAddress, opIndex, offset, refs[0].getReferenceType(), source);
	}

@Test
    public void testStackRefRemoveNoConflict() throws Exception {
		// Stack Refs
		// 01001af5: op1 to stack offset -0x24a
		// 01001b03: op2 to stack offset -0x24c
		// 01002125: op1 to stack offset -0x10

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
					refs = refMgr.getReferencesFrom(addr(program, "01001af5"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refs = refMgr.getReferencesFrom(addr(program, "0x1001b03"), 1);
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
					refs = refMgr.getReferencesFrom(addr(program, "01001af5"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					refs = refMgr.getReferencesFrom(addr(program, "0x1002125"), 0);
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
		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("01001b03"), 1);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("01002125"), 0);
		assertEquals(0, refs.length);
	}

@Test
    public void testStackRefRemoveVsChangePickLatest() throws Exception {
		// Stack Refs
		// 01001af5: op1 to stack offset -0x24a
		// 01001b03: op2 to stack offset -0x24c
		// 01002125: op1 to stack offset -0x10

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
					Reference[] refs = refMgr.getReferencesFrom(addr(program, "01001af5"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					changeStackRefOffset(program, "0x1001b03", 1, 100, SourceType.USER_DEFINED);
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
					changeStackRefOffset(program, "01001af5", 0, 100);
					Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001b03"), 1);
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
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(0, refs.length);

		refs = refMgr.getReferencesFrom(addr("01001b03"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(100, ((StackReference) refs[0]).getStackOffset());
	}

@Test
    public void testStackRefRemoveVsChangePickMy() throws Exception {
		// Stack Refs
		// 01001af5: op1 to stack offset -0x24a
		// 01001b03: op2 to stack offset -0x24c
		// 01002125: op1 to stack offset -0x10

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
					Reference[] refs = refMgr.getReferencesFrom(addr(program, "01001af5"), 0);
					assertEquals(1, refs.length);
					refMgr.delete(refs[0]);
					changeStackRefOffset(program, "0x1001b03", 1, 100, SourceType.ANALYSIS);
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
					changeStackRefOffset(program, "01001af5", 0, 100);
					Reference[] refs = refMgr.getReferencesFrom(addr(program, "0x1001b03"), 1);
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
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(100, ((StackReference) refs[0]).getStackOffset());

		refs = refMgr.getReferencesFrom(addr("01001b03"), 1);
		assertEquals(0, refs.length);
	}

@Test
    public void testStackRefChangeNoConflict() throws Exception {
		// Stack Refs
		// 01001af5: op1 to stack offset -0x24a
		// 01001b03: op2 to stack offset -0x24c
		// 01002125: op1 to stack offset -0x10

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
					refMgr.addRegisterReference(addr(program, "01001af5"), 0,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
					refMgr.addRegisterReference(addr(program, "0x1001b03"), 1,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
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
					refMgr.addRegisterReference(addr(program, "01001af5"), 0,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
					refMgr.addRegisterReference(addr(program, "01002125"), 0,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
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
		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].isRegisterReference());

		refs = refMgr.getReferencesFrom(addr("01001b03"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0].isRegisterReference());

		refs = refMgr.getReferencesFrom(addr("01002125"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0].isRegisterReference());
	}

@Test
    public void testStackRefChangePickLatest() throws Exception {
		// Stack Refs
		// 01001af5: op1 to stack offset -0x24a
		// 01001b03: op2 to stack offset -0x24c
		// 01002125: op1 to stack offset -0x10

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
					refMgr.addRegisterReference(addr(program, "01001af5"), 0,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
					refMgr.addRegisterReference(addr(program, "0x1001b03"), 1,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
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
					refMgr.addRegisterReference(addr(program, "01001af5"), 0,
						program.getRegister("EBX"), RefType.DATA, SourceType.USER_DEFINED);
					refMgr.addRegisterReference(addr(program, "0x1001b03"), 1,
						program.getRegister("EBX"), RefType.DATA, SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(1, refs.length);
		assertEquals(resultProgram.getRegister("EAX").getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01001b03"), 1);
		assertEquals(1, refs.length);
		assertEquals(resultProgram.getRegister("EAX").getAddress(), refs[0].getToAddress());
	}

@Test
    public void testStackRefChangePickMy() throws Exception {
		// Stack Refs
		// 01001af5: op1 to stack offset -0x24a
		// 01001b03: op2 to stack offset -0x24c
		// 01002125: op1 to stack offset -0x10

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
					refMgr.addRegisterReference(addr(program, "01001af5"), 0,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
					refMgr.addRegisterReference(addr(program, "0x1001b03"), 1,
						program.getRegister("EAX"), RefType.DATA, SourceType.USER_DEFINED);
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
					refMgr.addRegisterReference(addr(program, "01001af5"), 0,
						program.getRegister("EBX"), RefType.DATA, SourceType.USER_DEFINED);
					refMgr.addRegisterReference(addr(program, "0x1001b03"), 1,
						program.getRegister("EBX"), RefType.DATA, SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x1001af5"), 0);
		assertEquals(1, refs.length);
		assertEquals(resultProgram.getRegister("EBX").getAddress(), refs[0].getToAddress());

		refs = refMgr.getReferencesFrom(addr("01001b03"), 1);
		assertEquals(1, refs.length);
		assertEquals(resultProgram.getRegister("EBX").getAddress(), refs[0].getToAddress());
	}

@Test
    public void testStackRefAddSameNoConflict() throws Exception {
		// Stack Refs
		// 01001a55: op1 no ref to stack offset 0x10
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// 01002125: op0 to stack offset -0x10
		// 010024ea: op1 no ref to stack offset 0x10
		// 01002510: op0 no ref to stack offset 0x8
		// 01002a05: op0 no ref to stack offset -0x18

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x08, RefType.DATA,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x08, RefType.DATA,
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
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(1, refs.length);
	}

@Test
    public void testStackRefAddDiffPickLatest() throws Exception {
		// Stack Refs
		// 01001a55: op1 no ref to stack offset 0x10
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// 01002125: op0 to stack offset -0x10
		// 010024ea: op1 no ref to stack offset 0x10
		// 01002510: op0 no ref to stack offset 0x8
		// 01002a05: op0 no ref to stack offset -0x18

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x08, RefType.DATA,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x14, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x04, RefType.DATA,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(1, refs.length);
	}

@Test
    public void testStackRefAddDiffPickMy() throws Exception {
		// Stack Refs
		// 01001a55: op1 no ref to stack offset 0x10
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// 01002125: op0 to stack offset -0x10
		// 010024ea: op1 no ref to stack offset 0x10
		// 01002510: op0 no ref to stack offset 0x8
		// 01002a05: op0 no ref to stack offset -0x18

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x08, RefType.DATA,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x14, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x04, RefType.DATA,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(1, refs.length);
	}

}
