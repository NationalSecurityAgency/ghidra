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

import org.junit.Test;

import ghidra.program.database.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class RefMergerMemTest extends AbstractListingMergeManagerTest {

	// *** NotepadMergeListingTest ***

	// Mem Refs
	// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
	// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary
	// 01001aec: op1 to 01001398 AddrTable010080c0Element36 DATA primary
	// 01001b5f: op0 to 010061e3 FUN_010061e3 UNCONDITIONAL_CALL primary

	@Test
	public void testMemRefRemoveNoConflict() throws Exception {
		// Mem Refs
		// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
		// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary
		// 01001aec: op1 to 01001398 AddrTable010080c0Element36 DATA primary
		// 01001b5f: op0 to 010061e3 FUN_010061e3 UNCONDITIONAL_CALL primary

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
					Reference ref;
					ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
					refMgr.delete(ref);
					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
					refMgr.delete(ref);
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
					Reference ref;
					ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
					refMgr.delete(ref);
					ref = refMgr.getReference(addr(program, "0x1001aec"),
						addr(program, "0x1001398"), 1);
					refMgr.delete(ref);
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
		Reference ref;
		ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNull(ref);

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNull(ref);

		ref = refMgr.getReference(addr("0x1001aec"), addr("0x1001398"), 1);
		assertNull(ref);
	}

	@Test
	public void testMemRefRemoveVsChangePickLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// Mem Refs
			// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
			// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
					refMgr.delete(ref);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

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
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
					refMgr.delete(ref);

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
		Reference ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNull(ref);

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNotNull(ref);
		assertEquals(RefType.DATA_IND, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefRemoveVsChangePickMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// Mem Refs
			// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
			// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
					refMgr.delete(ref);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

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
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
					refMgr.delete(ref);

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
		Reference ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNotNull(ref);
		assertEquals(RefType.DATA_IND, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNull(ref);
	}

	@Test
	public void testMemRefChangePickLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// Mem Refs
			// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
			// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.READ_WRITE);
					assertEquals(RefType.READ_WRITE, ref.getReferenceType());

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.WRITE);
					assertEquals(RefType.WRITE, ref.getReferenceType());

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
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.WRITE);
					assertEquals(RefType.WRITE, ref.getReferenceType());

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.READ_WRITE);
					assertEquals(RefType.READ_WRITE, ref.getReferenceType());

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
		Reference ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNotNull(ref);
		assertEquals(RefType.READ_WRITE, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNotNull(ref);
		assertEquals(RefType.WRITE, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefChangePickMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// Mem Refs
			// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
			// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.READ_WRITE);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.WRITE);

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
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.WRITE);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.READ_WRITE);

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
		Reference ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNotNull(ref);
		assertEquals(RefType.WRITE, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNotNull(ref);
		assertEquals(RefType.READ_WRITE, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefAddSameNoConflict() throws Exception {
		// Add mnemonic ref from 1002eaf to 1002ee2 CONDITIONAL_JUMP primary user_defined

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);

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
		Reference ref = refMgr.getReference(addr("0x1002eaf"), addr("0x1002ee2"), -1);
		assertNotNull(ref);
		assertEquals(RefType.CONDITIONAL_JUMP, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefAddDiffNoConflict() throws Exception {
		// Add mnemonic mem ref from 1002eaf to 1002ee2 CONDITIONAL_JUMP primary user_defined
		// Add op1 mem ref from 1002f3e to 1002f49 DATA non-primary user_defined
		// Add op0 mem ref from 1002f73 to 00000064 DATA primary user_defined

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
					Reference ref = refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.setPrimary(ref, false);

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
		Reference ref = refMgr.getReference(addr("0x1002eaf"), addr("0x1002ee2"), -1);
		assertNotNull(ref);
		assertEquals(RefType.CONDITIONAL_JUMP, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f3e"), addr("0x1002f49"), 1);
		assertNotNull(ref);
		assertEquals(RefType.DATA, ref.getReferenceType());
		assertTrue(!ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f73"), addr("0x00000064"), 0);
		assertNotNull(ref);
		assertEquals(RefType.DATA, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefAddDiffPickLatest() throws Exception {
		// Add mnemonic mem ref from 1002eaf to 1002ee2 CONDITIONAL_JUMP primary user_defined
		// Add op1 mem ref from 1002f3e to 1002f49 DATA non-primary user_defined
		// Add op0 mem ref from 1002f73 to 00000064 DATA primary user_defined

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
					Reference ref;
					ref = refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.WRITE, SourceType.USER_DEFINED, -1);
					ref = refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.setPrimary(ref, false);
					ref = refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.READ, SourceType.USER_DEFINED, 0);

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
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x1002eaf"), addr("0x1002ee2"), -1);
		assertNotNull(ref);
		assertEquals(RefType.CONDITIONAL_JUMP, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f3e"), addr("0x1002f49"), 1);
		assertNotNull(ref);
		assertEquals(RefType.DATA, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f73"), addr("0x00000064"), 0);
		assertNotNull(ref);
		assertEquals(RefType.DATA, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefAddDiffPickMy() throws Exception {
		// Add mnemonic mem ref from 1002eaf to 1002ee2 CONDITIONAL_JUMP primary user_defined
		// Add op1 mem ref from 1002f3e to 1002f49 DATA non-primary user_defined
		// Add op0 mem ref from 1002f73 to 00000064 DATA primary user_defined

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
					Reference ref;
					ref = refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.WRITE, SourceType.USER_DEFINED, -1);
					ref = refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.setPrimary(ref, false);
					ref = refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.READ, SourceType.USER_DEFINED, 0);

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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x1002eaf"), addr("0x1002ee2"), -1);
		assertNotNull(ref);
		assertEquals(RefType.WRITE, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f3e"), addr("0x1002f49"), 1);
		assertNotNull(ref);
		assertEquals(RefType.DATA, ref.getReferenceType());
		assertTrue(!ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f73"), addr("0x00000064"), 0);
		assertNotNull(ref);
		assertEquals(RefType.READ, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefAddPrimaryPickLatest() throws Exception {
		// Add mnemonic mem ref from 1002eaf to ??? primary user_defined
		// Add op1 mem ref from 1002f3e to ??? primary user_defined
		// Add op0 mem ref from 1002f73 to ??? primary user_defined
		// 1002fe8 op 0 has no refs, so add primary.

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002edd"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f6d"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x000000ff"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x1002eaf"), addr("0x1002ee2"), -1);
		assertNotNull(ref);
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f3e"), addr("0x1002f49"), 1);
		assertNotNull(ref);
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f73"), addr("0x00000064"), 0);
		assertNotNull(ref);
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefAddPrimaryPickMy() throws Exception {
		// Add mnemonic mem ref from 1002eaf to ??? primary user_defined
		// Add op1 mem ref from 1002f3e to ??? primary user_defined
		// Add op0 mem ref from 1002f73 to ??? primary user_defined
		// 1002fe8 op 0 has no refs, so add primary.

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f49"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x00000064"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
					refMgr.addMemoryReference(addr(program, "0x1002eaf"),
						addr(program, "0x1002edd"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f3e"),
						addr(program, "0x1002f6d"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x1002f73"),
						addr(program, "0x000000ff"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x1002eaf"), addr("0x1002edd"), -1);
		assertNotNull(ref);
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f3e"), addr("0x1002f6d"), 1);
		assertNotNull(ref);
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1002f73"), addr("0x000000ff"), 0);
		assertNotNull(ref);
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefRemoveVsPrimaryPickLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// Mem Refs
			// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
			// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
					refMgr.delete(ref);
					ref = refMgr.addMemoryReference(addr(program, "0x1001a92"),
						addr(program, "0x1002edd"), RefType.DATA, SourceType.USER_DEFINED, 0);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

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
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
					refMgr.delete(ref);
					ref = refMgr.addMemoryReference(addr(program, "0x1001abb"),
						addr(program, "0x1002edd"), RefType.DATA, SourceType.USER_DEFINED, 0);

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
		chooseRadioButton(LATEST_BUTTON); // primary conflict
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNull(ref);

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNotNull(ref);
		assertEquals(RefType.DATA_IND, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefRemoveVsPrimaryPickMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// Mem Refs
			// 01001a92: op0 to 01001370 DAT_01001370 DATA primary user
			// 01001abb: op0 to 01001ac1 LAB_01001ac1 CONDITIONAL_JUMP primary

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
					refMgr.delete(ref);
					ref = refMgr.addMemoryReference(addr(program, "0x1001a92"),
						addr(program, "0x1002edd"), RefType.DATA, SourceType.USER_DEFINED, 0);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

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
					Reference ref = refMgr.getReference(addr(program, "0x1001a92"),
						addr(program, "0x1001370"), 0);
//					refMgr.setPrimary(ref, false);
					refMgr.updateRefType(ref, RefType.DATA_IND);

					ref = refMgr.getReference(addr(program, "0x1001abb"),
						addr(program, "0x1001ac1"), 0);
					refMgr.delete(ref);
					ref = refMgr.addMemoryReference(addr(program, "0x1001abb"),
						addr(program, "0x1002edd"), RefType.DATA, SourceType.USER_DEFINED, 0);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON); // primary conflict
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x1001a92"), addr("0x1001370"), 0);
		assertNotNull(ref);
		assertEquals(RefType.DATA_IND, ref.getReferenceType());
		assertTrue(ref.isPrimary());

		ref = refMgr.getReference(addr("0x1001abb"), addr("0x1001ac1"), 0);
		assertNull(ref);
	}

	@Test
	public void testMemRefChangeFallthroughPickLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				assertNotNull(refMgr.getReference(addr(program, "0x01002f49"),
					addr(program, "0x01002f55"), -1));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), -1);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.FALL_THROUGH);
					assertEquals(RefType.FALL_THROUGH, ref.getReferenceType());

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
					Reference ref = refMgr.getReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), -1);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.WRITE);
					assertEquals(RefType.WRITE, ref.getReferenceType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x01002f49"), addr("0x01002f55"), -1);
		assertNotNull(ref);
		assertEquals(RefType.FALL_THROUGH, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testMemRefChangeFallthroughPickMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				assertNotNull(refMgr.getReference(addr(program, "0x01002f49"),
					addr(program, "0x01002f55"), -1));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					Reference ref = refMgr.getReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), -1);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.FALL_THROUGH);
					assertEquals(RefType.FALL_THROUGH, ref.getReferenceType());

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
					Reference ref = refMgr.getReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), -1);
//					refMgr.setPrimary(ref, false);
					ref = refMgr.updateRefType(ref, RefType.WRITE);
					assertEquals(RefType.WRITE, ref.getReferenceType());

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x01002f49"), addr("0x01002f55"), -1);
		assertNotNull(ref);
		assertEquals(RefType.WRITE, ref.getReferenceType());
		assertTrue(ref.isPrimary());
	}

	@Test
	public void testFallthroughConflictKeepChangedLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Override fallthrough (0x01006421 to 0x01006423) by setting from 0x01006421 to 0x01006436
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006436"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				assertNotNull(refMgr.getReference(addr(program, "0x01006421"),
					addr(program, "0x01006436"), -1));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Change override fallthrough by setting from 0x01006421 to 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006442"));
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
//					// Remove default fallthrough for 0x01006421
//					Instruction inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
//					inst.setFallThrough(null);
//					commit = true;

					// Restore fallthrough by setting for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride(); // default fallthrough is 0x01006423
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_LATEST, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x01006442"), resultInst.getFallThrough());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x01006421"), addr("0x01006442"), -1);
		assertNotNull(ref);
		assertEquals(RefType.FALL_THROUGH, ref.getReferenceType());
	}

	@Test
	public void testFallthroughConflictKeepRestoredDefaultMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Override fallthrough (0x01006421 to 0x01006423) by setting from 0x01006421 to 0x01006436
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006436"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				assertNotNull(refMgr.getReference(addr(program, "0x01006421"),
					addr(program, "0x01006436"), -1));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Change override fallthrough by setting from 0x01006421 to 0x01006442
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006442"));
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
//					// Remove default fallthrough for 0x01006421
//					Instruction inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
//					inst.setFallThrough(null);
//					commit = true;

					// Restore fallthrough by setting for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride(); // default fallthrough is 0x01006423
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_MY, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x01006423"), resultInst.getFallThrough());
	}

	@Test
	public void testFallthroughConflictKeepChangedMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Override fallthrough (0x01006421 to 0x01006423) by setting from 0x01006421 to 0x01006436
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006436"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				assertNotNull(refMgr.getReference(addr(program, "0x01006421"),
					addr(program, "0x01006436"), -1));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
//					// Remove default fallthrough for 0x01006421
//					Instruction inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
//					inst.setFallThrough(null);
//					commit = true;

					// Restore fallthrough by setting for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride(); // default fallthrough is 0x01006423
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
					// Change override fallthrough by setting from 0x01006421 to 0x01006442
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006442"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_MY, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x01006442"), resultInst.getFallThrough());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference ref = refMgr.getReference(addr("0x01006421"), addr("0x01006442"), -1);
		assertNotNull(ref);
		assertEquals(RefType.FALL_THROUGH, ref.getReferenceType());
	}

	@Test
	public void testFallthroughConflictKeepRestoredDefaultLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Setup Original Program");
				boolean commit = false;
				try {
					// Override fallthrough (0x01006421 to 0x01006423) by setting from 0x01006421 to 0x01006436
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006436"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				assertNotNull(refMgr.getReference(addr(program, "0x01006421"),
					addr(program, "0x01006436"), -1));
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
//					// Remove default fallthrough for 0x01006421
//					Instruction inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
//					inst.setFallThrough(null);
//					commit = true;

					// Restore fallthrough by setting for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride(); // default fallthrough is 0x01006423
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
					// Change override fallthrough by setting from 0x01006421 to 0x01006442
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x01006442"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_LATEST, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x01006423"), resultInst.getFallThrough());
	}

	@Test
	public void testRemoveDefaultFallthroughNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				Instruction inst =
					program.getListing().getInstructionAt(addr(program, "0x01006421"));
				assertEquals(addr(program, "0x01006423"), inst.getFallThrough());
				inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
				assertEquals(addr(program, "0x01006435"), inst.getFallThrough());
				inst = program.getListing().getInstructionAt(addr(program, "0x01006443"));
				assertEquals(addr(program, "0x01006446"), inst.getFallThrough());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Remove default fallthrough for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
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
					// Remove default fallthrough for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					inst = program.getListing().getInstructionAt(addr(program, "0x01006443"));
					inst.setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(null, resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(null, resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006443"));
		assertEquals(null, resultInst.getFallThrough());
	}

	@Test
	public void testOverrideFallthroughNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				Instruction inst =
					program.getListing().getInstructionAt(addr(program, "0x01006421"));
				assertEquals(addr(program, "0x01006423"), inst.getFallThrough());
				inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
				assertEquals(addr(program, "0x01006435"), inst.getFallThrough());
				inst = program.getListing().getInstructionAt(addr(program, "0x01006443"));
				assertEquals(addr(program, "0x01006446"), inst.getFallThrough());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Override default fallthrough for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
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
					// Override fallthrough for 0x01006421
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					inst = program.getListing().getInstructionAt(addr(program, "0x01006443"));
					inst.setFallThrough(addr(program, "0x0100644f"));
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x0100642a"), resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(addr("0x0100643d"), resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006443"));
		assertEquals(addr("0x0100644f"), resultInst.getFallThrough());
	}

	@Test
	public void testRemoveVsOverrideFallthroughKeepLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				Instruction inst;
				// default fallthroughs
				inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
				assertEquals(addr(program, "0x01006423"), inst.getFallThrough());
				inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
				assertEquals(addr(program, "0x01006435"), inst.getFallThrough());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction inst;
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					// override fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
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
					Instruction inst;
					// override fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_LATEST, false);
		chooseCodeUnit("0x0100642f", "0x01006434", KEEP_LATEST, false);
		waitForMergeCompletion();

		Instruction resultInst;
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(null, resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(addr("0x0100643d"), resultInst.getFallThrough());
	}

	@Test
	public void testRemoveVsOverrideFallthroughKeepMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				Instruction inst =
					program.getListing().getInstructionAt(addr(program, "0x01006421"));
				assertEquals(addr(program, "0x01006423"), inst.getFallThrough());
				inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
				assertEquals(addr(program, "0x01006435"), inst.getFallThrough());
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
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
					Instruction inst =
						program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_MY, false);
		chooseCodeUnit("0x0100642f", "0x01006434", KEEP_MY, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x0100642a"), resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(null, resultInst.getFallThrough());
	}

	@Test
	public void testRemoveVsRestoreFallthroughKeepLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Instruction inst;
					// override fallthroughs
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
					commit = true;
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
					Instruction inst;
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride();
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
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
					Instruction inst;
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.clearFallThroughOverride();
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_LATEST, false);
		chooseCodeUnit("0x0100642f", "0x01006434", KEEP_LATEST, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x01006423"), resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(null, resultInst.getFallThrough());
	}

	@Test
	public void testRemoveVsRestoreFallthroughKeepMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Instruction inst;
					// override fallthroughs
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
					commit = true;
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
					Instruction inst;
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride();
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
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
					Instruction inst;
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.clearFallThroughOverride();
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_MY, false);
		chooseCodeUnit("0x0100642f", "0x01006434", KEEP_MY, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(null, resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(addr("0x01006435"), resultInst.getFallThrough());
	}

	@Test
	public void testOverrideVsRestoreFallthroughKeepLatest() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Instruction inst;
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
					commit = true;
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
					Instruction inst;
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride();
					// override fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
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
					Instruction inst;
					// override fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.clearFallThroughOverride();
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_LATEST, false);
		chooseCodeUnit("0x0100642f", "0x01006434", KEEP_LATEST, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x01006423"), resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(addr("0x0100643d"), resultInst.getFallThrough());
	}

	@Test
	public void testOverrideVsRestoreFallthroughKeepMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new OriginalProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Instruction inst;
					// remove fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(null);
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(null);
					commit = true;
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
					Instruction inst;
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.clearFallThroughOverride();
					// override fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.setFallThrough(addr(program, "0x0100643d"));
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
					Instruction inst;
					// override fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x01006421"));
					inst.setFallThrough(addr(program, "0x0100642a"));
					// restore fallthrough
					inst = program.getListing().getInstructionAt(addr(program, "0x0100642f"));
					inst.clearFallThroughOverride();
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x01006421", "0x01006422", KEEP_MY, false);
		chooseCodeUnit("0x0100642f", "0x01006434", KEEP_MY, false);
		waitForMergeCompletion();

		Instruction resultInst = resultProgram.getListing().getInstructionAt(addr("0x01006421"));
		assertEquals(addr("0x0100642a"), resultInst.getFallThrough());
		resultInst = resultProgram.getListing().getInstructionAt(addr("0x0100642f"));
		assertEquals(addr("0x01006435"), resultInst.getFallThrough());
	}

}
