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

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.*;

/**
 * Test the merge of the versioned program's listing.
 */
public class ReferenceMergerTest extends AbstractListingMergeManagerTest {

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

	/**
	 * 
	 * @param arg0
	 */
	public ReferenceMergerTest() {
		super();
	}

//	/**
//	 * 
//	 * @param program
//	 * @param ref
//	 * @param varName
//	 */
//	private void changeStackRefToVarRef(ProgramDB program, String fromAddr, int opIndex, String varName) {
//		Address fromAddress = addr(program, fromAddr);
//		ReferenceManager refMgr = program.getReferenceManager();
//		Reference[] refs = refMgr.getReferencesFrom(addr(program, fromAddr), opIndex);
//		assertEquals(1, refs.length);
//		Function f = program.getFunctionManager().getFunctionContaining(fromAddress);
//		Symbol s = program.getSymbolTable().getSymbol(varName, f);
//		Variable var = (Variable)s.getObject();
//		refMgr.addVariableReference(fromAddress, opIndex, var, refs[0].getReferenceType(), refs[0].isUserDefined());
//	}

//	/**
//	 * 
//	 * @param program
//	 * @param ref
//	 * @param varName
//	 */
//	private void changeStackRefOffset(ProgramDB program, String fromAddr, int opIndex, int offset) {
//		Address fromAddress = addr(program, fromAddr);
//		ReferenceManager refMgr = program.getReferenceManager();
//		Reference[] refs = refMgr.getReferencesFrom(addr(program, fromAddr), opIndex);
//		assertEquals(1, refs.length);
//		refMgr.addStackReference(fromAddress, opIndex, offset, refs[0].getReferenceType(), refs[0].isUserDefined());
//	}

@Test
    public void testAddMemVsExtPickLatest() throws Exception {

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
					refMgr.addExternalReference(addr(program, "0x10024ea"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 1,
						RefType.DATA);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x10025d8"), RefType.DATA, SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x1002608"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
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
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x100248c"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x10024ce"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x10025f1"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addExternalReference(addr(program, "0x1002510"), "USER32.DLL",
						"getMessage", addr(program, "0x1001a11"), SourceType.USER_DEFINED, 0,
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
		chooseRadioButton(LATEST_BUTTON);
		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(3, refs.length);
		Arrays.sort(refs);
		assertEquals(addr("0x00000010"), refs[0].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
		assertEquals(addr("0x10025d8"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[1].getReferenceType());
		assertTrue(!refs[1].isPrimary());
		assertEquals(addr("0x1002608"), refs[2].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[2].getReferenceType());
		assertTrue(!refs[2].isPrimary());
	}

@Test
    public void testAddMemVsExtPickMy() throws Exception {

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
					refMgr.addExternalReference(addr(program, "0x10024ea"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 1,
						RefType.DATA);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x10025d8"), RefType.DATA, SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x1002608"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
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
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x100248c"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x10024ce"), RefType.DATA, SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x10025f1"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addExternalReference(addr(program, "0x1002510"), "USER32.DLL",
						"getMessage", addr(program, "0x1001a11"), SourceType.USER_DEFINED, 0,
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
		chooseRadioButton(MY_BUTTON);
		chooseRadioButton(MY_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("010024ea"), 1);
		assertEquals(4, refs.length);
		Arrays.sort(refs);
		assertEquals(addr("0x100248c"), refs[0].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
		assertEquals(addr("0x10024ce"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[1].getReferenceType());
		assertTrue(!refs[1].isPrimary());
		assertEquals(addr("0x10025f1"), refs[2].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[2].getReferenceType());
		assertTrue(!refs[2].isPrimary());
		assertEquals(addr("0x1002ee2"), refs[3].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[3].getReferenceType());
		assertTrue(!refs[3].isPrimary());

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals("USER32.DLL::getMessage",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01001a11",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
	}

@Test
    public void testAddMemVsVarPickMy() throws Exception {
		// Stack Refs
		// 01001a55: op1 no ref to stack offset 0x10
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// 01002125: op0 to stack offset -0x10
		// 010024ea: op1 no ref to stack offset 0x10
		// 01002510: op0 no ref to stack offset 0x8
		// 01002a05: op0 no ref to stack offset -0x18

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
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
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
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x8, RefType.DATA,
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
		assertEquals(addr("0x1002ee2"), refs[0].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(0x8, ((StackReference) refs[0]).getStackOffset());
	}

@Test
    public void testAddSameFallthrough() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
	}

@Test
    public void testAddConflictingFallthroughsPickLatest() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
	}

@Test
    public void testAddConflictingFallthroughsPickMy() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_MY); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f5d"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
	}

	/**
	 * Tests Merge with Fallthrough conflict.
	 * 1) Fallthrough conflict for 1002f55(latest) vs 1002f5d(my)
	 * 2) Fallthrough(latest) vs Mem(my) ref for 1002f55
	 * Choose latest for 1.
	 * Choose latest for 2.
	 * @throws Exception
	 */
@Test
    public void testAddMemFallthroughConflict1() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
	}

	/**
	 * Tests Merge with Fallthrough conflict.
	 * 1) Fallthrough conflict for 1002f55(latest) vs 1002f5d(my)
	 * 2) Fallthrough(latest) vs Mem(my) ref for 1002f55
	 * Choose my for 1.
	 * Automerge my from 2 due to latest rejected in 1.
	 * @throws Exception
	 */
@Test
    public void testAddMemFallthroughConflict2() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_MY); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		Arrays.sort(refs);
		assertEquals(2, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[1].getReferenceType());
		assertEquals(false, refs[1].isPrimary());
	}

	/**
	 * Tests Merge with Fallthrough conflict.
	 * 1) Fallthrough conflict for 1002f5d(latest) vs 1002f5d(my)
	 * 2) Mem(latest) vs Fallthrough(my) ref for 1002f55
	 * Choose latest for 1.
	 * Automerge my from 2 due to latest rejected in 1.
	 * @throws Exception
	 */
@Test
    public void testAddMemFallthroughConflict3() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		Arrays.sort(refs);
		assertEquals(2, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[1].getReferenceType());
		assertEquals(false, refs[1].isPrimary());
	}

	/**
	 * Tests Merge with Fallthrough conflict.
	 * 1) Fallthrough conflict for 1002f5d(latest) vs 1002f5d(my)
	 * 2) Mem(latest) vs Fallthrough(my) ref for 1002f55
	 * Choose my for 1.
	 * Automerge my from 2 due to latest rejected in 1.
	 * @throws Exception
	 */
@Test
    public void testAddMemFallthroughConflict4() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_MY); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertEquals(true, refs[0].isPrimary());
	}

	/**
	 * Tests Merge with Fallthrough conflict.
	 * 1) Fallthrough conflict for 1002f5d(latest) vs 1002f5d(my)
	 * 2) Mem(latest) vs Fallthrough(my) ref for 1002f55
	 * Choose my for 1.
	 * Automerge my from 2 due to latest rejected in 1.
	 * @throws Exception
	 */
@Test
    public void testAddMemFallthroughConflict5() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(2, refs.length);
		Arrays.sort(refs);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[0].getReferenceType());
		assertEquals(true, refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[1].getReferenceType());
		assertEquals(false, refs[1].isPrimary());
	}

	/**
	 * Tests Merge with Fallthrough conflict.
	 * 1) Fallthrough conflict for 1002f5d(latest) vs 1002f5d(my)
	 * 2) Mem(latest) vs Fallthrough(my) ref for 1002f55
	 * Choose my for 1.
	 * Automerge my from 2 due to latest rejected in 1.
	 * @throws Exception
	 */
@Test
    public void testAddMemFallthroughConflict6() throws Exception {

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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
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
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002f49", "0x1002f4a", KEEP_MY); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(2, refs.length);
		Arrays.sort(refs);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertEquals(true, refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[1].getReferenceType());
		assertEquals(false, refs[1].isPrimary());
	}

@Test
    public void testRemoveFallthroughNoConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.getInstructionAt(addr(program, "0x01002f38")).setFallThrough(null);
					listing.getInstructionAt(addr(program, "0x01002ff6")).setFallThrough(null);
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
					Listing listing = program.getListing();
					listing.getInstructionAt(addr(program, "0x01002f38")).setFallThrough(null);
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();
		assertNull(listing.getInstructionAt(addr("0x01002f38")).getFallThrough());
		assertNull(listing.getInstructionAt(addr("0x01002ff6")).getFallThrough());
		assertNull(listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}

@Test
    public void testRemoveFallthroughConflict() throws Exception {

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					listing.getInstructionAt(addr(program, "0x01002ff6")).setFallThrough(null);
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(
						addr(program, "0x01003060"));
					listing.getInstructionAt(addr(program, "0x01003105")).setFallThrough(null);
					listing.getInstructionAt(addr(program, "0x0100319a")).setFallThrough(
						addr(program, "0x010031a0"));
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
					Listing listing = program.getListing();
					listing.getInstructionAt(addr(program, "0x01002ff6")).setFallThrough(
						addr(program, "0x01002ffd"));
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(null);
					listing.getInstructionAt(addr(program, "0x01003105")).setFallThrough(
						addr(program, "0x01003108"));
					listing.getInstructionAt(addr(program, "0x0100319a")).setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x1002ff6", "0x1002ff7", KEEP_LATEST); // Fallthrough is now a code unit diff.
		chooseCodeUnit("0x1003059", "0x100305a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		chooseCodeUnit("0x1003105", "0x1003106", KEEP_MY); // Fallthrough is now a code unit diff.
		chooseCodeUnit("0x100319a", "0x100319b", KEEP_MY); // Fallthrough is now a code unit diff.
		waitForMergeCompletion();

		Listing listing = resultProgram.getListing();
		assertNull(listing.getInstructionAt(addr("0x01002ff6")).getFallThrough());
		assertEquals(addr("0x01003060"),
			listing.getInstructionAt(addr("0x01003059")).getFallThrough());
		assertEquals(addr("0x01003108"),
			listing.getInstructionAt(addr("0x01003105")).getFallThrough());
		assertNull(listing.getInstructionAt(addr("0x0100319a")).getFallThrough());
	}

@Test
    public void testAddRefSourceDiff() throws Exception {

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
					refMgr.addExternalReference(addr(program, "0x10024ea"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.IMPORTED, 1, RefType.DATA);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP, SourceType.IMPORTED,
						0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x10025d8"), RefType.DATA, SourceType.ANALYSIS, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x1002608"), RefType.CONDITIONAL_JUMP, SourceType.DEFAULT, 0);
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
					refMgr.addExternalReference(addr(program, "0x10024ea"), "USER32.DLL", "printf",
						addr(program, "0x01234567"), SourceType.USER_DEFINED, 1,
						RefType.DATA);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x10025d8"), RefType.DATA, SourceType.USER_DEFINED, 0);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x1002608"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
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
// For now we no longer want to detect source type differences since they can't be changed anyway.
//		chooseRadioButton(LATEST_BUTTON);
//		chooseRadioButton(LATEST_BUTTON);
//		chooseRadioButton(LATEST_BUTTON);
//		chooseRadioButton(LATEST_BUTTON);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertEquals("USER32.DLL::printf",
			((ExternalReference) refs[0]).getExternalLocation().toString());
		assertEquals("01234567",
			((ExternalReference) refs[0]).getExternalLocation().getAddress().toString());
		assertTrue(refs[0].isPrimary());
		assertEquals(SourceType.IMPORTED, refs[0].getSource());

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(3, refs.length);
		assertEquals(addr("0x00000010"), refs[0].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
		assertEquals(SourceType.IMPORTED, refs[0].getSource());
		assertEquals(addr("0x10025d8"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[1].getReferenceType());
		assertTrue(!refs[1].isPrimary());
		assertEquals(SourceType.ANALYSIS, refs[1].getSource());
		assertEquals(addr("0x1002608"), refs[2].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[2].getReferenceType());
		assertTrue(!refs[2].isPrimary());
		assertEquals(SourceType.DEFAULT, refs[2].getSource());
	}

	private void setupRefTypeConflictUseForAll() throws Exception {
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
					refMgr.addStackReference(addr(program, "0x10024ea"), 1, 0x10, RefType.DATA,
						SourceType.USER_DEFINED);
					refMgr.addMemoryReference(addr(program, "0x1002510"),
						addr(program, "0x00000010"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 0);
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
					refMgr.addMemoryReference(addr(program, "0x10024ea"),
						addr(program, "0x1002ee2"), RefType.CONDITIONAL_JUMP,
						SourceType.USER_DEFINED, 1);
					refMgr.addStackReference(addr(program, "0x1002510"), 0, 0x8, RefType.DATA,
						SourceType.USER_DEFINED);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

@Test
    public void testRefTypeConflictUseForAllPickLatest() throws Exception {
		// Stack Refs
		// 01001a55: op1 no ref to stack offset 0x10
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// 01002125: op0 to stack offset -0x10
		// 010024ea: op1 no ref to stack offset 0x10
		// 01002510: op0 no ref to stack offset 0x8
		// 01002a05: op0 no ref to stack offset -0x18

		setupRefTypeConflictUseForAll();

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON, VerticalChoicesPanel.class, false);
		setUseForAll(true, VerticalChoicesPanel.class);
		chooseApply();
//		chooseRadioButton(LATEST_BUTTON, VerticalChoicesPanel.class, true); // Handled by Use For All
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(0x10, ((StackReference) refs[0]).getStackOffset());
//		assertEquals("Stack[0x10]", refs[0].getToAddress().toString());
//		assertEquals(RefType.DATA, refs[0].getReferenceType());
//		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(1, refs.length);
		assertEquals(addr("0x00000010"), refs[0].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
//		assertTrue(refs[0] instanceof StackReference);
//		assertEquals(0x8, ((StackReference) refs[0]).getStackOffset());
	}

@Test
    public void testRefTypeConflictUseForAllPickMy() throws Exception {
		// Stack Refs
		// 01001a55: op1 no ref to stack offset 0x10
		// 01001af5: op0 to stack offset -0x24a
		// 01001b03: op1 to stack offset -0x24c
		// 01002125: op0 to stack offset -0x10
		// 010024ea: op1 no ref to stack offset 0x10
		// 01002510: op0 no ref to stack offset 0x8
		// 01002a05: op0 no ref to stack offset -0x18

		setupRefTypeConflictUseForAll();

		executeMerge(ASK_USER);
		chooseRadioButton(MY_BUTTON, VerticalChoicesPanel.class, false);
		setUseForAll(true, VerticalChoicesPanel.class);
		chooseApply();
//		chooseRadioButton(MY_BUTTON, VerticalChoicesPanel.class, true); // Handled by Use For All
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x10024ea"), 1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x1002ee2"), refs[0].getToAddress());
		assertEquals(RefType.CONDITIONAL_JUMP, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("01002510"), 0);
		assertEquals(1, refs.length);
		assertTrue(refs[0] instanceof StackReference);
		assertEquals(0x8, ((StackReference) refs[0]).getStackOffset());
	}

@Test
    public void testFallthroughConflictDontUseForAllPickLatest() throws Exception {

		setupFallthroughConflictUseForAll();

		executeMerge(ASK_USER);

		chooseCodeUnit("0x01002f49", "0x01002f4a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		chooseCodeUnit("0x01003059", "0x0100305a", KEEP_LATEST); // Fallthrough is now a code unit diff.
		chooseReference("0x01002f5d", 1, KEEP_LATEST, false);
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("0x01002f5d"), 1);
		Arrays.sort(refs);
		assertEquals(2, refs.length);
		assertEquals(addr("0x10024ce"), refs[0].getToAddress());
		assertEquals(addr("0x1002517"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		Listing listing = resultProgram.getListing();
		assertEquals(addr("0x01003060"),
			listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}

	private void setupFallthroughConflictUseForAll() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x1002f5d"),
						addr(program, "0x10024ce"), RefType.DATA, SourceType.USER_DEFINED, 1);
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(
						addr(program, "0x01003060"));
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
					Listing listing = program.getListing();
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.FALL_THROUGH, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x1002f5d"),
						addr(program, "0x1002517"), RefType.READ, SourceType.USER_DEFINED, 1);
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

@Test
    public void testFallthroughConflictUseForAllPickLatest() throws Exception {

		setupFallthroughConflictUseForAll();

		executeMerge(ASK_USER);

		chooseCodeUnit("0x01002f49", "0x01002f4a", KEEP_LATEST, true); // Fallthrough is now a code unit diff.
//		chooseCodeUnit("0x01003059", "0x0100305a", KEEP_LATEST); // 0x01003059 Handled by Use For All.
		chooseReference("0x01002f5d", 1, KEEP_LATEST, false); // 01002f5d
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("0x01002f5d"), 1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x10024ce"), refs[0].getToAddress());
		assertEquals(addr("0x1002517"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		Listing listing = resultProgram.getListing();
		assertEquals(addr("0x01003060"),
			listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}

@Test
    public void testFallthroughConflictUseForAllPickMy() throws Exception {

		setupFallthroughConflictUseForAll();

		executeMerge(ASK_USER);

		chooseCodeUnit("0x01002f49", "0x01002f4a", KEEP_MY, true); // Fallthrough is now a code unit diff.
//		chooseCodeUnit("0x01003059", "0x0100305a", KEEP_MY); // 0x01003059 Handled by Use For All.
		chooseReference("0x01002f5d", 1, KEEP_LATEST, false); // 01002f5d
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(1, refs.length);
		assertEquals(addr("0x01002f5d"), refs[0].getToAddress());
		assertEquals(RefType.FALL_THROUGH, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		refs = refMgr.getReferencesFrom(addr("0x01002f5d"), 1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x10024ce"), refs[0].getToAddress());
		assertEquals(addr("0x1002517"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		Listing listing = resultProgram.getListing();
		assertNull(listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}

	private void setupPrimaryConflictUseForAll() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Listing listing = program.getListing();
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f55"), RefType.READ_WRITE, SourceType.USER_DEFINED,
						-1);
					refMgr.addMemoryReference(addr(program, "0x1002f5d"),
						addr(program, "0x10024ce"), RefType.DATA, SourceType.USER_DEFINED, 1);
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(
						addr(program, "0x01003060"));
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
					Listing listing = program.getListing();
					ReferenceManager refMgr = program.getReferenceManager();
					refMgr.addMemoryReference(addr(program, "0x01002f49"),
						addr(program, "0x01002f5d"), RefType.READ, SourceType.USER_DEFINED, -1);
					refMgr.addMemoryReference(addr(program, "0x1002f5d"),
						addr(program, "0x1002517"), RefType.READ, SourceType.USER_DEFINED, 1);
					listing.getInstructionAt(addr(program, "0x01003059")).setFallThrough(null);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

@Test
    public void testPrimaryConflictDontUseForAllPickLatest() throws Exception {

		setupPrimaryConflictUseForAll();

		executeMerge(ASK_USER);

		chooseCodeUnit("0x01003059", "0x0100305a", KEEP_LATEST, false);
		chooseReference("0x01002f49", -1, KEEP_LATEST, true); // 0x01002f49
//		chooseReference("0x01002f5d", 1, KEEP_LATEST, false); // 0x01002f5d Handled by Use For All.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.READ, refs[1].getReferenceType());
		assertFalse(refs[1].isPrimary());

		refs = refMgr.getReferencesFrom(addr("0x01002f5d"), 1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x10024ce"), refs[0].getToAddress());
		assertEquals(addr("0x1002517"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		Listing listing = resultProgram.getListing();
		assertEquals(addr("0x01003060"),
			listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}

@Test
    public void testPrimaryConflictUseForAllPickLatest() throws Exception {

		setupPrimaryConflictUseForAll();

		executeMerge(ASK_USER);

		chooseCodeUnit("0x01003059", "0x0100305a", KEEP_LATEST, false);
		chooseReference("0x01002f49", -1, KEEP_LATEST, true); // 0x01002f49
//		chooseReference("0x01002f5d", 1, KEEP_LATEST, false); // 0x01002f5d Handled by Use For All.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.READ, refs[1].getReferenceType());
		assertFalse(refs[1].isPrimary());

		refs = refMgr.getReferencesFrom(addr("0x01002f5d"), 1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x10024ce"), refs[0].getToAddress());
		assertEquals(addr("0x1002517"), refs[1].getToAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertTrue(refs[0].isPrimary());

		Listing listing = resultProgram.getListing();
		assertEquals(addr("0x01003060"),
			listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}

@Test
    public void testPrimaryConflictUseForAllPickMy() throws Exception {

		setupPrimaryConflictUseForAll();

		executeMerge(ASK_USER);

		chooseCodeUnit("0x01003059", "0x0100305a", KEEP_LATEST, false);
		chooseReference("0x01002f49", -1, KEEP_MY, true); // 0x01002f49
//		chooseReference("0x01002f5d", 1, KEEP_MY, false); // 0x01002f5d Handled by Use For All.
		waitForMergeCompletion();

		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] refs;
		refs = refMgr.getReferencesFrom(addr("0x01002f49"), -1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x01002f55"), refs[0].getToAddress());
		assertEquals(RefType.READ_WRITE, refs[0].getReferenceType());
		assertFalse(refs[0].isPrimary());
		assertEquals(addr("0x01002f5d"), refs[1].getToAddress());
		assertEquals(RefType.READ, refs[1].getReferenceType());
		assertTrue(refs[1].isPrimary());

		refs = refMgr.getReferencesFrom(addr("0x01002f5d"), 1);
		assertEquals(2, refs.length);
		assertEquals(addr("0x10024ce"), refs[0].getToAddress());
		assertEquals(RefType.DATA, refs[0].getReferenceType());
		assertFalse(refs[0].isPrimary());
		assertEquals(addr("0x1002517"), refs[1].getToAddress());
		assertEquals(RefType.READ, refs[1].getReferenceType());
		assertTrue(refs[1].isPrimary());

		Listing listing = resultProgram.getListing();
		assertEquals(addr("0x01003060"),
			listing.getInstructionAt(addr("0x01003059")).getFallThrough());
	}
}
