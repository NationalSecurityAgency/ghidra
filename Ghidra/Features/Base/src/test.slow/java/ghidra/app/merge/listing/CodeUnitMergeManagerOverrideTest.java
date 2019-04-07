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
import ghidra.program.database.*;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramDiff;

import org.junit.Test;

/**
 * Test the merge of the versioned program's listing.
 * Provides tests that create instruction flow overrides in various combinations.
 * For tests with conflicts, checks selection of latest, my, or original code unit(s).
 */
public class CodeUnitMergeManagerOverrideTest extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public CodeUnitMergeManagerOverrideTest() {
		super();
	}

@Test
    public void testAddLatestFlowOverride() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				// Do nothing.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

@Test
    public void testAddMyFlowOverride() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				// Do nothing.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

@Test
    public void testAddLatestFlowOverrideMyFlowOverridePickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

@Test
    public void testAddLatestFlowOverrideMyFlowOverridePickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

@Test
    public void testAddLatestFlowOverrideMyFlowOverridePickOrig() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

@Test
    public void testSameFlowOverrideLatestMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

@Test
    public void testRemoveLatestFlowOverrideChangeMyFlowOverridePickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.NONE);
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
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
	}

	@Test
	public void testAddMyFlowOverrideWhereHasDataRef() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					// Create a data ref.
					refMgr.addMemoryReference(addr(program, "0100354f"), addr(program, "01003553"),
						RefType.DATA, SourceType.USER_DEFINED, 1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
				assertEquals(1, referencesFrom.length);
				assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
				assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
				assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
			}
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
				assertEquals(1, referencesFrom.length);
				assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
				assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
				assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.CALL_RETURN, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	@Test
	public void testAddDifferentFlowOverrideWhereHasDataRefPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
				ReferenceManager refMgr = program.getReferenceManager();
					// Create a data ref.
					refMgr.addMemoryReference(addr(program, "0100354f"), addr(program, "01003553"),
						RefType.DATA, SourceType.USER_DEFINED, 1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
				assertEquals(1, referencesFrom.length);
				assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
				assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
				assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
			}
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
				assertEquals(1, referencesFrom.length);
				assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
				assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
				assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.BRANCH, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	@Test
	public void testAddDifferentFlowOverrideWhereHasDataRefPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new OriginalProgramModifierListener() {
			@Override
			public void modifyOriginal(ProgramDB program) {
				int txId = program.startTransaction("Modify Original Program");
				boolean commit = false;
				try {
					ReferenceManager refMgr = program.getReferenceManager();
					// Create a data ref.
					refMgr.addMemoryReference(addr(program, "0100354f"), addr(program, "01003553"),
						RefType.DATA, SourceType.USER_DEFINED, 1);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.BRANCH);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
				assertEquals(1, referencesFrom.length);
				assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
				assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
				assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
				ReferenceManager refMgr = program.getReferenceManager();
				Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
				assertEquals(1, referencesFrom.length);
				assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
				assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
				assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.CALL_RETURN, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	@Test
	public void testAddLatestFallthroughOverrideMyFlowOverridePickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Fallthrough override from 0100354f to 01003553.
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFallThrough(addr(program, "01003553"));
					commit = true;
					assertEquals(addr(program, "01003553"), instruction.getFallThrough());
					assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
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
					// Flow override at 0100354f was changed to a CallReturn.
					Instruction instruction =
						program.getListing().getInstructionAt(addr(program, "0100354f"));
					instruction.setFlowOverride(FlowOverride.CALL_RETURN);
					assertEquals(addr(program, "01003551"), instruction.getFallThrough());
					assertEquals(FlowOverride.CALL_RETURN, instruction.getFlowOverride());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(addr(resultProgram, "01003553"), instruction.getFallThrough());
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
	}

	@Test
	public void testAddLatestFallthroughOverrideMyFlowOverridePickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestFallthroughOverride(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myFlowOverride(program);
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.CALL_RETURN, instruction.getFlowOverride());
		assertEquals(addr(resultProgram, "01003551"), instruction.getFallThrough());
	}

	@Test
	public void testAddLatestDataRefMyFlowOverrideChooseLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestDataRef(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myFlowOverride(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom2.length);
		assertEquals(RefType.DATA, referencesFrom2[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom2[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom2[0].getToAddress());

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		assertEquals(false, instruction.isFallThroughOverridden());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	@Test
	public void testAddLatestDataRefMyFlowOverrideChooseMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestDataRef(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myFlowOverride(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom2.length);
		assertEquals(RefType.DATA, referencesFrom2[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom2[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom2[0].getToAddress());

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.CALL_RETURN, instruction.getFlowOverride());
		assertEquals(false, instruction.isFallThroughOverridden());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(0, referencesFrom.length);
	}

	@Test
	public void testAddLatestFlowOverrideMyDataRefChooseLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestFlowOverride(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myDataRef(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(0, referencesFrom2.length);

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.CALL_RETURN, instruction.getFlowOverride());
		assertEquals(false, instruction.isFallThroughOverridden());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(0, referencesFrom.length);
	}

	@Test
	public void testAddLatestFlowOverrideMyDataRefChooseMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestFlowOverride(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myDataRef(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(0, referencesFrom2.length);

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		assertEquals(false, instruction.isFallThroughOverridden());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"), 1);
		assertEquals(1, referencesFrom.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	@Test
	public void testAddLatestDataRefMyFallthroughOverrideChooseLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestDataRef(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myFallthroughOverride(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"));
		assertEquals(1, referencesFrom2.length);
		assertEquals(RefType.DATA, referencesFrom2[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom2[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom2[0].getToAddress());

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(false, instruction.isFallThroughOverridden());
		assertEquals(addr(resultProgram, "01003551"), instruction.getFallThrough());
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"));
		Reference[] diffRefs = ProgramDiff.getDiffRefs(referencesFrom);
		assertEquals(1, diffRefs.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	@Test
	public void testAddLatestDataRefMyFallthroughOverrideChooseMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestDataRef(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myFallthroughOverride(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"));
		assertEquals(1, referencesFrom2.length);
		assertEquals(RefType.DATA, referencesFrom2[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom2[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom2[0].getToAddress());

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(true, instruction.isFallThroughOverridden());
		assertEquals(addr(resultProgram, "01003559"), instruction.getFallThrough());
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"));
		Reference[] diffRefs = ProgramDiff.getDiffRefs(referencesFrom);
		assertEquals(0, diffRefs.length);
	}

	@Test
	public void testAddLatestFallthroughOverrideMyDataRefChooseLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestFallthroughOverride(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myDataRef(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"));
		assertEquals(1, referencesFrom2.length);
		assertEquals(RefType.FALL_THROUGH, referencesFrom2[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom2[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003559"), referencesFrom2[0].getToAddress());

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(true, instruction.isFallThroughOverridden());
		assertEquals(addr(resultProgram, "01003559"), instruction.getFallThrough());
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"));
		Reference[] diffRefs = ProgramDiff.getDiffRefs(referencesFrom);
		assertEquals(0, diffRefs.length);
	}

	@Test
	public void testAddLatestFallthroughOverrideMyDataRefChooseMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				latestFallthroughOverride(program);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				myDataRef(program);
			}
		});

		resultProgram = mtf.getResultProgram();
		ReferenceManager refMgr2 = resultProgram.getReferenceManager();
		Reference[] referencesFrom2 = refMgr2.getReferencesFrom(addr(resultProgram, "0100354f"));
		assertEquals(1, referencesFrom2.length);
		assertEquals(RefType.FALL_THROUGH, referencesFrom2[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom2[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003559"), referencesFrom2[0].getToAddress());

		executeMerge(ASK_USER);
		chooseCodeUnit("0100354f", "01003550", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0100354f"),
			addr("01003550")));
		Instruction instruction =
			resultProgram.getListing().getInstructionAt(addr(resultProgram, "0100354f"));
		assertEquals(false, instruction.isFallThroughOverridden());
		assertEquals(addr(resultProgram, "01003551"), instruction.getFallThrough());
		assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		ReferenceManager refMgr = resultProgram.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(resultProgram, "0100354f"));
		Reference[] diffRefs = ProgramDiff.getDiffRefs(referencesFrom);
		assertEquals(1, diffRefs.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(resultProgram, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(resultProgram, "01003553"), referencesFrom[0].getToAddress());
	}

	private void latestDataRef(ProgramDB program) {
		dataRef(program, "Modify Latest Program");
	}

	private void myDataRef(ProgramDB program) {
		dataRef(program, "Modify My Program");
	}

	/**
	 * Create a data ref from 0100354f to 01003553.
	 * @param program create the reference in this program.
	 * @param description description for the transaction that creates the reference.
	 */
	private void dataRef(ProgramDB program, String description) {
		int txId = program.startTransaction(description);
		boolean commit = false;
		ReferenceManager refMgr = program.getReferenceManager();
		try {
			// Create a data ref from 0100354f to 01003553.
			refMgr.addMemoryReference(addr(program, "0100354f"), addr(program, "01003553"),
				RefType.DATA, SourceType.USER_DEFINED, 1);
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
		assertEquals(1, referencesFrom.length);
		assertEquals(RefType.DATA, referencesFrom[0].getReferenceType());
		assertEquals(addr(program, "0100354f"), referencesFrom[0].getFromAddress());
		assertEquals(addr(program, "01003553"), referencesFrom[0].getToAddress());
	}

	private void latestFlowOverride(ProgramDB program) {
		flowOverride(program, "Modify Latest Program");
	}

	private void myFlowOverride(ProgramDB program) {
		flowOverride(program, "Modify My Program");
	}

	/**
	 * Override flow as a CallReturn @ 0100354f.
	 * @param program override the flow in this program.
	 * @param description description for the transaction that overrides the flow.
	 */
	private void flowOverride(ProgramDB program, String description) {
		int txId = program.startTransaction(description);
		boolean commit = false;
		try {
			// Override flow as a CallReturn @ 0100354f.
			Instruction instruction =
				program.getListing().getInstructionAt(addr(program, "0100354f"));
			instruction.setFlowOverride(FlowOverride.CALL_RETURN);
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
		assertEquals(0, referencesFrom.length);
	}

	private void latestFallthroughOverride(ProgramDB program) {
		fallthroughOverride(program, "Modify Latest Program");
	}

	private void myFallthroughOverride(ProgramDB program) {
		fallthroughOverride(program, "Modify My Program");
	}

	/**
	 * Fallthrough override from 0100354f to 01003559.
	 * @param program override the flow in this program.
	 * @param description description for the transaction that overrides the flow.
	 */
	private void fallthroughOverride(ProgramDB program, String description) {
		int txId = program.startTransaction(description);
		boolean commit = false;
		try {
			// Fallthrough override from 0100354f to 01003559.
			Instruction instruction =
				program.getListing().getInstructionAt(addr(program, "0100354f"));
			instruction.setFallThrough(addr(program, "01003559"));
			commit = true;
			assertEquals(addr(program, "01003559"), instruction.getFallThrough());
			assertEquals(FlowOverride.NONE, instruction.getFlowOverride());
		}
		finally {
			program.endTransaction(txId, commit);
		}
		ReferenceManager refMgr = program.getReferenceManager();
		Reference[] referencesFrom = refMgr.getReferencesFrom(addr(program, "0100354f"), 1);
		assertEquals(0, referencesFrom.length);
	}
}
