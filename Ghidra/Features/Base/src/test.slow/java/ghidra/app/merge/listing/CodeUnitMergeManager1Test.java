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

import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * Test the merge of the versioned program's listing.
 * Provides tests that create instructions and data in various combinations.
 * For tests with conflicts, checks selection of latest, my, or original code unit(s).
 */
public class CodeUnitMergeManager1Test extends AbstractListingMergeManagerTest {

	/**
	 * 
	 * @param arg0
	 */
	public CodeUnitMergeManager1Test() {
		super();
	}

@Test
    public void testAddLatestInstr() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
				// No changes.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e1")));
	}

@Test
    public void testAddMyInstr() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e1")));
	}

@Test
    public void testAddLatestData() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new WordDataType());
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
				// No changes.
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013da")));
	}

@Test
    public void testAddMyData() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// No changes.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testAddLatestInstrMyDataPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					createData(program, "0x10013d9", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013dc", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testAddLatestInstrMyDataPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					createData(program, "0x10013d9", new TerminatedStringDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e4", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e4")));
	}

@Test
    public void testAddLatestInstrMyDataPickOrig() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					createData(program, "0x10013d9", new TerminatedStringDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e4", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e4")));
	}

@Test
    public void testAddLatestDataMyInstrPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new TerminatedStringDataType());
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
					disassemble(program, "0x10013d9", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e4", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e4")));
	}

@Test
    public void testAddLatestDataMyInstrPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new DWordDataType());
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
					disassemble(program, "0x10013d9", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013dc", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testAddLatestDataMyInstrPickOrig() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new TerminatedStringDataType());
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
					disassemble(program, "0x10013d9", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e4", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e4")));
	}

@Test
    public void testAddLatestInstrMyInstrPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					disassemble(program, "0x10013da", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e2", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e2")));
	}

@Test
    public void testAddLatestInstrMyInstrPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					disassemble(program, "0x10013da", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e2", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e2")));
	}

@Test
    public void testAddLatestInstrMyInstrPickOrig() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					disassemble(program, "0x10013da", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013e2", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e2")));
	}

@Test
    public void testAddLatestDataMyDataPickLatest() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new WordDataType());
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
					createData(program, "0x10013d9", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013dc", KEEP_LATEST);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testAddLatestDataMyDataPickMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new WordDataType());
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
					createData(program, "0x10013d9", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013dc", KEEP_MY);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, myProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testAddLatestDataMyDataPickOrig() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new WordDataType());
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
					createData(program, "0x10013d9", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x10013d9", "0x10013dc", KEEP_ORIGINAL);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, originalProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testSameInstrLatestMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					disassemble(program, "0x10013d9", "0x10013e1");
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
					disassemble(program, "0x10013d9", "0x10013e1");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013e1")));
	}

@Test
    public void testSameDataLatestMy() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					createData(program, "0x10013d9", new DWordDataType());
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
					createData(program, "0x10013d9", new DWordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		assertSameCodeUnits(resultProgram, latestProgram, new AddressSet(addr("0x10013d9"),
			addr("0x10013dc")));
	}

@Test
    public void testMergeCodeUnitsOriginal() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Clear Code Units from 1002312 to 1002320
					program.getListing().clearCodeUnits(addr(program, "0x1002312"),
						addr(program, "0x1002320"), false);

					// Clear Code Units from 1002390 to 1002394
					program.getListing().clearCodeUnits(addr(program, "0x1002390"),
						addr(program, "0x1002394"), false);

					// Put a label @ from 10023be-10023c2 to create a conflict with the code unit.
					program.getSymbolTable().createLabel(addr(program, "0x10023be"), "LabelABC",
						SourceType.USER_DEFINED);

					// Put an Ascii at 10080d0
					program.getListing().createData(addr(program, "0x10080d0"), new CharDataType());

					// Put a Float at 10080db
					program.getListing().createData(addr(program, "0x10080db"), new FloatDataType());

					Memory mem = program.getMemory();
					MemoryBlock block = mem.getBlock(addr(program, "0x1001000"));

					try {
						// My Byte Changed @ 100652a causing a code unit change.
						Address addr = addr(program, "0x100652a");
						AddressSet addrSet = new AddressSet(addr, addr);
						program.getListing().clearCodeUnits(addr, addr, false);
						block.putByte(addr, (byte) 0x50);
						disassemble(program, addrSet, false);

					}
					catch (MemoryAccessException e) {
						Assert.fail(e.getMessage());
					}
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
					// Clear Code Units from 100231d to 1002328
					program.getListing().clearCodeUnits(addr(program, "0x100231d"),
						addr(program, "0x1002328"), false);
					assertTrue(!(program.getListing().getCodeUnitAt(addr(program, "0x1002328")) instanceof Instruction));

					// Put a comment @ 1002390-1002394 to create a conflict with the code unit.
					program.getListing().getCodeUnitAt(addr(program, "0x1002390")).setComment(
						CodeUnit.EOL_COMMENT, "EOL comment");

					// Clear Code Units from 10023be to 10023c2
					program.getListing().clearCodeUnits(addr(program, "0x10023be"),
						addr(program, "0x10023c2"), false);

					// Put a structure at 10080d0 to 10080d3
					StructureDataType struct = new StructureDataType("Item", 4);
					struct.replace(0, new CharDataType(), 1);
					program.getListing().createData(addr(program, "0x10080d0"), struct);

					// Put a Word at 10080e2
					program.getListing().createData(addr(program, "0x10080e2"), new WordDataType());

					// Clear Code Units from 100652a to 100652a
					program.getListing().clearCodeUnits(addr(program, "0x100652a"),
						addr(program, "0x100652a"), false);

					commit = true;
				}
				catch (CodeUnitInsertionException e) {
					e.printStackTrace();
				}
				catch (DataTypeConflictException e) {
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100652a", "0x100652b", KEEP_ORIGINAL);
		chooseCodeUnit("0x10080d0", "0x10080d3", KEEP_ORIGINAL);
		waitForMergeCompletion();

		AddressSet myAddrs = new AddressSet();
		// changed due to automerge of my changes.
		myAddrs.addRange(addr("0x100231d"), addr("0x1002328"));
		myAddrs.addRange(addr("0x10023be"), addr("0x10023c2"));
		myAddrs.addRange(addr("0x10080e2"), addr("0x10080e3"));
		assertSameCodeUnits(resultProgram, myProgram, myAddrs);

		AddressSet originalAddrs = new AddressSet();
		// changed due to manual merge.
		originalAddrs.addRange(addr("0x100652a"), addr("0x100652b"));
		originalAddrs.addRange(addr("0x10080d0"), addr("0x10080d3"));
		assertSameCodeUnits(resultProgram, originalProgram, originalAddrs);

		AddressSet latestAddrs =
			resultProgram.getMemory().subtract(myAddrs).subtract(originalAddrs);
		assertSameCodeUnits(resultProgram, latestProgram, latestAddrs);
	}

@Test
    public void testMergeCodeUnitsLatest() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Clear Code Units from 1002312 to 1002320
					program.getListing().clearCodeUnits(addr(program, "0x1002312"),
						addr(program, "0x1002320"), false);

					// Clear Code Units from 1002390 to 1002394
					program.getListing().clearCodeUnits(addr(program, "0x1002390"),
						addr(program, "0x1002394"), false);

					// Put a label @ from 10023be-10023c2 to create a conflict with the code unit.
					program.getSymbolTable().createLabel(addr(program, "0x10023be"), "LabelABC",
						SourceType.USER_DEFINED);

					// Put an Ascii at 10080d0
					program.getListing().createData(addr(program, "0x10080d0"), new CharDataType());

					// Put a Float at 10080db
					program.getListing().createData(addr(program, "0x10080db"), new FloatDataType());

					Memory mem = program.getMemory();
					MemoryBlock block = mem.getBlock(addr(program, "0x1001000"));

					try {
						// My Byte Changed @ 100652a causing a code unit change.
						Address addr = addr(program, "0x100652a");
						AddressSet addrSet = new AddressSet(addr, addr);
						program.getListing().clearCodeUnits(addr, addr, false);
						block.putByte(addr, (byte) 0x50);
						disassemble(program, addrSet, false);

					}
					catch (MemoryAccessException e) {
						Assert.fail(e.getMessage());
					}
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
					// Clear Code Units from 100231d to 1002328
					program.getListing().clearCodeUnits(addr(program, "0x100231d"),
						addr(program, "0x1002328"), false);
					assertTrue(!(program.getListing().getCodeUnitAt(addr(program, "0x1002328")) instanceof Instruction));

					// Put a comment @ 1002390-1002394 to create a conflict with the code unit.
					program.getListing().getCodeUnitAt(addr(program, "0x1002390")).setComment(
						CodeUnit.EOL_COMMENT, "EOL comment");

					// Clear Code Units from 10023be to 10023c2
					program.getListing().clearCodeUnits(addr(program, "0x10023be"),
						addr(program, "0x10023c2"), false);

					// Put a structure at 10080d0 to 10080d3
					StructureDataType struct = new StructureDataType("Item", 4);
					struct.replace(0, new CharDataType(), 1);
					program.getListing().createData(addr(program, "0x10080d0"), struct);

					// Put a Word at 10080e2
					program.getListing().createData(addr(program, "0x10080e2"), new WordDataType());

					// Clear Code Units from 100652a to 100652a
					program.getListing().clearCodeUnits(addr(program, "0x100652a"),
						addr(program, "0x100652a"), false);

					commit = true;
				}
				catch (CodeUnitInsertionException e) {
					e.printStackTrace();
				}
				catch (DataTypeConflictException e) {
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER); // auto set is [0100231d, 01002328] [010023be, 010023c2] [010080e2, 010080e3]
		chooseCodeUnit("0x100652a", "0x100652b", KEEP_LATEST);
		chooseCodeUnit("0x10080d0", "0x10080d3", KEEP_LATEST);
		waitForMergeCompletion();

		AddressSet myAddrs = new AddressSet();
		// changed due to automerge of my changes.
		myAddrs.addRange(addr("0x100231d"), addr("0x1002328"));
		myAddrs.addRange(addr("0x10023be"), addr("0x10023c2"));
		myAddrs.addRange(addr("0x10080e2"), addr("0x10080e3"));
		assertSameCodeUnits(resultProgram, myProgram, myAddrs);

		AddressSet latestAddrs = resultProgram.getMemory().subtract(myAddrs);
		assertSameCodeUnits(resultProgram, latestProgram, latestAddrs);

	}

@Test
    public void testMergeCodeUnitsMine() throws Exception {
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Clear Code Units from 1002312 to 1002320
					program.getListing().clearCodeUnits(addr(program, "0x1002312"),
						addr(program, "0x1002320"), false);

					// Clear Code Units from 1002390 to 1002394
					program.getListing().clearCodeUnits(addr(program, "0x1002390"),
						addr(program, "0x1002394"), false);

					// Put a label @ from 10023be-10023c2 to create a conflict with the code unit.
					program.getSymbolTable().createLabel(addr(program, "0x10023be"), "LabelABC",
						SourceType.USER_DEFINED);

					// Put an Ascii at 10080d0
					program.getListing().createData(addr(program, "0x10080d0"), new CharDataType());

					// Put a Float at 10080db
					program.getListing().createData(addr(program, "0x10080db"), new FloatDataType());

					Memory mem = program.getMemory();
					MemoryBlock block = mem.getBlock(addr(program, "0x1001000"));

					try {
						// My Byte Changed @ 100652a causing a code unit change.
						Address addr = addr(program, "0x100652a");
						AddressSet addrSet = new AddressSet(addr, addr);
						program.getListing().clearCodeUnits(addr, addr, false);
						block.putByte(addr, (byte) 0x50);
						disassemble(program, addrSet, false);

					}
					catch (MemoryAccessException e) {
						Assert.fail(e.getMessage());
					}
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
					// Clear Code Units from 100231d to 1002328
					program.getListing().clearCodeUnits(addr(program, "0x100231d"),
						addr(program, "0x1002328"), false);
					assertTrue(!(program.getListing().getCodeUnitAt(addr(program, "0x1002328")) instanceof Instruction));

					// Put a comment @ 1002390-1002394 to create a conflict with the code unit.
					program.getListing().getCodeUnitAt(addr(program, "0x1002390")).setComment(
						CodeUnit.EOL_COMMENT, "EOL comment");

					// Clear Code Units from 10023be to 10023c2
					program.getListing().clearCodeUnits(addr(program, "0x10023be"),
						addr(program, "0x10023c2"), false);

					// Put a structure at 10080d0 to 10080d3
					StructureDataType struct = new StructureDataType("Item", 4);
					struct.replace(0, new CharDataType(), 1);
					program.getListing().createData(addr(program, "0x10080d0"), struct);

					// Put a Word at 10080e2
					program.getListing().createData(addr(program, "0x10080e2"), new WordDataType());

					// Clear Code Units from 100652a to 100652a
					program.getListing().clearCodeUnits(addr(program, "0x100652a"),
						addr(program, "0x100652a"), false);

					commit = true;
				}
				catch (CodeUnitInsertionException e) {
					e.printStackTrace();
				}
				catch (DataTypeConflictException e) {
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

//		mergeMgr.setConflictDecision(ListingMergeManager.KEEP_MY);
//		mergeMgr.merge(monitor);
		executeMerge(ASK_USER);
		chooseCodeUnit("0x100652a", "0x100652b", KEEP_MY);
		chooseCodeUnit("0x10080d0", "0x10080d3", KEEP_MY);
		waitForMergeCompletion();

		AddressSet myAddrs = new AddressSet();
		// changed due to automerge of my changes.
		myAddrs.addRange(addr("0x100231d"), addr("0x1002328"));
		myAddrs.addRange(addr("0x10023be"), addr("0x10023c2"));
		myAddrs.addRange(addr("0x10080e2"), addr("0x10080e3"));
		// changed due to manual merge.
		myAddrs.addRange(addr("0x100652a"), addr("0x100652b"));
		myAddrs.addRange(addr("0x10080d0"), addr("0x10080d3"));
		assertSameCodeUnits(resultProgram, myProgram, myAddrs);

		AddressSet latestAddrs = resultProgram.getMemory().subtract(myAddrs);
		assertSameCodeUnits(resultProgram, latestProgram, latestAddrs);
	}

@Test
    public void testMergeCodeUnitsUseForAllPickLatest() throws Exception {
		setupUseForAll();

		executeMerge(ASK_USER); // auto set is [0100231d, 01002328] [010023be, 010023c2] [010080e2, 010080e3]
		chooseCodeUnit("0x100652a", "0x100652b", KEEP_LATEST, true);
//		chooseCodeUnit("0x10080d0", "0x10080d3", KEEP_LATEST, false); // UseForAll will do this.
		waitForMergeCompletion();

		AddressSet myAddrs = new AddressSet();
		// changed due to automerge of my changes.
		myAddrs.addRange(addr("0x100231d"), addr("0x1002328"));
		myAddrs.addRange(addr("0x10023be"), addr("0x10023c2"));
		myAddrs.addRange(addr("0x10080e2"), addr("0x10080e3"));
		assertSameCodeUnits(resultProgram, myProgram, myAddrs);

		AddressSet latestAddrs = resultProgram.getMemory().subtract(myAddrs);
		assertSameCodeUnits(resultProgram, latestProgram, latestAddrs);

	}

	private void setupUseForAll() throws Exception {
		mtf.initialize("DiffTestPgm1", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					// Clear Code Units from 1002312 to 1002320
					program.getListing().clearCodeUnits(addr(program, "0x1002312"),
						addr(program, "0x1002320"), false);

					// Clear Code Units from 1002390 to 1002394
					program.getListing().clearCodeUnits(addr(program, "0x1002390"),
						addr(program, "0x1002394"), false);

					// Put a label @ from 10023be-10023c2 to create a conflict with the code unit.
					program.getSymbolTable().createLabel(addr(program, "0x10023be"), "LabelABC",
						SourceType.USER_DEFINED);

					// Put an Ascii at 10080d0
					program.getListing().createData(addr(program, "0x10080d0"), new CharDataType());

					// Put a Float at 10080db
					program.getListing().createData(addr(program, "0x10080db"), new FloatDataType());

					Memory mem = program.getMemory();
					MemoryBlock block = mem.getBlock(addr(program, "0x1001000"));

					try {
						// My Byte Changed @ 100652a causing a code unit change.
						Address addr = addr(program, "0x100652a");
						AddressSet addrSet = new AddressSet(addr, addr);
						program.getListing().clearCodeUnits(addr, addr, false);
						block.putByte(addr, (byte) 0x50);
						disassemble(program, addrSet, false);

					}
					catch (MemoryAccessException e) {
						Assert.fail(e.getMessage());
					}
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
					// Clear Code Units from 100231d to 1002328
					program.getListing().clearCodeUnits(addr(program, "0x100231d"),
						addr(program, "0x1002328"), false);
					assertTrue(!(program.getListing().getCodeUnitAt(addr(program, "0x1002328")) instanceof Instruction));

					// Put a comment @ 1002390-1002394 to create a conflict with the code unit.
					program.getListing().getCodeUnitAt(addr(program, "0x1002390")).setComment(
						CodeUnit.EOL_COMMENT, "EOL comment");

					// Clear Code Units from 10023be to 10023c2
					program.getListing().clearCodeUnits(addr(program, "0x10023be"),
						addr(program, "0x10023c2"), false);

					// Put a structure at 10080d0 to 10080d3
					StructureDataType struct = new StructureDataType("Item", 4);
					struct.replace(0, new CharDataType(), 1);
					program.getListing().createData(addr(program, "0x10080d0"), struct);

					// Put a Word at 10080e2
					program.getListing().createData(addr(program, "0x10080e2"), new WordDataType());

					// Clear Code Units from 100652a to 100652a
					program.getListing().clearCodeUnits(addr(program, "0x100652a"),
						addr(program, "0x100652a"), false);

					commit = true;
				}
				catch (CodeUnitInsertionException e) {
					e.printStackTrace();
				}
				catch (DataTypeConflictException e) {
					e.printStackTrace();
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});
	}

@Test
    public void testMergeCodeUnitsUseForAllPickMine() throws Exception {
		setupUseForAll();

		executeMerge(ASK_USER);
		chooseCodeUnit("0x100652a", "0x100652b", KEEP_MY, true);
//		chooseCodeUnit("0x10080d0", "0x10080d3", KEEP_MY, false); // UseForAll will do this.
		waitForMergeCompletion();

		AddressSet myAddrs = new AddressSet();
		// changed due to automerge of my changes.
		myAddrs.addRange(addr("0x100231d"), addr("0x1002328"));
		myAddrs.addRange(addr("0x10023be"), addr("0x10023c2"));
		myAddrs.addRange(addr("0x10080e2"), addr("0x10080e3"));
		// changed due to manual merge.
		myAddrs.addRange(addr("0x100652a"), addr("0x100652b"));
		myAddrs.addRange(addr("0x10080d0"), addr("0x10080d3"));
		assertSameCodeUnits(resultProgram, myProgram, myAddrs);

		AddressSet latestAddrs = resultProgram.getMemory().subtract(myAddrs);
		assertSameCodeUnits(resultProgram, latestProgram, latestAddrs);
	}

}
