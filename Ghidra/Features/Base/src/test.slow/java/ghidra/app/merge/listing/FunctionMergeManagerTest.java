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
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the merge of the versioned program's listing.
 */
public class FunctionMergeManagerTest extends AbstractListingMergeManagerTest {

	// *** NotepadMergeListingTest ***
	// 01001978     no function 
	// 0100299e		no function
	// 01002a91		FUN_01002a91	body:1002a91-1002b43
	// 01002b44		FUN_01002b44	body:1002b44-1002b7c
	// 01002b7d		FUN_01002b7d	body:1002b7d-1002c92
	// 01002c93		FUN_01002c93	body:1002c93-1002cf4
	// 01002cf5		FUN_01002cf5	body:1002cf5-1002d6d
	// 01002f01		FUN_01002f01	body:1002f01-10030c5
	// 010031ee		FUN_010031ee	body:10031ee-100324f
	// 01003250		FUN_01003250	body:1003250-10032d4
	// 01003bed		FUN_01003bed	body:1003bed-1003efb
	// 01005c6f		FUN_01005c6f	body:[1005c6f-1005fbd][1005ff5-10061e2]
	// 01006420		entry			body:[1006420-1006581][10065a4-10065cd]

	@Test
	public void testChangeLatestRemoveMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x10031ee");
					func.addLocalVariable(
						new LocalVariableImpl("local_24", new DWordDataType(), -24, program),
						SourceType.USER_DEFINED);
					func = getFunction(program, "0x1003bed");
					func.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					commit = true;
				}
				catch (DuplicateNameException e) {
					e.printStackTrace();
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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x10031ee");
					removeFunction(program, "0x1003bed");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		verticalChooseFunction("0x10031ee", KEEP_LATEST);
		verticalChooseFunction("0x1003bed", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body10031ee = new AddressSet(addr("0x10031ee"), addr("0x100324f"));
		checkFunction(resultProgram, "0x10031ee", "FUN_010031ee", body10031ee);
		noFunction(resultProgram, "0x1003bed");
	}

	@Test
	public void testChangeLatestRemoveMyOverlapConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// 0100299e		FUN_0100299e	body:100299e-1002a90
			// 01002a91		FUN_01002a91	body:1002a91-1002b43
			// 01002b44		FUN_01002b44	body:1002b44-1002b7c
			// 01002b7d		FUN_01002b7d	body:1002b7d-1002c92
			// 01002c93		FUN_01002c93	body:1002c93-1002cf4
			// 01002cf5		FUN_01002cf5	body:1002cf5-1002d6d
			// 01002f01		FUN_01002f01	body:1002f01-10030c5
			// 010031ee		FUN_010031ee	body:10031ee-100324f
			// 01003250		FUN_01003250	body:1003250-10032d4
			// 01003bed		FUN_01003bed	body:1003bed-1003efb
			// 01005c6f		FUN_01005c6f	body:[1005c6f-1005fbd][1005ff5-10061e2]
			// 01006420		entry			body:[1006420-1006581][10065a4-10065cd]

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x1002a91");
					removeFunction(program, "0x1002b44");
					AddressSet body1002a91 =
						new AddressSet(addr(program, "0x1002a91"), addr(program, "0x1002b49"));
					createFunction(program, "0x1002a91", "FUN_01002a91", body1002a91);

					removeFunction(program, "0x1002b7d");
					removeFunction(program, "0x1002c93");
					AddressSet body1002b7d =
						new AddressSet(addr(program, "0x1002b7d"), addr(program, "0x1002c9c"));
					createFunction(program, "0x1002b7d", "FUN_01002b7d", body1002b7d);

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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x1002a91");
					Function func = getFunction(program, "0x1002b44");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);

					removeFunction(program, "0x1002b7d");
					func = getFunction(program, "0x1002c93");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x1002a91", KEEP_LATEST);
		horizontalChooseFunction("0x1002b7d", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body1002a91 = new AddressSet(addr("0x1002a91"), addr("0x1002b49"));
		checkFunction(resultProgram, "0x1002a91", "FUN_01002a91", body1002a91);
		noFunction(resultProgram, "0x1002b44");

		noFunction(resultProgram, "0x1002b7d");
		AddressSet body1002c93 = new AddressSet(addr("0x1002c93"), addr("0x1002cf4"));
		checkFunction(resultProgram, "0x1002c93", "FUN_01002c93", body1002c93);
	}

	@Test
	public void testChangeLatestRemoveMyOverlapOK() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			// 0100299e		FUN_0100299e	body:100299e-1002a90
			// 01002a91		FUN_01002a91	body:1002a91-1002b43
			// 01002b44		FUN_01002b44	body:1002b44-1002b7c
			// 01002b7d		FUN_01002b7d	body:1002b7d-1002c92
			// 01002c93		FUN_01002c93	body:1002c93-1002cf4
			// 01002cf5		FUN_01002cf5	body:1002cf5-1002d6d
			// 01002f01		FUN_01002f01	body:1002f01-10030c5
			// 010031ee		FUN_010031ee	body:10031ee-100324f
			// 01003250		FUN_01003250	body:1003250-10032d4
			// 01003bed		FUN_01003bed	body:1003bed-1003efb
			// 01005c6f		FUN_01005c6f	body:[1005c6f-1005fbd][1005ff5-10061e2]
			// 01006420		entry			body:[1006420-1006581][10065a4-10065cd]

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x1002a91");
					removeFunction(program, "0x1002b44");
					AddressSet body1002a91 =
						new AddressSet(addr(program, "0x1002a91"), addr(program, "0x1002b49"));
					createFunction(program, "0x1002a91", "FUN_01002a91", body1002a91);

					removeFunction(program, "0x1002b7d");
					removeFunction(program, "0x1002c93");
					AddressSet body1002b7d =
						new AddressSet(addr(program, "0x1002b7d"), addr(program, "0x1002c92"));
					createFunction(program, "0x1002b7d", "FUN_01002b7d", body1002b7d);

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
					removeFunction(program, "0x1002a91");
					removeFunction(program, "0x1002b7d");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		verticalChooseFunction("0x1002a91", KEEP_LATEST);
		verticalChooseFunction("0x1002b7d", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body1002a91 = new AddressSet(addr("0x1002a91"), addr("0x1002b49"));
		checkFunction(resultProgram, "0x1002a91", "FUN_01002a91", body1002a91);
		noFunction(resultProgram, "0x1002b44");

		noFunction(resultProgram, "0x1002b7d");
		noFunction(resultProgram, "0x1002c93");
	}

	@Test
	public void testAddSame() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
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
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
	}

	@Test
	public void testAddLatest() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
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
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
	}

	@Test
	public void testAddMy() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
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
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
	}

	@Test
	public void testAddLatestOverlapConflict() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

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
					removeFunction(program, "0x100194b");
					AddressSet body100194b =
						new AddressSet(addr(program, "0x100194b"), addr(program, "0x100197f"));
					createFunction(program, "0x100194b", "FUN_0100194b", body100194b);

					removeFunction(program, "0x1002950");
					AddressSet body1002950 =
						new AddressSet(addr(program, "0x1002950"), addr(program, "0x10029a4"));
					createFunction(program, "0x1002950", "FUN_01002950", body1002950);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x100194b", KEEP_LATEST);
		horizontalChooseFunction("0x1002950", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body100194b = new AddressSet(addr("0x100194b"), addr("0x1001977"));
		checkFunction(resultProgram, "0x100194b", "FUN_0100194b", body100194b);
		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);

		AddressSet body1002950 = new AddressSet(addr("0x1002950"), addr("0x10029a4"));
		checkFunction(resultProgram, "0x1002950", "FUN_01002950", body1002950);
		noFunction(resultProgram, "0x10029a1");
	}

	@Test
	public void testAddMyOverlapConflict() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		no FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		no FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x100194b");
					AddressSet body100194b =
						new AddressSet(addr(program, "0x100194b"), addr(program, "0x100197f"));
					createFunction(program, "0x100194b", "FUN_0100194b", body100194b);

					removeFunction(program, "0x1002950");
					AddressSet body1002950 =
						new AddressSet(addr(program, "0x1002950"), addr(program, "0x10029a4"));
					createFunction(program, "0x1002950", "FUN_01002950", body1002950);

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
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x100194b", KEEP_LATEST);
		horizontalChooseFunction("0x1002950", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body100194b = new AddressSet(addr("0x100194b"), addr("0x100197f"));
		checkFunction(resultProgram, "0x100194b", "FUN_0100194b", body100194b);
		noFunction(resultProgram, "0x1001979");

		AddressSet body1002950 = new AddressSet(addr("0x1002950"), addr("0x100299d"));
		checkFunction(resultProgram, "0x1002950", "FUN_01002950", body1002950);
		AddressSet body10029a1 = new AddressSet(addr("0x10029a1"), addr("0x10029ca"));
		checkFunction(resultProgram, "0x10029a1", "FUN_010029a1", body10029a1);
	}

	@Test
	public void testAddLatestOverlapOK() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		no FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		no FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x1001ae3");
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x1001b00"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					removeFunction(program, "0x1002a91");
					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x1002a99"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

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
				// Empty
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x1001b00"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		noFunction(resultProgram, "0x1001ae3");

		AddressSet body10029a1 = new AddressSet(addr("0x10029a1"), addr("0x1002a99"));
		checkFunction(resultProgram, "0x10029a1", "FUN_010029a1", body10029a1);
		noFunction(resultProgram, "0x1002a91");
	}

	@Test
	public void testAddMyOverlapOK() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		no FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		no FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// Empty
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x1001ae3");
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x1001b00"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					removeFunction(program, "0x1002a91");
					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x1002a99"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x1001b00"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		noFunction(resultProgram, "0x1001ae3");

		AddressSet body10029a1 = new AddressSet(addr("0x10029a1"), addr("0x1002a99"));
		checkFunction(resultProgram, "0x10029a1", "FUN_010029a1", body10029a1);
		noFunction(resultProgram, "0x1002a91");
	}

	@Test
	public void testAddBothDiffEntryOverlapConflict() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

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
					AddressSet body1001984 =
						new AddressSet(addr(program, "0x1001984"), addr(program, "0x100198a"));
					createFunction(program, "0x1001984", "FUN_01001984", body1001984);

					AddressSet body10029bc =
						new AddressSet(addr(program, "0x10029bc"), addr(program, "0x10029d3"));
					createFunction(program, "0x10029bc", "FUN_010029bc", body10029bc);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x1001979", KEEP_LATEST);
		horizontalChooseFunction("0x10029a1", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		noFunction(resultProgram, "0x1001984");

		AddressSet body10029bc = new AddressSet(addr("0x10029bc"), addr("0x10029d3"));
		checkFunction(resultProgram, "0x10029bc", "FUN_010029bc", body10029bc);
		noFunction(resultProgram, "0x10029a1");
	}

	@Test
	public void testAddBothSameEntryOverlapConflict() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

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
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100198a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029d3"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		verticalChooseFunction("0x1001979", KEEP_LATEST);
		verticalChooseFunction("0x10029a1", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);

		AddressSet body10029a1 = new AddressSet(addr("0x10029a1"), addr("0x10029d3"));
		checkFunction(resultProgram, "0x10029a1", "FUN_010029a1", body10029a1);
	}

	@Test
	public void testAddDiffReturnType() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setReturnType(Undefined2DataType.dataType, SourceType.ANALYSIS);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setReturnType(Undefined2DataType.dataType, SourceType.ANALYSIS);

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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setReturnType(WordDataType.dataType, SourceType.ANALYSIS);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setReturnType(WordDataType.dataType, SourceType.ANALYSIS);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		chooseRadioButton(LATEST_BUTTON_NAME); // byte return type for function at 0x01001979
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // float return type for function at 0x10029a1
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		Function func = getFunction(resultProgram, "0x1001979");
		assertTrue(new Undefined2DataType().isEquivalent(func.getReturnType()));

		func = getFunction(resultProgram, "0x10029a1");
		assertSameDataType(new WordDataType(), func.getReturnType());
	}

	@Test
	public void testAddDiffCustomReturnTypeToNonCustomStorage() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setReturnType(new Undefined2DataType(), SourceType.ANALYSIS);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setCustomVariableStorage(true);
					func.setReturn(new Undefined2DataType(),
						new VariableStorage(program, program.getRegister("r0l")),
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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setCustomVariableStorage(true);
					func.setReturn(new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")),
						SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setCustomVariableStorage(true);
					func.setReturn(new Undefined2DataType(),
						new VariableStorage(program, program.getRegister("r1l")),
						SourceType.USER_DEFINED);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseVariousOptions("0x1001979", new int[] { INFO_ROW, KEEP_LATEST }); // non-custom storage
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // custom float return type for function at 0x01001979
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // custom byte return type for function at 0x10029a1
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);

		Function func = getFunction(resultProgram, "0x1001979");
		assertTrue(func.hasCustomVariableStorage());
		assertTrue(new WordDataType().isEquivalent(func.getReturnType()));
		// Calling convention will cause the storage to allocate 10 bytes.
		assertEquals("r0l:2", func.getReturn().getVariableStorage().toString()); // reflects dynamic storage 

		func = getFunction(resultProgram, "0x10029a1");
		assertSameDataType(new Undefined2DataType(), func.getReturnType());
		assertEquals("r1l:2", func.getReturn().getVariableStorage().toString());
	}

	@Test
	public void testAddDiffNonCustomReturnTypeToCustomStorage() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setReturnType(new Undefined2DataType(), SourceType.ANALYSIS);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setCustomVariableStorage(true);
					func.setReturn(new Undefined2DataType(),
						new VariableStorage(program, program.getRegister("r0l")),
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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setCustomVariableStorage(true);
					func.setReturn(new WordDataType(),
						new VariableStorage(program, program.getRegister("r0l")),
						SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setCustomVariableStorage(true);
					func.setReturn(new Undefined2DataType(),
						new VariableStorage(program, program.getRegister("r1l")),
						SourceType.USER_DEFINED);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseVariousOptions("0x1001979", new int[] { INFO_ROW, KEEP_MY }); // custom storage
		chooseRadioButton(LATEST_BUTTON_NAME); // non-custom byte return type for function at 0x01001979
		chooseRadioButton(LATEST_BUTTON_NAME); // custom byte return type for function at 0x10029a1
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);

		Function func = getFunction(resultProgram, "0x1001979");
		assertFalse(func.hasCustomVariableStorage());
		assertTrue(new Undefined2DataType().isEquivalent(func.getReturnType()));
		assertEquals("r12l:2", func.getReturn().getVariableStorage().toString());

		func = getFunction(resultProgram, "0x10029a1");
		assertSameDataType(new Undefined2DataType(), func.getReturnType());
		assertEquals("r0l:2", func.getReturn().getVariableStorage().toString());
	}

	@Test
	public void testAddDiffCustomCompoundReturnType() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setReturnType(new IntegerDataType(), SourceType.ANALYSIS);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setCustomVariableStorage(true);
					func.setReturn(new IntegerDataType(),
						new VariableStorage(program, program.getRegister("EBX")),
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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setCustomVariableStorage(true);
					func.setReturn(new FloatDataType(),
						new VariableStorage(program, program.getRegister("AX"),
							program.getRegister("BL"), program.getRegister("CL")),
						SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setCustomVariableStorage(true);
					func.setReturn(new IntegerDataType(),
						new VariableStorage(program, program.getRegister("ECX")),
						SourceType.USER_DEFINED);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
//		chooseVariousOptions("0x1001979", new int[] { INFO_ROW, KEEP_MY }); // custom storage
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // custom float return type for function at 0x01001979
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // custom float return type for function at 0x10029a1
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);

		Function func = getFunction(resultProgram, "0x1001979");
		assertTrue(new FloatDataType().isEquivalent(func.getReturnType()));
		assertEquals("AX:2,BL:1,CL:1", func.getReturn().getVariableStorage().toString()); // reflects dynamic storage

		func = getFunction(resultProgram, "0x10029a1");
		assertSameDataType(new IntegerDataType(), func.getReturnType());
		assertEquals("ECX:4", func.getReturn().getVariableStorage().toString());
	}

	@Test
	public void testAddDiffParameters() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		final Parameter[] latest_Parm1 = new Parameter[1];
		final Parameter[] latest_Parm2 = new Parameter[1];
		final Parameter[] latest_p1 = new Parameter[1];
		final Parameter[] latest_p2 = new Parameter[1];
		final Parameter[] my_Parm1 = new Parameter[1];
		final Parameter[] my_Parm2 = new Parameter[1];
		final Parameter[] my_count = new Parameter[1];
		final Parameter[] my_offset = new Parameter[1];
		final Parameter[] my_increment = new Parameter[1];

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latest_Parm1[0] = new MyParameter("Parm1", 0, new DWordDataType(), 4, program);
					latest_Parm2[0] = new MyParameter("Parm2", 1, new WordDataType(), 8, program);
					latest_p1[0] = new MyParameter("p1", 0, new ByteDataType(), 4, program);
					latest_p2[0] = new MyParameter("p2", 1, new WordDataType(), 8, program);

					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.addParameter(latest_Parm1[0], SourceType.USER_DEFINED);
					func.addParameter(latest_Parm2[0], SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.addParameter(latest_p1[0], SourceType.USER_DEFINED);
					func.addParameter(latest_p2[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (DuplicateNameException e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				catch (InvalidInputException e) {
					e.printStackTrace();
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
					my_Parm1[0] = new MyParameter("Parm1", 0, new FloatDataType(), 4, program);
					my_Parm2[0] = new MyParameter("Parm2", 1, new WordDataType(), 8, program);
					my_count[0] = new MyParameter("count", 0, new ByteDataType(), 4, program);
					my_offset[0] = new MyParameter("offset", 1, new WordDataType(), 8, program);
					my_increment[0] =
						new MyParameter("increment", 2, new DWordDataType(), 12, program);

					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.addParameter(my_Parm1[0], SourceType.USER_DEFINED);
					func.addParameter(my_Parm2[0], SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.addParameter(my_count[0], SourceType.USER_DEFINED);
					func.addParameter(my_offset[0], SourceType.USER_DEFINED);
					func.addParameter(my_increment[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (DuplicateNameException e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				catch (InvalidInputException e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1001979", new int[] { INFO_ROW, KEEP_LATEST }); // dword vs float
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // signature conflict at 0x10029a1
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		Function func = getFunction(resultProgram, "0x1001979");
		Parameter[] parms = func.getParameters();
		assertEquals(2, parms.length);
		assertEquals(latest_Parm1[0], parms[0]);
		assertEquals(latest_Parm2[0], parms[1]);

		func = getFunction(resultProgram, "0x10029a1");
		parms = func.getParameters();
		assertEquals(3, parms.length);
		assertEquals(my_count[0], parms[0]);
		assertEquals(my_offset[0], parms[1]);
		assertEquals(my_increment[0], parms[2]);
	}

	@Test
	public void testAddDiffLocalVarsPickLatestAndMy() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		final Variable[] latestLocal4 = new Variable[1];
		final Variable[] latestLocal8 = new Variable[1];
		final Variable[] latestLocalC = new Variable[1];
		final Variable[] myLocal4 = new Variable[1];
		final Variable[] myLocala = new Variable[1];
		final Variable[] myLocal30 = new Variable[1];

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latestLocal4[0] =
						new LocalVariableImpl("local_4", new ByteDataType(), -4, program);
					latestLocal8[0] =
						new LocalVariableImpl("local_8", new Undefined4DataType(), -8, program);
					latestLocalC[0] =
						new LocalVariableImpl("local_c", new ByteDataType(), -0xc, program);

					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979"); // has single param at 0xc?
					func.addLocalVariable(latestLocal4[0], SourceType.USER_DEFINED);
					func.addLocalVariable(latestLocal8[0], SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.addLocalVariable(latestLocalC[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
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
					myLocal4[0] = new LocalVariableImpl("local_4", new WordDataType(), -4, program);
					myLocala[0] =
						new LocalVariableImpl("local_a", new Undefined4DataType(), -0xa, program);
					myLocal30[0] =
						new LocalVariableImpl("local_30", new ByteDataType(), -0x30, program);

					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.addLocalVariable(myLocal4[0], SourceType.USER_DEFINED);
					func.addLocalVariable(myLocala[0], SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.addLocalVariable(myLocal30[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseListRadioButton(LATEST_LIST_BUTTON_NAME); // stack overlap: -0x4:1 vs. -0x4:2 @ 01001979 - pick LATEST
		chooseListRadioButton(CHECKED_OUT_LIST_BUTTON_NAME); // stack overlap: -0xa:4 vs. -0x8:4 @ 01001979 - pick CHECKED_OUT

		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		Function func = getFunction(resultProgram, "0x1001979");
		Variable[] vars = func.getLocalVariables();
		assertEquals(2, vars.length);
		assertEquals(latestLocal4[0], vars[0]);
		assertEquals(myLocala[0], vars[1]);

		func = getFunction(resultProgram, "0x10029a1");
		vars = func.getLocalVariables();
		assertEquals(2, vars.length);
		assertEquals(latestLocalC[0], vars[0]);
		assertEquals(myLocal30[0], vars[1]);
	}

	@Test
	public void testAddDiffLocalVarsPickMy() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		final Variable[] latestLocal4 = new Variable[1];
		final Variable[] latestLocal8 = new Variable[1];
		final Variable[] latestLocalC = new Variable[1];
		final Variable[] myLocal4 = new Variable[1];
		final Variable[] myLocala = new Variable[1];
		final Variable[] myLocal30 = new Variable[1];

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latestLocal4[0] =
						new LocalVariableImpl("local_4", new ByteDataType(), -4, program);
					latestLocal8[0] =
						new LocalVariableImpl("local_8", new Undefined4DataType(), -8, program);
					latestLocalC[0] =
						new LocalVariableImpl("local_c", new ByteDataType(), -0xc, program);

					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979"); // has single param at 0xc?
					func.addLocalVariable(latestLocal4[0], SourceType.USER_DEFINED);
					func.addLocalVariable(latestLocal8[0], SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.addLocalVariable(latestLocalC[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
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
					myLocal4[0] = new LocalVariableImpl("local_4", new WordDataType(), -4, program);
					myLocala[0] =
						new LocalVariableImpl("local_a", new Undefined4DataType(), -0xa, program);
					myLocal30[0] =
						new LocalVariableImpl("local_30", new ByteDataType(), -0x30, program);

					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.addLocalVariable(myLocal4[0], SourceType.USER_DEFINED);
					func.addLocalVariable(myLocala[0], SourceType.USER_DEFINED);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.addLocalVariable(myLocal30[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseListRadioButton(CHECKED_OUT_LIST_BUTTON_NAME); // stack overlap: -0x4:1 vs. -0x4:2 @ 01001979 - pick CHECKED_OUT
		chooseListRadioButton(CHECKED_OUT_LIST_BUTTON_NAME); // stack overlap: -0xa:4 vs. -0x8:4 @ 01001979 - pick CHECKED_OUT
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		Function func = getFunction(resultProgram, "0x1001979");
		Variable[] vars = func.getLocalVariables();
		assertEquals(2, vars.length);
		assertEquals(myLocal4[0], vars[0]);
		assertEquals(myLocala[0], vars[1]);

		func = getFunction(resultProgram, "0x10029a1");
		vars = func.getLocalVariables();
		assertEquals(2, vars.length);
		assertEquals(latestLocalC[0], vars[0]);
		assertEquals(myLocal30[0], vars[1]);
	}

	@Test
	public void testAddStackParamConflict() throws Exception {
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43
		// 01002b44		FUN_01002b44	body:1002b44-1002b7c
		// 01002b7d		FUN_01002b7d	body:1002b7d-1002c92
		// 01002c93		FUN_01002c93	body:1002c93-1002cf4
		// 01002cf5		FUN_01002cf5	body:1002cf5-1002d6d
		// 01002f01		FUN_01002f01	body:1002f01-10030c5
		// 010031ee		FUN_010031ee	body:10031ee-100324f
		// 01003250		FUN_01003250	body:1003250-10032d4
		// 01003bed		FUN_01003bed	body:1003bed-1003efb
		// 01005c6f		FUN_01005c6f	body:[1005c6f-1005fbd][1005ff5-10061e2]
		// 01006420		entry			body:[1006420-1006581][10065a4-10065cd]

		final Parameter[] latest3 = new Parameter[1];
		final Parameter[] latest1 = new Parameter[1];
		final Parameter[] my3 = new Parameter[1];
		final Parameter[] my1 = new Parameter[1];

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latest3[0] = new MyParameter("elm", 3, new WordDataType(), 20, program);
					latest1[0] = new MyParameter("pine", 1, new Undefined4DataType(), 8, program);

					Function func;
					func = getFunction(program, "0x1002b44");
					func.setCustomVariableStorage(true);
					func.addParameter(latest1[0], SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002c93");
					func.setCustomVariableStorage(true);
					func.addParameter(latest3[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
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
					my3[0] = new MyParameter("three", 3, new FloatDataType(), 24, program);
					my1[0] = new MyParameter("one", 1, new ByteDataType(), 8, program);

					Function func;
					func = getFunction(program, "0x1002b44");
					func.setCustomVariableStorage(true);
					func.addParameter(my1[0], SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002c93");
					func.setCustomVariableStorage(true);
					func.addParameter(my3[0], SourceType.USER_DEFINED);

					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);

		// first case has storage conflict due to different size params
		chooseListRadioButton(CHECKED_OUT_LIST_BUTTON_NAME); // 0x1002b44 - KEEP_MY

		// second case has signature conflict since all param storage matches but datatype(s) differ (float vs. undefined4)
		chooseRadioButton(LATEST_BUTTON_NAME);

		waitForMergeCompletion();

		Function func;
		func = getFunction(resultProgram, "0x1002b44");
		assertEquals(2, func.getParameters().length);
		assertEquals(my1[0], func.getParameter(1));

		func = getFunction(resultProgram, "0x1002c93");
		assertEquals(4, func.getParameters().length);
		assertEquals(latest3[0], func.getParameter(3));
	}

	@Test
	public void testChangeParamTypeConflict() throws Exception {
		// FUTURE test to change stack param to reg param & vice versa.
	}

	@Test
	public void testAddVarArgNoConflict() throws Exception {
		// 0x010018cf	"undefined FUN_010018cf(...)"
		// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
		// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
		// 0x01004068	"undefined FUN_01004068(undefined4 param_1, ...)"
		// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
		// 0x01004c1d	"undefined FUN_01004c1d(undefined4 param_1, undefined4 param_2, ...)"
		// 0x010058b8	"undefined FUN_010058b8(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, ...)"

		mtf.initialize("notepad.exe_3.1_w_DotDotDot", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
					// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
					// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
					Function func;
					func = getFunction(program, "0x0100194b");
					func.setVarArgs(true);
					func = getFunction(program, "0x01004a15");
					func.setVarArgs(true);

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
					// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
					// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
					// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
					Function func;
					func = getFunction(program, "0x0100299e");
					func.setVarArgs(true);
					func = getFunction(program, "0x01004a15");
					func.setVarArgs(true);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		Function func;
		func = getFunction(resultProgram, "0x0100194b");
		assertEquals(true, func.hasVarArgs());
		func = getFunction(resultProgram, "0x0100299e");
		assertEquals(true, func.hasVarArgs());
		func = getFunction(resultProgram, "0x01004a15");
		assertEquals(true, func.hasVarArgs());
	}

	@Test
	public void testAddVarArgResolveConflict() throws Exception {
		// 0x010018cf	"undefined FUN_010018cf(...)"
		// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
		// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
		// 0x01004068	"undefined FUN_01004068(undefined4 param_1, ...)"
		// 0x01004132	"undefined FUN_01004132(undefined4 param_1, undefined4 param_2, undefined4 param_3)"
		// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
		// 0x01004c1d	"undefined FUN_01004c1d(undefined4 param_1, undefined4 param_2, ...)"
		// 0x010058b8	"undefined FUN_010058b8(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, ...)"

		mtf.initialize("notepad.exe_3.1_w_DotDotDot", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Parameter my_count =
						new MyParameter("count", 0, new IntegerDataType(), 4, program);

					// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
					// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
					// 0x01004132	"undefined FUN_01004132(undefined4 param_1, undefined4 param_2, undefined4 param_3)"
					// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
					Function func;
					func = getFunction(program, "0x0100194b");
					func.setVarArgs(true);
					func = getFunction(program, "0x0100299e");
					func.removeParameter(0);
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);
					func = getFunction(program, "0x01004132");
					func.setVarArgs(true);
					func = getFunction(program, "0x01004a15");
					func.removeParameter(0);
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);

					commit = true;
				}
				catch (DuplicateNameException e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				catch (InvalidInputException e) {
					e.printStackTrace();
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
					Parameter my_count =
						new ParameterImpl("count", new IntegerDataType(), 4, program);

					// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
					// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
					// 0x01004132	"undefined FUN_01004132(undefined4 param_1, undefined4 param_2, undefined4 param_3)"
					// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
					Function func;
					func = getFunction(program, "0x0100194b");
					func.removeParameter(0);
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);
					func = getFunction(program, "0x0100299e");
					func.setVarArgs(true);
					func = getFunction(program, "0x01004132");
					func.removeParameter(0);
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);
					func = getFunction(program, "0x01004a15");
					func.setVarArgs(true);

					commit = true;
				}
				catch (DuplicateNameException e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				catch (InvalidInputException e) {
					e.printStackTrace();
					Assert.fail(e.getMessage());
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME); // function signature @ 0100194b
		chooseRadioButton(LATEST_BUTTON_NAME); // function signature @ 0100299e
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // function signature @ 01004132
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // function signature @ 01004a15
		waitForMergeCompletion();

		Function func;

		func = getFunction(resultProgram, "0x0100194b");
		assertEquals(true, func.hasVarArgs());
		assertEquals(2, func.getParameterCount());

		func = getFunction(resultProgram, "0x0100299e");
		assertEquals(false, func.hasVarArgs());
		assertEquals(3, func.getParameterCount());

		func = getFunction(resultProgram, "0x01004132");
		assertEquals(false, func.hasVarArgs());
		assertEquals(3, func.getParameterCount());

		func = getFunction(resultProgram, "0x01004a15");
		assertEquals(true, func.hasVarArgs());
		assertEquals(2, func.getParameterCount());
	}

	@Test
	public void testChangeLatestRemoveMyFunctionNoReturn() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x10031ee");
					func.setNoReturn(true);
					func = getFunction(program, "0x1003bed");
					func.setNoReturn(true);
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
					removeFunction(program, "0x10031ee");
					removeFunction(program, "0x1003bed");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		verticalChooseFunction("0x10031ee", KEEP_LATEST);
		verticalChooseFunction("0x1003bed", KEEP_MY);
		waitForMergeCompletion();

		AddressSet body10031ee = new AddressSet(addr("0x10031ee"), addr("0x100324f"));
		Function function = checkFunction(resultProgram, "0x10031ee", "FUN_010031ee", body10031ee);
		assertEquals(true, function.hasNoReturn());
		noFunction(resultProgram, "0x1003bed");
	}

	@Test
	public void testAddDiffInline() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setInline(true);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setInline(false);

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
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setInline(false);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setInline(true);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1001979", new int[] { INFO_ROW, KEEP_LATEST });
		chooseVariousOptions("0x10029a1", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		Function func = checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		assertEquals(true, func.isInline());

		func = getFunction(resultProgram, "0x10029a1");
		assertEquals(false, func.isInline());
	}

	@Test
	public void testAddDiffNoReturn() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setNoReturn(true);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setNoReturn(false);

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
					AddressSet body1001979 =
						new AddressSet(addr(program, "0x1001979"), addr(program, "0x100199a"));
					createFunction(program, "0x1001979", "FUN_01001979", body1001979);
					Function func = getFunction(program, "0x1001979");
					func.setNoReturn(false);

					AddressSet body10029a1 =
						new AddressSet(addr(program, "0x10029a1"), addr(program, "0x10029ca"));
					createFunction(program, "0x10029a1", "FUN_010029a1", body10029a1);
					func = getFunction(program, "0x10029a1");
					func.setNoReturn(true);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1001979", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x10029a1", new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		Function func = checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		assertEquals(false, func.hasNoReturn());

		func = getFunction(resultProgram, "0x10029a1");
		assertEquals(true, func.hasNoReturn());
	}
}
