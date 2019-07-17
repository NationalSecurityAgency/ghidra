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

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Test the merge of the versioned program's listing.
 */
public class FunctionMergeManager2Test extends AbstractListingMergeManagerTest {

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
	public void testRemoveWithNoConflict() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					removeFunction(program, "0x1002950");
					removeFunction(program, "0x1002cf5");
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
					removeFunction(program, "0x1002b7d");
					removeFunction(program, "0x1002cf5");
					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		noFunction(resultProgram, "0x1002950");
		noFunction(resultProgram, "0x1002b7d");
		noFunction(resultProgram, "0x1002cf5");
	}

	@Test
	public void testRemoveLatestChangeMy() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x10031ee");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
					func = getFunction(program, "0x1003bed");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);
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

		noFunction(resultProgram, "0x10031ee");
		AddressSet body1003bed = new AddressSet(addr("0x1003bed"), addr("0x1003efb"));
		checkFunction(resultProgram, "0x1003bed", "FUN_01003bed", body1003bed);
	}

	@Test
	public void testRemoveLatestChangeMyOverlapConflict() throws Exception {
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
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
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
		});

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x1002a91", KEEP_LATEST);
		horizontalChooseFunction("0x1002b7d", KEEP_MY);
		waitForMergeCompletion();

		noFunction(resultProgram, "0x1002a91");
		AddressSet body1002b44 = new AddressSet(addr("0x1002b44"), addr("0x1002b7c"));
		checkFunction(resultProgram, "0x1002b44", "FUN_01002b44", body1002b44);

		AddressSet body1002b7d = new AddressSet(addr("0x1002b7d"), addr("0x1002c9c"));
		checkFunction(resultProgram, "0x1002b7d", "FUN_01002b7d", body1002b7d);
		noFunction(resultProgram, "0x1002c93");
	}

	@Test
	public void testRemoveLatestChangeMyOverlapOK() throws Exception {
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
					removeFunction(program, "0x1002b7d");

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
		});

		executeMerge(ASK_USER);
		verticalChooseFunction("0x1002a91", KEEP_LATEST);
		verticalChooseFunction("0x1002b7d", KEEP_MY);
		waitForMergeCompletion();

		noFunction(resultProgram, "0x1002a91");
		noFunction(resultProgram, "0x1002b44");

		AddressSet body1002b7d = new AddressSet(addr("0x1002b7d"), addr("0x1002c92"));
		checkFunction(resultProgram, "0x1002b7d", "FUN_01002b7d", body1002b7d);
		noFunction(resultProgram, "0x1002c93");
	}

	@Test
	public void testDiffReturnTypeConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002b44");
					func.setReturnType(new Undefined4DataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b7d");
					func.setReturnType(new ByteDataType(), SourceType.ANALYSIS);

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
					Function func = getFunction(program, "0x1002b44");
					func.setReturnType(new FloatDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b7d");
					func.setReturnType(new FloatDataType(), SourceType.ANALYSIS);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseRadioButton(LATEST_BUTTON_NAME); // 0x1002b44
		chooseRadioButton(MY_BUTTON); // 0x1002b7d
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1002b44");
		assertSameDataType(new Undefined4DataType(), func.getReturnType());

		func = getFunction(resultProgram, "0x1002b7d");
		assertSameDataType(new FloatDataType(), func.getReturnType());
	}

	@Test
	public void testDiffStackParamConflict() throws Exception {
		// FUTURE implement test
	}

	@Test
	public void testDiffStackParamCommentConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(2).setComment("Latest comment 1002c93_2.");

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setComment("Latest comment 1002b44_0.");

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
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(2).setComment("My comment 1002c93_2.");

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setComment("My comment 1002b44_0.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x1002c93", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1002c93");
		assertEquals("Latest comment 1002c93_2.", func.getParameter(2).getComment());

		func = getFunction(resultProgram, "0x1002b44");
		assertEquals("My comment 1002b44_0.", func.getParameter(0).getComment());
	}

	@Test
	public void testDiffStackParamNameConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(1).setName("Latest_1002c93_1", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setName("Latest_1002b44_0", SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(1).setName("My_1002c93_1", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setName("My_1002b44_0", SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x1002c93", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1002c93");
		assertEquals("Latest_1002c93_1", func.getParameter(1).getName());

		func = getFunction(resultProgram, "0x1002b44");
		assertEquals("My_1002b44_0", func.getParameter(0).getName());
	}

	@Test
	public void testDiffStackParamSymbolNameConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(1).getSymbol().setName("Latest_1002c93_1",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).getSymbol().setName("Latest_1002b44_0",
						SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(1).getSymbol().setName("My_1002c93_1",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).getSymbol().setName("My_1002b44_0",
						SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x1002c93", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1002c93");
		assertEquals("Latest_1002c93_1", func.getParameter(1).getName());

		func = getFunction(resultProgram, "0x1002b44");
		assertEquals("My_1002b44_0", func.getParameter(0).getName());
	}

	@Test
	public void testDiffStackParamDataTypeConflict() throws Exception {
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

		final DataType arrayDt = new ArrayDataType(new ByteDataType(), 4, 1);

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(1).setDataType(arrayDt, SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setDataType(new DWordDataType(), SourceType.ANALYSIS);

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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1002c93");
					func.getParameter(1).setDataType(new FloatDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setDataType(new FloatDataType(), SourceType.ANALYSIS);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x1002c93", new int[] { INFO_ROW, KEEP_LATEST });
//		chooseRadioButton(CHECKED_OUT_BUTTON_NAME);
//		chooseRadioButton(LATEST_BUTTON_NAME);
		waitForMergeCompletion();

		Function func;
		func = getFunction(resultProgram, "0x1002b44");
		assertSameDataType(new FloatDataType(), func.getParameter(0).getDataType());

		func = getFunction(resultProgram, "0x1002c93");
		assertSameDataType(arrayDt, func.getParameter(1).getDataType());
	}

	@Test
	public void testDiffLocalVarConflict() throws Exception {
		// FUTURE implement test
	}

	@Test
	public void testDiffLocalVarCommentConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					Variable[] vars = func.getLocalVariables();
					vars[2].setComment("Latest comment 100415a_2.");

					func = getFunction(program, "0x1002a91");
					vars = func.getLocalVariables();
					vars[0].setComment("Latest comment 1002a91_0.");

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
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[2].setComment("My comment 100415a_2.");

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[0].setComment("My comment 1002a91_0.");

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1002a91", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		assertEquals("Latest comment 100415a_2.", func.getLocalVariables()[2].getComment());

		func = getFunction(resultProgram, "0x1002a91");
		assertEquals("My comment 1002a91_0.", func.getLocalVariables()[0].getComment());
	}

	@Test
	public void testDiffLocalVarNameConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[1].setName("Latest_100415a_1",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[2].setName("Latest_1002a91_2",
						SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[1].setName("My_100415a_1", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[2].setName("My_1002a91_2", SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x1002a91", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		assertEquals("Latest_100415a_1", func.getLocalVariables()[1].getName());

		func = getFunction(resultProgram, "0x1002a91");
		assertEquals("My_1002a91_2", func.getLocalVariables()[2].getName());
	}

	@Test
	public void testDiffLocalVarSymbolNameConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[1].getSymbol().setName("Latest_100415a_1",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[2].getSymbol().setName("Latest_1002a91_2",
						SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[1].getSymbol().setName("My_100415a_1",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[2].getSymbol().setName("My_1002a91_2",
						SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x1002a91", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		assertEquals("Latest_100415a_1", func.getLocalVariables()[1].getName());

		func = getFunction(resultProgram, "0x1002a91");
		assertEquals("My_1002a91_2", func.getLocalVariables()[2].getName());
	}

	@Test
	public void testDiffLocalVarDataTypeConflict() throws Exception {
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

		final DataType arrayDt = new ArrayDataType(new ByteDataType(), 4, 1);

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[1].setDataType(arrayDt, SourceType.ANALYSIS);

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[0].setDataType(new DWordDataType(),
						SourceType.ANALYSIS);

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
			public void modifyPrivate(ProgramDB program) throws Exception {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getLocalVariables()[1].setDataType(new FloatDataType(),
						SourceType.ANALYSIS);

					func = getFunction(program, "0x1002a91");
					func.getLocalVariables()[0].setDataType(new FloatDataType(),
						SourceType.ANALYSIS);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseVariousOptions("0x1002a91", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		assertSameDataType(arrayDt, func.getLocalVariables()[1].getDataType());

		func = getFunction(resultProgram, "0x1002a91");
		assertSameDataType(new FloatDataType(), func.getLocalVariables()[0].getDataType());
	}

	@Test
	public void testChangeStackParamNameCommentNoConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setName("NewLatestName", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setComment("New latest comment.");

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setComment("New my comment.");

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setName("NewMyName", SourceType.USER_DEFINED);

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("NewLatestName", parm.getName());
		assertEquals("New my comment.", parm.getComment());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertEquals("NewMyName", parm.getName());
		assertEquals("New latest comment.", parm.getComment());
	}

	@Test
	public void testChangeStackParamNameDataTypeNoConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setName("NewLatestName", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setDataType(new IntegerDataType(), SourceType.ANALYSIS);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new FloatDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setName("NewMyName", SourceType.USER_DEFINED);

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("NewLatestName", parm.getName());
		assertSameDataType(new FloatDataType(), parm.getDataType());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertEquals("NewMyName", parm.getName());
		assertSameDataType(new IntegerDataType(), parm.getDataType());
	}

	@Test
	public void testChangeStackParamDataTypeComment() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new IntegerDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setComment("New latest comment.");

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setComment("New my comment.");

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setDataType(new FloatDataType(), SourceType.ANALYSIS);

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertSameDataType(new IntegerDataType(), parm.getDataType());
		assertEquals("New my comment.", parm.getComment());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertSameDataType(new FloatDataType(), parm.getDataType());
		assertEquals("New latest comment.", parm.getComment());
	}

	@Test
	public void testChangeStackParamNameConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setName("NewLatestName100415a", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setName("NewLatestName1002b44", SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setName("NewMyName100415a", SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setName("NewMyName1002b44", SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("NewLatestName100415a", parm.getName());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertEquals("NewMyName1002b44", parm.getName());
	}

	@Test
	public void testChangeStackParamSymbolNameConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).getSymbol().setName("NewLatestName100415a",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).getSymbol().setName("NewLatestName1002b44",
						SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).getSymbol().setName("NewMyName100415a",
						SourceType.USER_DEFINED);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).getSymbol().setName("NewMyName1002b44",
						SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("NewLatestName100415a", parm.getName());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertEquals("NewMyName1002b44", parm.getName());
	}

	@Test
	public void testChangeStackParamCommentConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setComment("New latest comment.");

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setComment("New latest comment.");

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setComment("New my comment.");

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setComment("New my comment.");

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
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("New latest comment.", parm.getComment());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertEquals("New my comment.", parm.getComment());
	}

	@Test
	public void testChangeStackParamDataTypeConflict() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new CharDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setDataType(new CharDataType(), SourceType.ANALYSIS);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new ByteDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1002b44");
					func.getParameter(0).setDataType(new ByteDataType(), SourceType.ANALYSIS);

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
		chooseVariousOptions("0x1002b44", new int[] { INFO_ROW, KEEP_MY });
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertSameDataType(new CharDataType(), parm.getDataType());

		func = getFunction(resultProgram, "0x1002b44");
		parm = func.getParameter(0);
		assertSameDataType(new ByteDataType(), parm.getDataType());
	}

	@Test
	public void testChangeStackParamNameSame() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setName("NewName100415a", SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setName("NewName100415a", SourceType.USER_DEFINED);

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("NewName100415a", parm.getName());
	}

	@Test
	public void testChangeStackParamCommentSame() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setComment("New comment.");

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setComment("New comment.");

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertEquals("New comment.", parm.getComment());
	}

	@Test
	public void testChangeStackParamDataTypeSame() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new WordDataType(), SourceType.ANALYSIS);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new WordDataType(), SourceType.ANALYSIS);

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm = func.getParameter(2);
		assertSameDataType(new WordDataType(), parm.getDataType());
	}

	@Test
	public void testMultipleFunctionConflictsPickLatest() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.setRepeatableComment("Latest");
					func.setReturnType(new DWordDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setDataType(new CharDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setName("Ernie", SourceType.USER_DEFINED);
					func.getParameter(0).setComment("Parm_1_Latest");

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
					Function func = getFunction(program, "0x100415a");
					func.setRepeatableComment("Mine");
					func.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setDataType(new ByteDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setName("Bert", SourceType.USER_DEFINED);
					func.getParameter(0).setComment("Parm_1_Mine");

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
		chooseRadioButton(LATEST_BUTTON_NAME); // 0x100415a - KEEP_LATEST return type
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST }); // Function Details - parameter comment  // TODO: not checked due to signature diff (may get lost!!)
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST, KEEP_LATEST }); // parameter3 name & datatype // TODO: not checked due to signature diff
		chooseComment("Repeatable", addr("0x100415a"), KEEP_LATEST); // Repeatable Comment
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm0 = func.getParameter(0);
		Parameter parm2 = func.getParameter(2);
		assertSameDataType(new DWordDataType(), func.getReturnType());
		assertEquals("Parm_1_Latest", parm0.getComment());
		assertEquals("Ernie", parm2.getName());
		assertSameDataType(new CharDataType(), parm2.getDataType());
	}

	@Test
	public void testMultipleFunctionConflictsPickMy() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.setRepeatableComment("Latest");
					func.setReturnType(new DWordDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setDataType(new CharDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setName("Ernie", SourceType.USER_DEFINED);
					func.getParameter(0).setComment("Parm_1_Latest");

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
					Function func = getFunction(program, "0x100415a");
					func.setRepeatableComment("Mine");
					func.setReturnType(new FloatDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setDataType(new ByteDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setName("Bert", SourceType.USER_DEFINED);
					func.getParameter(0).setComment("Parm_1_Mine");

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
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // 0x100415a - KEEP_MY return type 'float'
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_MY }); // parameter0 Details
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_MY, KEEP_MY }); // parameter2 name & datatype
		chooseComment("Repeatable", addr("0x100415a"), KEEP_MY); // Repeatable Comment
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm0 = func.getParameter(0);
		Parameter parm2 = func.getParameter(2);
		assertSameDataType(new FloatDataType(), func.getReturnType());
		assertEquals("Parm_1_Mine", parm0.getComment());
		assertEquals("Bert", parm2.getName());
		assertSameDataType(new ByteDataType(), parm2.getDataType());
	}

	@Test
	public void testParameterConflicts() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new CharDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setName("Ernie", SourceType.USER_DEFINED);
					func.getParameter(0).setComment("Parm_1_Latest");
					Parameter[] parms = func.getParameters();
					int num = parms.length;
					StackFrame frame = func.getStackFrame();
					Parameter p = new MyParameter("NewParam", num, new Undefined4DataType(),
						frame.getParameterOffset() + frame.getParameterSize(), program);
					func.addParameter(p, SourceType.USER_DEFINED);

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
					Function func = getFunction(program, "0x100415a");
					func.getParameter(2).setDataType(new ByteDataType(), SourceType.ANALYSIS);
					func.getParameter(2).setName("Bert", SourceType.USER_DEFINED);
					func.getParameter(0).setComment("Parm_1_Mine");
					Parameter[] parms = func.getParameters();
					int num = parms.length;
					StackFrame frame = func.getStackFrame();

					Parameter p = new MyParameter("MyParam", num, new Undefined4DataType(),
						frame.getParameterOffset() + frame.getParameterSize(), program);
					func.addParameter(p, SourceType.USER_DEFINED);

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
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST }); // parameter 1 comment
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST, KEEP_MY }); // parameter 3 name & data type
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_MY }); // parameter 4 name
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Parameter parm1 = func.getParameter(0); // param 1
		Parameter parm3 = func.getParameter(2); // param 3
		Parameter parm4 = func.getParameter(3); // param 3
		assertEquals("Parm_1_Latest", parm1.getComment());
		assertEquals("Ernie", parm3.getName());
		assertSameDataType(new ByteDataType(), parm3.getDataType());
		assertEquals("MyParam", parm4.getName());
	}

	@Test
	public void testLocalVariableConflicts() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x100415a");
					Register reg = func.getProgram().getRegister("AX"); // 16 bit
					Variable[] vars = func.getLocalVariables();
					vars[0].setComment("Local_8_Latest");
					Variable var;
					var =
						new LocalVariableImpl("NewLatestLocal", new ByteDataType(), -0x24, program);
					func.addLocalVariable(var, SourceType.USER_DEFINED);
					var = new LocalVariableImpl("RegAX", 0, new WordDataType(), reg, program);
					func.addLocalVariable(var, SourceType.USER_DEFINED);
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
					Function func = getFunction(program, "0x100415a");
					Register reg = func.getProgram().getRegister("AX"); // 16 bit
					Variable[] vars = func.getLocalVariables();
					vars[0].setComment("Local_8_Mine");
					Variable var =
						new LocalVariableImpl("NewMyLocal", new ByteDataType(), -0x24, program);
					func.addLocalVariable(var, SourceType.USER_DEFINED);
					var = new LocalVariableImpl("myAX", 0, new WordDataType(), reg.getAddress(),
						program);
					func.addLocalVariable(var, SourceType.USER_DEFINED);
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
		// LATEST: RegAX, newLatestLocal(local_24.0), latest_24_12(local_24.12), local_10, local_c, local_8
		// LATEST: myAX, newMyLocal(local_24.0), my_local_12(local_24.12), local_10, local_c, local_8
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_MY }); // AX Register Local name
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST }); // local_8 comment
		chooseVariousOptions("0x100415a", new int[] { INFO_ROW, KEEP_LATEST }); // local_24 name
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x100415a");
		Variable[] locals = func.getLocalVariables();
		assertEquals(5, locals.length);
		assertEquals("myAX", locals[0].getName());
		assertEquals("local_8", locals[1].getName());
		assertEquals("Local_8_Latest", locals[1].getComment());
		assertEquals("local_c", locals[2].getName());
		assertEquals("local_10", locals[3].getName());
		assertEquals("NewLatestLocal", locals[4].getName());
	}

	@Test
	public void testLatestParamSigChanged() throws Exception {
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

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latest_Parm1[0] = new MyParameter("Parm1", 0, new ByteDataType(), 4, program);
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
				// Empty
			}
		});

		executeMerge(ASK_USER);
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
		assertEquals(2, parms.length);
		assertEquals(latest_p1[0], parms[0]);
		assertEquals(latest_p2[0], parms[1]);
	}

	@Test
	public void testMyParamSigChanged() throws Exception {
		// 0100194b		FUN_0100194b	body:100194b-1001977
		// 01001978		FUN_01001978	body:1001978-1001ae2
		// 01001ae3		FUN_01001ae3	body:1001ae3-100219b

		// 01002950		FUN_01002950	body:1002950-100299d
		// 0100299e		FUN_0100299e	body:100299e-1002a90
		// 01002a91		FUN_01002a91	body:1002a91-1002b43

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
		waitForMergeCompletion();

		AddressSet body1001979 = new AddressSet(addr("0x1001979"), addr("0x100199a"));
		checkFunction(resultProgram, "0x1001979", "FUN_01001979", body1001979);
		Function func = getFunction(resultProgram, "0x1001979");
		Parameter[] parms = func.getParameters();
		assertEquals(2, parms.length);
		assertEquals(my_Parm1[0], parms[0]);
		assertEquals(my_Parm2[0], parms[1]);

		func = getFunction(resultProgram, "0x10029a1");
		parms = func.getParameters();
		assertEquals(3, parms.length);
		assertEquals(my_count[0], parms[0]);
		assertEquals(my_offset[0], parms[1]);
		assertEquals(my_increment[0], parms[2]);
	}

	@Test
	public void testParamSigVsInfoConflict() throws Exception {
		// 01003ac0		FUN_01003ac0	body:1003ac0-1003bec
		// 01004c1d		FUN_01004c1d	body:1004c1d-1004c2f

		final Parameter[] latest_Parm1 = new Parameter[1];
		final Parameter[] latest_Parm2 = new Parameter[1];
		final Parameter[] my_count = new Parameter[1];
		final Parameter[] my_offset = new Parameter[1];

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					latest_Parm1[0] =
						new MyParameter("apple", 4, new ByteDataType(), 0x14, program);
					latest_Parm2[0] =
						new MyParameter("banana", 5, new WordDataType(), 0x20, program);

					Function func = getFunction(program, "0x1003ac0");
					func.setCustomVariableStorage(true);
					func.addParameter(latest_Parm1[0], SourceType.USER_DEFINED);
					func.addParameter(latest_Parm2[0], SourceType.USER_DEFINED);

					func = getFunction(program, "0x1004c1d");
					func.setCustomVariableStorage(true);
					Parameter p0 = func.getParameter(0);
					p0.setName("DonaldDuck", SourceType.USER_DEFINED);

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
					my_count[0] = new MyParameter("count", 2, new ByteDataType(), 0x14, program);
					my_offset[0] = new MyParameter("offset", 3, new WordDataType(), 0x20, program);

					Function func = getFunction(program, "0x1003ac0");
					func.setCustomVariableStorage(true);
					Parameter p0 = func.getParameter(0);
					p0.setName("MickeyMouse", SourceType.USER_DEFINED);
					Parameter p1 = func.getParameter(1);
					p1.setDataType(new FloatDataType(), SourceType.ANALYSIS);

					func = getFunction(program, "0x1004c1d");
					func.setCustomVariableStorage(true);
					func.addParameter(my_count[0], SourceType.USER_DEFINED);
					func.addParameter(my_offset[0], SourceType.USER_DEFINED);

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
		chooseRadioButton(LATEST_BUTTON_NAME); // signature @ 0x1003ac0
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // signature @ 0x1004c1d
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1003ac0");
		Parameter[] parms = func.getParameters();
		assertEquals(6, parms.length);
		assertEquals("param_1", parms[0].getName());
		assertEquals("param_2", parms[1].getName());
		assertEquals("param_3", parms[2].getName());
		assertEquals("param_4", parms[3].getName());
		assertEquals(latest_Parm1[0], parms[4]);
		assertEquals(latest_Parm2[0], parms[5]);

		func = getFunction(resultProgram, "0x1004c1d");
		parms = func.getParameters();
		assertEquals(4, parms.length);
		assertEquals("param_1", parms[0].getName());
		assertEquals("param_2", parms[1].getName());
		assertEquals(my_count[0], parms[2]);
		assertEquals(my_offset[0], parms[3]);
	}

	@Test
	public void testParamCommentNoConflict() throws Exception {
		// 01003ac0		FUN_01003ac0	body:1003ac0-1003bec
		// 01004c1d		FUN_01004c1d	body:1004c1d-1004c2f

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1003ac0");
					Parameter p1 = func.getParameter(1);
					p1.setComment("Parameter 1 comment.");

//					func = getFunction(program, "0x1004c1d");
//					Parameter p0 = func.getParameter(0);
//					p0.setName("DonaldDuck");
//					Parameter p1 = func.getParameter(1);

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
					Function func = getFunction(program, "0x1003ac0");
					Parameter p = func.getParameter(0);
					p.setComment("parm 0 comment");

//					func = getFunction(program, "0x1004c1d");
//					p = func.getParameter(0);
//					p.setComment("parm 0 comment");

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
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1003ac0");
		Parameter[] parms = func.getParameters();
		assertEquals(4, parms.length);
		assertEquals("parm 0 comment", parms[0].getComment());
		assertEquals("Parameter 1 comment.", parms[1].getComment());
	}

	@Test
	public void testParamCommentConflict() throws Exception {
		// 01003ac0		FUN_01003ac0	body:1003ac0-1003bec
		// 01004c1d		FUN_01004c1d	body:1004c1d-1004c2f

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x1003ac0");
					Parameter p = func.getParameter(0);
					p.setComment("Parameter 0 comment.");

					func = getFunction(program, "0x1004c1d");
					p = func.getParameter(1);
					p.setComment("DonaldDuck");

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
					Function func = getFunction(program, "0x1003ac0");
					Parameter p = func.getParameter(0);
					p.setComment("parm 0 comment");

					func = getFunction(program, "0x1004c1d");
					p = func.getParameter(1);
					p.setComment("To be or not to be.");

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
		chooseVariousOptions("0x1003ac0", new int[] { INFO_ROW, KEEP_LATEST });
		chooseVariousOptions("0x1004c1d", new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		Function func = getFunction(resultProgram, "0x1003ac0");
		Parameter[] parms = func.getParameters();
		assertEquals(4, parms.length);
		assertEquals("Parameter 0 comment.", parms[0].getComment());
		assertEquals(null, parms[1].getComment());

		func = getFunction(resultProgram, "0x1004c1d");
		parms = func.getParameters();
		assertEquals(2, parms.length);
		assertEquals(null, parms[0].getComment());
		assertEquals("To be or not to be.", parms[1].getComment());
	}

	@Test
	public void testRemoveVarArgNoConflict() throws Exception {
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
					// 0x010018cf	"undefined FUN_010018cf(...)"
					// 0x01004068	"undefined FUN_01004068(undefined4 param_1, ...)"
					// 0x01004c1d	"undefined FUN_01004c1d(undefined4 param_1, undefined4 param_2, ...)"
					// 0x010058b8	"undefined FUN_010058b8(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, ...)"
					Function func;
					func = getFunction(program, "0x01004068");
					func.setVarArgs(false);
					func = getFunction(program, "0x010058b8");
					func.setVarArgs(false);

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
					// 0x010018cf	"undefined FUN_010018cf(...)"
					// 0x01004068	"undefined FUN_01004068(undefined4 param_1, ...)"
					// 0x01004c1d	"undefined FUN_01004c1d(undefined4 param_1, undefined4 param_2, ...)"
					// 0x010058b8	"undefined FUN_010058b8(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, ...)"
					Function func;
					func = getFunction(program, "0x01004c1d");
					func.setVarArgs(false);
					func = getFunction(program, "0x010058b8");
					func.setVarArgs(false);

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
		func = getFunction(resultProgram, "0x01004068");
		assertEquals(false, func.hasVarArgs());
		func = getFunction(resultProgram, "0x01004c1d");
		assertEquals(false, func.hasVarArgs());
		func = getFunction(resultProgram, "0x010058b8");
		assertEquals(false, func.hasVarArgs());
	}

	@Test
	public void testRemoveVarArgResolveConflict() throws Exception {
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
						new ParameterImpl("count", new IntegerDataType(), 4, program);

					// 0x010018cf	"undefined FUN_010018cf(...)"
					// 0x01004068	"undefined FUN_01004068(undefined4 param_1, ...)"
					// 0x01004c1d	"undefined FUN_01004c1d(undefined4 param_1, undefined4 param_2, ...)"
					// 0x010058b8	"undefined FUN_010058b8(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, ...)"
					Function func;
					func = getFunction(program, "0x010018cf");
					func.setVarArgs(false);
					func = getFunction(program, "0x01004068");
					func.removeParameter(0);
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);
					func = getFunction(program, "0x01004c1d");
					func.setVarArgs(false);
					func = getFunction(program, "0x010058b8");
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

					// 0x010018cf	"undefined FUN_010018cf(...)"
					// 0x01004068	"undefined FUN_01004068(undefined4 param_1, ...)"
					// 0x01004c1d	"undefined FUN_01004c1d(undefined4 param_1, undefined4 param_2, ...)"
					// 0x010058b8	"undefined FUN_010058b8(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, ...)"
					Function func;
					func = getFunction(program, "0x010018cf");
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);
					func = getFunction(program, "0x01004068");
					func.setVarArgs(false);
					func = getFunction(program, "0x01004c1d");
					func.removeParameter(0);
					func.insertParameter(0, my_count, SourceType.USER_DEFINED);
					func = getFunction(program, "0x010058b8");
					func.setVarArgs(false);

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
		chooseRadioButton(LATEST_BUTTON_NAME); // function signature @ 010018cf
		chooseRadioButton(LATEST_BUTTON_NAME); // function signature @ 01004068
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // function signature @ 01004c1d
		chooseRadioButton(CHECKED_OUT_BUTTON_NAME); // function signature @ 010058b8
		waitForMergeCompletion();

		Function func;

		func = getFunction(resultProgram, "0x010018cf");
		assertEquals(false, func.hasVarArgs());
		assertEquals(0, func.getParameterCount());

		func = getFunction(resultProgram, "0x01004068");
		assertEquals(true, func.hasVarArgs());
		assertEquals(1, func.getParameterCount());

		func = getFunction(resultProgram, "0x01004c1d");
		assertEquals(true, func.hasVarArgs());
		assertEquals(2, func.getParameterCount());

		func = getFunction(resultProgram, "0x010058b8");
		assertEquals(false, func.hasVarArgs());
		assertEquals(5, func.getParameterCount());
	}

	@Test
	public void testSetInline() throws Exception {
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
					func.setInline(true);
					func = getFunction(program, "0x01004a15");
					func.setInline(true);

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
					func.setInline(true);
					func = getFunction(program, "0x01004a15");
					func.setInline(true);

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
		assertEquals(true, func.isInline());
		func = getFunction(resultProgram, "0x0100299e");
		assertEquals(true, func.isInline());
		func = getFunction(resultProgram, "0x01004a15");
		assertEquals(true, func.isInline());
	}

	@Test
	public void testUnsetInline() throws Exception {
		// 0x01004132 Inline			"undefined FUN_01004132()"
		// 0x010041fc NoReturn			"undefined FUN_010041fc()"
		// 0x0100476b Inline & NoReturn	"undefined FUN_0100476b()"
		// 0x01004a15 Inline			"undefined FUN_01004a15()"
		// 0x01004bc0 NoReturn			"undefined FUN_01004bc0()"
		// 0x01004c1d Inline & NoReturn	"undefined FUN_01004c1d()"

		mtf.initialize("notepad.exe_3.1_w_DotDotDot", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func;
					func = getFunction(program, "0x01004132");
					func.setInline(false);
					func = getFunction(program, "0x01004a15");
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
					Function func;
					func = getFunction(program, "0x0100476b");
					func.setInline(false);
					func = getFunction(program, "0x01004a15");
					func.setInline(false);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		Function func;
		originalProgram = mtf.getOriginalProgram();

		func = getFunction(originalProgram, "0x01004132");
		assertEquals(true, func.isInline());
		func = getFunction(originalProgram, "0x0100476b");
		assertEquals(true, func.isInline());
		func = getFunction(originalProgram, "0x01004a15");
		assertEquals(true, func.isInline());

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		func = getFunction(resultProgram, "0x01004132");
		assertEquals(false, func.isInline());
		func = getFunction(resultProgram, "0x0100476b");
		assertEquals(false, func.isInline());
		func = getFunction(resultProgram, "0x01004a15");
		assertEquals(false, func.isInline());
	}

	@Test
	public void testSetNoReturn() throws Exception {
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
					func.setNoReturn(true);
					func = getFunction(program, "0x01004a15");
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
					// 0x0100194b	"undefined FUN_0100194b(undefined4 param_1, undefined4 param_2)"
					// 0x0100299e	"undefined FUN_0100299e(undefined4 param_1, undefined4 param_2, undefined param_3)"
					// 0x01004a15	"undefined FUN_01004a15(undefined4 param_1, undefined4 param_2)"
					Function func;
					func = getFunction(program, "0x0100299e");
					func.setNoReturn(true);
					func = getFunction(program, "0x01004a15");
					func.setNoReturn(true);

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
		assertEquals(true, func.hasNoReturn());
		func = getFunction(resultProgram, "0x0100299e");
		assertEquals(true, func.hasNoReturn());
		func = getFunction(resultProgram, "0x01004a15");
		assertEquals(true, func.hasNoReturn());
	}

	@Test
	public void testUnsetNoReturn() throws Exception {
		// 0x01004132 Inline			"undefined FUN_01004132()"
		// 0x010041fc NoReturn			"undefined FUN_010041fc()"
		// 0x0100476b Inline & NoReturn	"undefined FUN_0100476b()"
		// 0x01004a15 Inline			"undefined FUN_01004a15()"
		// 0x01004bc0 NoReturn			"undefined FUN_01004bc0()"
		// 0x01004c1d Inline & NoReturn	"undefined FUN_01004c1d()"

		mtf.initialize("notepad.exe_3.1_w_DotDotDot", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func;
					func = getFunction(program, "0x010041fc");
					func.setNoReturn(false);
					func = getFunction(program, "0x0100476b");
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
					Function func;
					func = getFunction(program, "0x01004bc0");
					func.setNoReturn(false);
					func = getFunction(program, "0x0100476b");
					func.setNoReturn(false);

					commit = true;
				}
				finally {
					program.endTransaction(txId, commit);
				}
			}
		});

		Function func;
		originalProgram = mtf.getOriginalProgram();

		func = getFunction(originalProgram, "0x010041fc");
		assertEquals(true, func.hasNoReturn());
		func = getFunction(originalProgram, "0x01004bc0");
		assertEquals(true, func.hasNoReturn());
		func = getFunction(originalProgram, "0x0100476b");
		assertEquals(true, func.hasNoReturn());

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		func = getFunction(resultProgram, "0x010041fc");
		assertEquals(false, func.hasNoReturn());
		func = getFunction(resultProgram, "0x01004bc0");
		assertEquals(false, func.hasNoReturn());
		func = getFunction(resultProgram, "0x0100476b");
		assertEquals(false, func.hasNoReturn());
	}

	@Test
	public void testRemoveLatestChangeMyFunctionInline() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x10031ee");
					func.setInline(true);
					func = getFunction(program, "0x1003bed");
					func.setInline(true);
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

		noFunction(resultProgram, "0x10031ee");
		AddressSet body1003bed = new AddressSet(addr("0x1003bed"), addr("0x1003efb"));
		Function function = checkFunction(resultProgram, "0x1003bed", "FUN_01003bed", body1003bed);
		assertEquals(true, function.isInline());
	}

	@Test
	public void testSetCallingConvention() throws Exception {
		// NotepadMergeListingTest has "unknown", "default", "__stdcall", "__cdecl", "__fastcall", "__thiscall".
		// 01006420 entry()
		// 01001ae3 FUN_01001ae3(p1,p2)
		// 010021f3 FUN_010021f3(p1)
		// 0100248f FUN_0100248f(p1,p2,p3,p4)
		// 01002c93 FUN_01002c93(p1,p2,p3)

		mtf.initialize("NotepadMergeListingTest_X86", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func;
					func = getFunction(program, "0x01006420");
					func.setCallingConvention("__stdcall");
					func = getFunction(program, "0x010021f3");
					func.setCallingConvention("__thiscall");
					func = getFunction(program, "0x0100248f");
					func.setCallingConvention("__fastcall");
					func = getFunction(program, "0x01002c93");
					func.setCallingConvention("__fastcall");

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
					Function func;
					func = getFunction(program, "0x01001ae3");
					func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
					func = getFunction(program, "0x010021f3");
					func.setCallingConvention("__cdecl");
					func = getFunction(program, "0x0100248f");
					func.setCallingConvention("__fastcall");
					func = getFunction(program, "0x01002c93");
					func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);

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
		chooseVariousOptions("0x010021f3", new int[] { INFO_ROW, KEEP_LATEST });
		chooseVariousOptions("0x01002c93", new int[] { INFO_ROW, KEEP_MY });
		waitForMergeCompletion();

		// 01006420 entry()
		// 01001ae3 FUN_01001ae3(p1,p2)
		// 010021f3 FUN_010021f3(p1)
		// 0100248f FUN_0100248f(p1,p2,p3,p4)
		// 01002c93 FUN_010023c93(p1,p2,p3)
		Function func;
		func = getFunction(resultProgram, "0x01006420");
		assertEquals("__stdcall", func.getCallingConventionName());
		func = getFunction(resultProgram, "0x01001ae3");
		assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, func.getCallingConventionName());
		func = getFunction(resultProgram, "0x010021f3");
		assertEquals("__thiscall", func.getCallingConventionName());
		func = getFunction(resultProgram, "0x0100248f");
		assertEquals("__fastcall", func.getCallingConventionName());
		func = getFunction(resultProgram, "0x01002c93");
		assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING, func.getCallingConventionName());
	}

	@Test
	public void testRemoveLatestChangeMyCallingConvention() throws Exception {
		mtf.initialize("NotepadMergeListingTest", new ProgramModifierListener() {

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				int txId = program.startTransaction("Modify Latest Program");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				int txId = program.startTransaction("Modify My Program");
				boolean commit = false;
				try {
					Function func = getFunction(program, "0x10031ee");
					func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
					func = getFunction(program, "0x1003bed");
					func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
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
		verticalChooseFunction("0x10031ee", KEEP_LATEST);
		verticalChooseFunction("0x1003bed", KEEP_MY);
		waitForMergeCompletion();

		noFunction(resultProgram, "0x10031ee");
		AddressSet body1003bed = new AddressSet(addr("0x1003bed"), addr("0x1003efb"));
		Function function = checkFunction(resultProgram, "0x1003bed", "FUN_01003bed", body1003bed);
		assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING,
			function.getCallingConventionName());
	}

	@Test
	public void testRemoveMyChangeLatestCallingConvention() throws Exception {
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
					func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
					func = getFunction(program, "0x1003bed");
					func.setCallingConvention(Function.DEFAULT_CALLING_CONVENTION_STRING);
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
		assertEquals(Function.DEFAULT_CALLING_CONVENTION_STRING,
			function.getCallingConventionName());
		noFunction(resultProgram, "0x1003bed");
	}

	@Test
	public void testOverlapConflictDontUseForAll() throws Exception {
		setupOverlapUseForAll();

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x1001979", KEEP_MY, false);
		horizontalChooseFunction("0x10029a1", KEEP_LATEST, false);
		waitForMergeCompletion();

		noFunction(resultProgram, "0x1001979");
		AddressSet body10029a1 = new AddressSet(addr("0x10029a1"), addr("0x10029ca"));
		checkFunction(resultProgram, "0x10029a1", "FUN_010029a1", body10029a1);

		AddressSet body1001984 = new AddressSet(addr("0x1001984"), addr("0x100198a"));
		checkFunction(resultProgram, "0x1001984", "FUN_01001984", body1001984);
		noFunction(resultProgram, "0x10029bc");
	}

	@Test
	public void testOverlapConflictUseForAll() throws Exception {
		setupOverlapUseForAll();

		executeMerge(ASK_USER);
		horizontalChooseFunction("0x1001979", KEEP_MY, true);
//		horizontalChooseFunction("0x10029a1", KEEP_MY, false); // handled by "Use For All".
		waitForMergeCompletion();

		noFunction(resultProgram, "0x1001979");
		AddressSet body1001984 = new AddressSet(addr("0x1001984"), addr("0x100198a"));
		checkFunction(resultProgram, "0x1001984", "FUN_01001984", body1001984);

		AddressSet body10029bc = new AddressSet(addr("0x10029bc"), addr("0x10029d3"));
		checkFunction(resultProgram, "0x10029bc", "FUN_010029bc", body10029bc);
		noFunction(resultProgram, "0x10029a1");
	}

	@Test
	public void testRemoveConflictDontUseForAll() throws Exception {
		setupRemoveConflictUseForAll();

		executeMerge(ASK_USER);
		verticalChooseFunction("0x10031ee", KEEP_LATEST, false);
		verticalChooseFunction("0x1003bed", KEEP_MY, false);
		waitForMergeCompletion();

		noFunction(resultProgram, "0x10031ee");
		AddressSet body1003bed = new AddressSet(addr("0x1003bed"), addr("0x1003efb"));
		checkFunction(resultProgram, "0x1003bed", "FUN_01003bed", body1003bed);
		Function func1003bed = getFunction(resultProgram, "0x1003bed");
		assertTrue(new ByteDataType().isEquivalent(func1003bed.getReturnType()));
	}

	@Test
	public void testRemoveConflictUseForAll() throws Exception {
		setupRemoveConflictUseForAll();

		executeMerge(ASK_USER);
		verticalChooseFunction("0x10031ee", KEEP_MY, true);
//		verticalChooseFunction("0x1003bed", KEEP_MY, false); // Handled by "Use For All".
		waitForMergeCompletion();

		AddressSet body10031ee = new AddressSet(addr("0x10031ee"), addr("0x100324f"));
		checkFunction(resultProgram, "0x10031ee", "FUN_010031ee", body10031ee);
		Function func10031ee = getFunction(resultProgram, "0x10031ee");
		assertTrue(new ByteDataType().isEquivalent(func10031ee.getReturnType()));
		AddressSet body1003bed = new AddressSet(addr("0x1003bed"), addr("0x1003efb"));
		checkFunction(resultProgram, "0x1003bed", "FUN_01003bed", body1003bed);
		Function func1003bed = getFunction(resultProgram, "0x1003bed");
		assertTrue(new ByteDataType().isEquivalent(func1003bed.getReturnType()));
	}
}
