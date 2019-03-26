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
package ghidra.app.plugin.core.function.tags;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.awt.Window;
import java.io.IOException;
import java.util.Collection;

import javax.swing.JComponent;
import javax.swing.JLabel;

import org.junit.Test;

import generic.test.TestUtils;
import ghidra.app.merge.listing.*;
import ghidra.app.merge.tool.ListingMergePanel;
import ghidra.program.database.*;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.*;

/**
 * Test for the {@link FunctionTagListingMerger} and {@link FunctionTagMerger}. These are tests 
 * that involve creating/editing/deleting tags from the system, as well as adding or
 * removing tags from functions.
 * 
 * Note that the two mergers mentioned above are always run in sequence, the tag merger
 * running before the listing merger. This sequence is done here for all test.
 * @see #doMerge(int, int)
 * 
 */
public class FunctionTagMergeTest extends AbstractListingMergeManagerTest {

	// Set up some tag names that we will use in various tests. These can
	// be used for any purpose but the names should make their intended 
	// use obvious.
	private String TAG_NAME_A = "testTagA";
	private String TAG_NAME_B = "testTagB";
	private String TAG_NAME_C = "testTagC";
	private String TAG_NAME_A_LATEST = "testTagALatest";
	private String TAG_NAME_A_MY = "testTagAMy";
	private String TAG_NAME_B_LATEST = "testTagBLatest";
	private String TAG_NAME_B_MY = "testTagBMy";
	private String TAG_NAME_C_LATEST = "testTagCLatest";
	private String TAG_NAME_C_MY = "testTagCMy";

	// Use this notepad variant from {@link MergeProgramGenerator_Notepads} because it
	// has empty functions we can assign tags to.
	private String notepad = "notepad.exe_3.1_w_DotDotDot";

	/****************************************************************************************
	 * TESTS
	 ****************************************************************************************/

	/**
	 * Tests that we can add the same tag to two programs and have there
	 * be no conflict.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCreateSameTagsNoConflict() throws Exception {

		mtf.initialize(notepad, new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "");
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The tag exists in Result.
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
	}

	/**
	 * Tests that different tags created in Latest and My will be merged with 
	 * no conflict.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCreateDifferentTagsNoConflict() throws Exception {

		mtf.initialize(notepad, new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "");
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_B, "");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The tag exists in Result.
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
	}

	/**
	 * Tests that we can create tags with different names and different comments, and
	 * there's no conflict.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCreateTagsDifferentNameDifferentCommentNoConflict() throws Exception {

		mtf.initialize(notepad, new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "comment A");
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_B, "comment B");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The tag exists in Result.
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
	}

	/**
	 * Tests that creating tags with different comments (same name) causes a conflict, 
	 * and that we can add the correct one to the result.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testCreateTagsSameNameDifferentCommentConflict() throws Exception {

		mtf.initialize(notepad, new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "comment A");
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "comment B");
			}
		});

		executeMerge(ASK_USER);

		int conflicts = getTagConflictCount();
		assertTrue(conflicts == 1);

		chooseFunctionTagButton(MY_BUTTON, false);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The tag exists in Result.
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(getTagComment(TAG_NAME_A, mtf.getResultProgram()).equals("comment B"));
	}

	/**
	 * Tests that editing just the comment of tags with the same name will cause
	 * a conflict.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEditCommentsConflict() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagComment(program, TAG_NAME_A, "comment C");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					editTagComment(program, TAG_NAME_A, "comment B");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "comment A");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		int conflicts = getTagConflictCount();
		assertTrue(conflicts == 1);

		chooseFunctionTagButton(LATEST_BUTTON, false);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The tag exists in Result.
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(getTagComment(TAG_NAME_A, mtf.getResultProgram()).equals("comment C"));
	}

	/**
	 * Tests that we can create different tags in different orders and have no conflict. This
	 * ensures that there is no issue with how IDs are compared.
	 * 
	 * @throws Exception 
	 */
	@Test
	public void testCreateDifferentTagsDifferentOrderNoConflict() throws Exception {

		mtf.initialize(notepad, new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_A, "");
				createTag(program, TAG_NAME_B, "");
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				createTag(program, TAG_NAME_B, "");
				createTag(program, TAG_NAME_A, "");
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The tag exists in Result.
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
	}

	/**
	 * Tests that two users can delete the same tag with no conflict.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testTagNameDeleteNoConflict() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					deleteTag(program, TAG_NAME_A);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					deleteTag(program, TAG_NAME_A);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		// Get the result program and check that: 
		// 1. The tag does not exist in Result
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
	}

	/**
	 * Test that we can edit a tag in Latest and add it to a function
	 * in My to create a conflict.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEditMyAddLatestNoConflict() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					addTagToFunction(TAG_NAME_A, program, "100299e");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					addTagToFunction(TAG_NAME_A, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		int conflicts = getTagListingConflictCount();
		assertTrue(conflicts == 1);

		chooseFunctionTagButton(LATEST_BUTTON, false);
		waitForMergeCompletion();

		assertTrue(isTagInProgram(TAG_NAME_A_LATEST, mtf.getResultProgram()));
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));

		assertTrue(isTagInFunction(TAG_NAME_A_LATEST, mtf.getResultProgram(), "100194b"));
		assertTrue(isTagInFunction(TAG_NAME_A_LATEST, mtf.getResultProgram(), "100299e"));
	}

	/**
	 * Test that we can add different tags to different functions in My and
	 * Latest.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testAddTagsToDifferentFunctionsNoConflict() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					addTagToFunction(TAG_NAME_A, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					addTagToFunction(TAG_NAME_B, program, "100299e");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					tagManager.createFunctionTag(TAG_NAME_B, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		int conflicts = getTagListingConflictCount();
		assertTrue(conflicts == 0);

		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
		assertTrue(isTagInFunction(TAG_NAME_A, mtf.getResultProgram(), "100194b"));
		assertTrue(isTagInFunction(TAG_NAME_B, mtf.getResultProgram(), "100299e"));
	}

	/**
	 * Tests that we can add different tags to the same function and have them 
	 * mere with no conflicts.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testAddTagsToSameFunctionsNoConflict() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					addTagToFunction(TAG_NAME_A, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					addTagToFunction(TAG_NAME_B, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					tagManager.createFunctionTag(TAG_NAME_B, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		waitForMergeCompletion();

		int conflicts = getTagListingConflictCount();
		assertTrue(conflicts == 0);

		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
		assertTrue(isTagInFunction(TAG_NAME_A, mtf.getResultProgram(), "100194b"));
		assertTrue(isTagInFunction(TAG_NAME_B, mtf.getResultProgram(), "100194b"));
	}

	/**
	 * Tests that we can correctly recognize multiple conflicts with the 
	 * tag merge resolver. In this case we do the following:
	 * 1. Add tags A & B to both programs
	 * 2. Rename A and B in Latest
	 * 3. Rename A and B in My
	 * 4. Verify we have 2 conflicts.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testMultipleTagConflicts() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
					editTagName(program, TAG_NAME_B, TAG_NAME_B_LATEST);

				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_MY);
					editTagName(program, TAG_NAME_B, TAG_NAME_B_MY);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					tagManager.createFunctionTag(TAG_NAME_B, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		int conflicts = getTagConflictCount();
		assertTrue(conflicts == 2);

		chooseFunctionTagButton(LATEST_BUTTON, false);
		chooseFunctionTagButton(MY_BUTTON, false);
		waitForMergeCompletion();

		assertTrue(isTagInProgram(TAG_NAME_A_LATEST, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B_MY, mtf.getResultProgram()));
	}

	/**
	 * Tests that we can correctly recognize multiple conflicts with both the tag
	 * merger and the tag listing merger. In this case we do the following:
	 * 1. Add tags A, B and C to both programs
	 * 2. Rename A in Latest, and delete B
	 * 3. Rename A and C in My, and add B to a function
	 * 4. Verify we have 2 conflicts (the edit of A, and the add of a 
	 *    deleted tag - B, in My).
	 * 
	 * @throws Exception
	 */
	@Test
	public void testMultipleTagAndListingConflicts() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
					deleteTag(program, TAG_NAME_B);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_MY);
					addTagToFunction(TAG_NAME_B, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					tagManager.createFunctionTag(TAG_NAME_B, "");
					tagManager.createFunctionTag(TAG_NAME_C, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseFunctionTagButton(MY_BUTTON, true);
		chooseListingFunctionTagButton(MY_BUTTON, addr("100194b"), false);
		waitForMergeCompletion();

		assertTrue(isTagInProgram(TAG_NAME_A_MY, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_C, mtf.getResultProgram()));

		assertTrue(isTagInFunction(TAG_NAME_B, mtf.getResultProgram(), "100194b"));
	}

	/**
	 * Tests that the use-for-all checkbox works correctly in the tag merge
	 * panel. To do this we create 3 conflicts by editing the name of 
	 * 3 tags in each program. We then verify that the version in the Result
	 * program is from the checked-out version.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testUseForAll1() throws Exception {
		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
					editTagName(program, TAG_NAME_B, TAG_NAME_B_LATEST);
					editTagName(program, TAG_NAME_C, TAG_NAME_C_LATEST);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_MY);
					editTagName(program, TAG_NAME_B, TAG_NAME_B_MY);
					editTagName(program, TAG_NAME_C, TAG_NAME_C_MY);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					tagManager.createFunctionTag(TAG_NAME_B, "");
					tagManager.createFunctionTag(TAG_NAME_C, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		int conflicts = getTagConflictCount();
		assertTrue(conflicts == 3);

		chooseFunctionTagButton(MY_BUTTON, true);
		waitForMergeCompletion();

		assertTrue(isTagInProgram(TAG_NAME_A_MY, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B_MY, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_C_MY, mtf.getResultProgram()));
	}

	/**
	 * Tests that the use-for-all checkbox works correctly in the tag listing
	 * merge panel. To do this we create 3 conflicts by deleting 3 tags from
	 * the Latest program, while adding those same three tags to a function
	 * in My. We then verify that the version in the Result
	 * program is from the checked-out (My) version.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testUseForAll2() throws Exception {
		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					deleteTag(program, TAG_NAME_A);
					deleteTag(program, TAG_NAME_B);
					deleteTag(program, TAG_NAME_C);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					addTagToFunction(TAG_NAME_A, program, "100194b");
					addTagToFunction(TAG_NAME_B, program, "100194b");
					addTagToFunction(TAG_NAME_C, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
					tagManager.createFunctionTag(TAG_NAME_B, "");
					tagManager.createFunctionTag(TAG_NAME_C, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);

		int conflicts = getTagListingConflictCount();
		assertTrue(conflicts == 3);

		chooseFunctionTagButton(MY_BUTTON, true);
		waitForMergeCompletion();

		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_B, mtf.getResultProgram()));
		assertTrue(isTagInProgram(TAG_NAME_C, mtf.getResultProgram()));

		assertTrue(isTagInFunction(TAG_NAME_A, mtf.getResultProgram(), "100194b"));
		assertTrue(isTagInFunction(TAG_NAME_B, mtf.getResultProgram(), "100194b"));
		assertTrue(isTagInFunction(TAG_NAME_C, mtf.getResultProgram(), "100194b"));
	}

	/**
	 * Tests that we handle the conflict case where a tag name has been edited in both 
	 * My and Latest versions of the program. For this test, keep the one in 
	 * Latest.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testTagNameEditKeepLatest() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_MY);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseFunctionTagButton(LATEST_BUTTON, false);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The edited tag exists in Result.
		// 2. The original tag does NOT exist in Result.
		assertTrue(isTagInProgram(TAG_NAME_A_LATEST, mtf.getResultProgram()));
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
	}

	/**
	 * Tests that we handle the conflict case where a tag name has been edited in both 
	 * My and Latest versions of the program. For this test, keep the version in My.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testTagNameEditKeepMy() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_MY);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseFunctionTagButton(MY_BUTTON, false);
		waitForMergeCompletion();

		// Get the result program and check that we have:
		// 1. The edited tag exists in Result.
		// 2. The original tag does NOT exist in Result.
		assertTrue(isTagInProgram(TAG_NAME_A_MY, mtf.getResultProgram()));
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
	}

	/**
	 * Tests that we handle the conflict case where a tag name has been deleted in Latest
	 * but added to a function in My; keep My.
	 * 
	 * This is arguably the most complicated type of test case as it involves two 
	 * mergers: {@link FunctionTagMerger} and {@link FunctionTagListingMerger}. First the
	 * delete is handled (and approved) by the former, then the tag is brought back in by 
	 * latter.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testDeleteLatestAddMy_KeepMy() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					deleteTag(program, TAG_NAME_A);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					addTagToFunction(TAG_NAME_A, program, "100194b");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseListingFunctionTagButton(MY_BUTTON, addr("100194b"), false);
		waitForMergeCompletion();

		// Get the result program and check that:
		// 1. The tag still exists in the db
		// 2. The tag is assigned to the function
		assertTrue(isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(isTagInFunction(TAG_NAME_A, mtf.getResultProgram(), "100194b"));
	}

	/**
	 * Tests that we handle the conflict case where a tag name has been deleted in Latest
	 * but added to a function in My; keep Latest;
	 * 
	 * This is arguably the most complicated type of test case as it involves two 
	 * mergers: {@link FunctionTagMerger} and {@link FunctionTagListingMerger}. First the
	 * delete is handled (and approved) by the former, then the tag recognized by the
	 * latter as a conflict, but ignored since its been told to keep the LATEST version (where
	 * the delete happened).
	 * 
	 * @throws Exception
	 */
	@Test
	public void testDeleteLatestAddMy_KeepLatest() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					deleteTag(program, TAG_NAME_A);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					addTagToFunction(TAG_NAME_A, program, "100299e");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseListingFunctionTagButton(LATEST_BUTTON, addr("100299e"), false);
		waitForMergeCompletion();

		// Get the result program and check that:
		// 1. The tag remains deleted
		// 2. The tag is no longer associated with the function
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
		assertTrue(!isTagInFunction(TAG_NAME_A, mtf.getResultProgram(), "100299e"));
	}

	/**
	 * Tests that we can edit a tag in Latest, delete it in My, and 
	 * correctly resolve the conflict to keep the edited version.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEditLatestDeleteMy_KeepLatest() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					deleteTag(program, TAG_NAME_A);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseFunctionTagButton(LATEST_BUTTON, false);
		waitForMergeCompletion();

		// Get the result program and check that:
		// 1. The edited tag is still in Result
		// 2. The original version is not in Result
		assertTrue(isTagInProgram(TAG_NAME_A_LATEST, mtf.getResultProgram()));
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
	}

	/**
	 * Tests that we can edit a tag in Latest, delete it in My, and 
	 * correctly resolve the conflict to keep the deleted version.
	 * 
	 * @throws Exception
	 */
	@Test
	public void testEditLatestDeleteMy_KeepMy() throws Exception {

		mtf.initialize(notepad, new OriginalProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("latest");
				try {
					editTagName(program, TAG_NAME_A, TAG_NAME_A_LATEST);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("my");
				try {
					deleteTag(program, TAG_NAME_A);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				int transactionID = program.startTransaction("original");
				try {
					FunctionTagManager tagManager = getTagManager(program);
					tagManager.createFunctionTag(TAG_NAME_A, "");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge(ASK_USER);
		chooseFunctionTagButton(MY_BUTTON, false);
		waitForMergeCompletion();

		// Get the result program and check that:
		// 1. The edited tag is NOT in Result
		// 2. The original version is NOT in Result
		assertTrue(!isTagInProgram(TAG_NAME_A_LATEST, mtf.getResultProgram()));
		assertTrue(!isTagInProgram(TAG_NAME_A, mtf.getResultProgram()));
	}

	/****************************************************************************************
	 * PRIVATE METHODS
	 ****************************************************************************************/

	private void chooseFunctionTagButton(String buttonChoice, boolean useForAll) throws Exception {
		chooseButtonAndApply("Resolve Function Tags Conflict", buttonChoice, useForAll);
	}

	private void chooseListingFunctionTagButton(String buttonChoice, Address address,
			boolean useForAll) throws Exception {
		chooseButtonAndApply("Resolve Function Tags Conflict", buttonChoice, useForAll);
	}

	/**
	 * Returns the comment for the tag provided.
	 * 
	 * @param tagName the name of the tag 
	 * @param program the program 
	 * @return
	 * @throws IOException
	 */
	private String getTagComment(String tagName, Program program) throws IOException {
		Collection<? extends FunctionTag> tags = getAllTags(program);
		for (FunctionTag tag : tags) {
			if (tag.getName().equals(tagName)) {
				return tag.getComment();
			}
		}
		return "";
	}

	/**
	 * Searches a function for a tag.
	 * 
	 * @param name the tag to search for
	 * @param program the program to search
	 * @param address the address of the function, as a string
	 * @return true if found
	 */
	private boolean isTagInFunction(String name, Program program, String address) {

		Address entryPoint = addr(address, program);

		FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		Function function = functionManagerDB.getFunctionAt(entryPoint);
		Collection<FunctionTag> tags = function.getTags();
		for (FunctionTag tag : tags) {
			if (tag.getName().equals(name)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Searches a program for a tag.
	 * 
	 * Note: This has nothing to do with functions; only checks that the tag exists.
	 * 
	 * @param name the tag to search for
	 * @param program the program to search
	 * @return true if found
	 * @throws IOException
	 */
	private boolean isTagInProgram(String name, Program program) throws IOException {

		Collection<? extends FunctionTag> resultTags = getAllTags(program);

		// @formatter:off
       	return resultTags.stream()
		      		     .filter(t -> t.getName().equals(name)) 
		       		     .count() > 0;
		// @formatter:on
	}

	/**
	 * Adds a tag to a function.
	 * 
	 * @param name the name of the tag to add
	 * @param program the program where the function resides
	 * @param address the entry point of the function, as a string
	 */
	private void addTagToFunction(String name, Program program, String address) {

		Address entryPoint = addr(address, program);

		int transactionID = program.startTransaction("add");
		try {
			FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
			Function function = functionManagerDB.getFunctionAt(entryPoint);
			function.addTag(name);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	/**
	 * Creates a new tag.
	 * 
	 * @param program the program to add the tag go
	 * @param name the tag name
	 * @param comment the tag comment
	 */
	private void createTag(Program program, String name, String comment) {
		int transactionID = program.startTransaction("add");
		try {
			FunctionTagManager tagManager = getTagManager(program);
			tagManager.createFunctionTag(name, comment);
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	/**
	 * Deletes a tag from the database.
	 * 
	 * @param program the program to delete the tag from
	 * @param name the tag name
	 * @throws IOException
	 */
	private void deleteTag(Program program, String name) throws IOException {
		int transactionID = program.startTransaction("delete");
		try {
			FunctionTagManager tagManager = getTagManager(program);
			FunctionTag tag = tagManager.getFunctionTag(name);
			tag.delete();
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	/**
	 * Updates a tag with a new name.
	 * 
	 * @param program the program version to use
	 * @param origName the tag to change
	 * @param newName the new tag name
	 * @throws IOException
	 */
	private void editTagName(Program program, String origName, String newName) throws IOException {
		FunctionTagManager tagManager = getTagManager(program);
		FunctionTag tag = tagManager.getFunctionTag(origName);
		assertNotNull(tag);
		tag.setName(newName);
	}

	/**
	 * Updates a tag with a new comment.
	 * 
	 * @param program the program version to use
	 * @param tagName the tag to change
	 * @param newComment the new tag comment
	 * @throws IOException
	 */
	private void editTagComment(Program program, String tagName, String newComment)
			throws IOException {
		FunctionTagManager tagManager = getTagManager(program);
		FunctionTag tag = tagManager.getFunctionTag(tagName);
		assertNotNull(tag);
		tag.setComment(newComment);
	}

	/**
	 * Returns the tag manager for the given program.
	 * 
	 * @param program the program version
	 * @return
	 */
	private FunctionTagManager getTagManager(Program program) {
		FunctionManagerDB functionManagerDB = (FunctionManagerDB) program.getFunctionManager();
		return functionManagerDB.getFunctionTagManager();
	}

	/**
	 * Returns all tags in the given program.
	 * 
	 * @param program the program version
	 * @return
	 * @throws IOException
	 */
	private Collection<? extends FunctionTag> getAllTags(Program program) throws IOException {
		FunctionTagManager tagManager = getTagManager(program);
		return tagManager.getAllFunctionTags();
	}

	/**
	 * Converts a string address (ie: "01001001") to an {@link Address} object.
	 * 
	 * @param address the stringified address
	 * @param program the program version
	 * @return
	 */
	private Address addr(String address, Program program) {
		AddressFactory addrFactory = program.getAddressFactory();
		return addrFactory.getAddress(address);
	}

	private int getTagConflictCount() throws Exception {
		VerticalChoicesPanel mergePanel = getMergePanel(VerticalChoicesPanel.class);
		assertNotNull(mergePanel);
		JLabel header = (JLabel) TestUtils.getInstanceField("headerLabel", mergePanel);
		String headerStr = header.getText();
		headerStr = headerStr.replaceAll("[^0-9]+", " ");
		String[] numbers = headerStr.trim().split(" ");
		if (numbers.length >= 2) {
			return Integer.valueOf(numbers[1]);
		}

		return -1;
	}

	private int getTagListingConflictCount() throws Exception {
		ListingMergePanel mergePanel = getMergePanel();
		if (mergePanel == null) {
			return 0; // no merging was being done
		}
		Window window = windowForComponent(mergePanel);
		JComponent comp = findComponent(window, ConflictInfoPanel.class);
		assertNotNull(comp);
		return (Integer) TestUtils.getInstanceField("totalConflicts", comp);
	}
}
