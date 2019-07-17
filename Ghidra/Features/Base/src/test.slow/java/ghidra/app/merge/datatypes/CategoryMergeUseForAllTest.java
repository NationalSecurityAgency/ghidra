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
package ghidra.app.merge.datatypes;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Tests for the merge data type manager.
 */
public class CategoryMergeUseForAllTest extends AbstractDataTypeMergeTest {

	@Test
    public void testCategoryDoNotUseForAll() throws Exception {

		// Set up multiple category conflicts and choose my for all using the checkbox.
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat1 =
					program.getDataTypeManager().getCategory(new CategoryPath("/Category1"));
				Category cat2 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
//				Category cat4 =
//					program.getDataTypeManager().getCategory(
//						new CategoryPath("/Category1/Category2/Category4"));
				try {
					miscCat.setName("My Misc");
					cat1.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					DataTypeManager dtm = program.getDataTypeManager();
					dtm.createCategory(new CategoryPath("/newCat"));
					cat2.removeCategory("Category4", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				Category cat4 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category4"));
				try {
					miscCat.setName("Some Other Misc");
					cat4.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose My program
		executeMerge();
		resolveCategoryConflict(DataTypeMergeManager.OPTION_MY, false,
			"/Category1/Category2/Category3");
		resolveCategoryConflict(DataTypeMergeManager.OPTION_ORIGINAL, false, "/MISC");
		waitForMergeCompletion();

		// Original
		// Verify results
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		// expect category "Some Other Misc" to exist in results program
		assertNotNull(root.getCategory("MISC"));
		assertNull(root.getCategory("My Misc"));
		assertNull(root.getCategory("Some Other Misc"));
	}

	@Test
    public void testCategoryUseForAllPickLatest() throws Exception {

		// Set up multiple category conflicts and choose my for all using the checkbox.
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat1 =
					program.getDataTypeManager().getCategory(new CategoryPath("/Category1"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				try {
					miscCat.setName("My Misc");
					cat1.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				Category cat4 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category4"));
				try {
					miscCat.setName("Some Other Misc");
					cat4.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose My program
		executeMerge();
		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class,
			DataTypeMergeManager.OPTION_MY, true);
		waitForMergeCompletion();

		// Verify results
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		// expect category "Some Other Misc" to exist in results program
		assertNull(root.getCategory("MISC"));
		assertNotNull(root.getCategory("Some Other Misc"));
	}

	@Test
    public void testCategoryUseForAllPickMy() throws Exception {

		// Set up multiple category conflicts and choose my for all using the checkbox.
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat1 =
					program.getDataTypeManager().getCategory(new CategoryPath("/Category1"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				try {
					miscCat.setName("My Misc");
					cat1.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				Category cat4 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category4"));
				try {
					miscCat.setName("Some Other Misc");
					cat4.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose My program
		executeMerge();
		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class,
			DataTypeMergeManager.OPTION_MY, true);
		waitForMergeCompletion();

		// Verify results
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		// expect category "Some Other Misc" to exist in results program
		assertNull(root.getCategory("MISC"));
		assertNotNull(root.getCategory("Some Other Misc"));
	}

	@Test
    public void testCategoryUseForAllPickOriginal() throws Exception {

		// Set up multiple category conflicts and choose my for all using the checkbox.
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat1 =
					program.getDataTypeManager().getCategory(new CategoryPath("/Category1"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				try {
					miscCat.setName("My Misc");
					cat1.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				Category cat4 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category4"));
				try {
					miscCat.setName("Some Other Misc");
					cat4.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		// choose My program
		executeMerge();
		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class,
			DataTypeMergeManager.OPTION_ORIGINAL, true);// Category /Category1/Category2/Category3
//		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class,
//			DataTypeMergeManager.OPTION_ORIGINAL, false); // Category /Misc  gets handled by "Use For All".
		waitForMergeCompletion();

		// Verify results
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		// expect category "Some Other Misc" to exist in results program
		assertNotNull(root.getCategory("MISC"));
		assertNull(root.getCategory("Some Other Misc"));
		Category category1 = root.getCategory("Category1");
		assertNotNull(category1);
		Category category2 = category1.getCategory("Category2");
		assertNotNull(category2);
		Category category3 = category2.getCategory("Category3");
		assertNotNull(category3);
		Category category4 = category2.getCategory("Category4");
		assertNotNull(category4);
		Category wrong1243 = category4.getCategory("Category3");
		assertNull(wrong1243);
		Category wrong13 = category1.getCategory("Category3");
		assertNull(wrong13);
	}

	@Test
    public void testDataTypeDoNotUseForAll() throws Exception {

		// Set up multiple category conflicts and choose my for all using the checkbox.
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat1 =
					program.getDataTypeManager().getCategory(new CategoryPath("/Category1"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				try {
					miscCat.setName("My Misc");
					cat1.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category cat3 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category3"));
				Category cat4 = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category4"));
				try {
					miscCat.setName("Some Other Misc");
					cat4.moveCategory(cat3, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!" + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose My program
		executeMerge();
		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class,
			DataTypeMergeManager.OPTION_MY, false);
		resolveConflict(CategoryMergePanel.class, CategoryConflictPanel.class,
			DataTypeMergeManager.OPTION_MY, false);
		waitForMergeCompletion();

		// Verify results
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		// expect category "Some Other Misc" to exist in results program
		assertNull(root.getCategory("MISC"));
		assertNotNull(root.getCategory("Some Other Misc"));
	}
}
