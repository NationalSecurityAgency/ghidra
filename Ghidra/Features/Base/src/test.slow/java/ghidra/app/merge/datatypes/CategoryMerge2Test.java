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

import static org.junit.Assert.*;

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
 * 
 * 
 */
public class CategoryMerge2Test extends AbstractDataTypeMergeTest {

	@Test
    public void testCategoryDeletedNoConflicts() throws Exception {
		// delete category in My program; no change in latest program

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes in Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.removeCategory("Category3", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertNull(c.getCategory("Category3"));
		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct"));
		checkConflictCount(0);

	}

	@Test
    public void testCategoryDeletedInBoth() throws Exception {
		// delete category in My program; no change in latest program

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.removeCategory("Category3", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.removeCategory("Category3", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertNull(c.getCategory("Category3"));
		checkConflictCount(0);

	}

	@Test
    public void testCategoryDeleteRenameConflicts() throws Exception {
		// delete Category4 in Latest; in My program rename Category4 to "MyCategory4"

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.removeCategory("Category4", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
				try {
					c.setName("My Category4");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException: " + e);
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException: " + e);
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose my program change
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertTrue(dtm.containsCategory(c.getCategoryPath()));
		assertNotNull(c.getCategory("My Category4"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteRenameConflicts2() throws Exception {
		// in Latest rename Category4 to "MyCategory4; delete Category4 in My program;

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
				try {
					c.setName("My Category4");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException: " + e);
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException: " + e);
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.removeCategory("Category4", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose my latest change
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertTrue(dtm.containsCategory(c.getCategoryPath()));
		assertNull(c.getCategory("My Category4"));
		assertNull(c.getCategory("Category4"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteRenameConflicts3() throws Exception {
		// in Latest rename Category4 to "MyCategory4; delete Category4 in My program;

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
				try {
					c.setName("My Category4");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException: " + e);
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException: " + e);
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.removeCategory("Category4", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose ORIGINAL
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertTrue(dtm.containsCategory(c.getCategoryPath()));
		assertNull(c.getCategory("My Category4"));
		assertNotNull(c.getCategory("Category4"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteMoveConflicts() throws Exception {
		// delete category in Latest program; move same category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// delete MISC 
				int transactionID = program.startTransaction("test");
				Category root = dtm.getCategory(CategoryPath.ROOT);
				try {
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
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
				DataTypeManager dtm = program.getDataTypeManager();
				// move MISC to /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Category miscCat = dtm.getCategory(new CategoryPath("/MISC"));
				Category destCat =
					dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					destCat.moveCategory(miscCat, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose my program change
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		Category destCat = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNotNull(destCat.getCategory("MISC"));
		assertNull(root.getCategory("MISC"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteMoveConflicts2() throws Exception {
		// move category in Latest program; delete same category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move MISC to /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Category miscCat = dtm.getCategory(new CategoryPath("/MISC"));
				Category destCat =
					dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					destCat.moveCategory(miscCat, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				// delete MISC 
				int transactionID = program.startTransaction("test");
				Category root = dtm.getCategory(CategoryPath.ROOT);
				try {
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		// choose my program change
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		Category destCat = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNull(destCat.getCategory("MISC"));
		assertNull(root.getCategory("MISC"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteMoveConflicts3() throws Exception {
		// move category in Latest program; delete same category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move MISC to /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Category miscCat = dtm.getCategory(new CategoryPath("/MISC"));
				Category destCat =
					dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					destCat.moveCategory(miscCat, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				// delete MISC 
				int transactionID = program.startTransaction("test");
				Category root = dtm.getCategory(CategoryPath.ROOT);
				try {
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		// choose ORIGinal 
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		Category destCat = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNull(destCat.getCategory("MISC"));
		assertNotNull(root.getCategory("MISC"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteRenameConflicts4() throws Exception {
		// rename category in Latest program; delete parent category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// rename /Category1/Category2/Category3 to "Other Category 3"
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("Other Category 3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				// delete /Category1/Category2 
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1"));
				try {
					c.removeCategory("Category2", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		// choose My program 
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1"));
		assertNull(c.getCategory("Category2"));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category3")));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteRenameConflicts5() throws Exception {
		// rename category in Latest program; delete parent category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// rename /Category1/Category2/Category3 to "Other Category 3"
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("Other Category 3");
					c.createCategory("Test");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				// delete /Category1/Category2 
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1"));
				try {
					c.removeCategory("Category2", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		// choose original program 
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1"));
		c = c.getCategory("Category2");
		assertNotNull(c);
		assertNotNull(c.getCategory("Category3"));
		assertNull(c.getCategory("Other Category 3"));
		c = c.getCategory("Category3");
		assertNull(c.getCategory("Test"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteRenameConflicts6() throws Exception {
		// rename category in Latest program; delete parent category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// rename /Category1/Category2/Category3 to "Other Category 3"
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("Other Category 3");
					c.createCategory("Test");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				// delete /Category1/Category2 
				int transactionID = program.startTransaction("test");
				Category root = dtm.getCategory(CategoryPath.ROOT);
				try {
					root.removeCategory("Category1", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		// choose original program 
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1"));
		c = c.getCategory("Category2");
		assertNotNull(c);
		assertNotNull(c.getCategory("Category3"));
		assertNull(c.getCategory("Other Category 3"));
		c = c.getCategory("Category3");
		assertNull(c.getCategory("Test"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryDeleteRenameConflicts7() throws Exception {
		// rename category in Latest program; delete parent category in My Program 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// rename /Category1/Category2/Category3 to "Other Category 3"
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("Other Category 3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				// delete /Category1/Category2 
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1"));
				try {
					c.removeCategory("Category2", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		// choose My program 
		executeMerge(DataTypeMergeManager.OPTION_LATEST);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1"));
		assertNotNull(c.getCategory("Category2"));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/Other Category 3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category4")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category5")));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryMoveRenameConflict() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root; rename
		// /Category3 to "Other Category3"
		//My Program: rename Category1/Category2/Category3 to "My Category3",
		// move Category1/Category2/My Category3 to /MISC

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category root = dtm.getCategory(CategoryPath.ROOT);
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					root.moveCategory(c, TaskMonitorAdapter.DUMMY_MONITOR);
					c = root.getCategory(c.getName());
					c.setName("Other Category3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("My Category3");
					miscCat.moveCategory(c, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
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
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		assertNull(root.getCategory("Other Category3"));
		assertNull(root.getCategory("Category3"));

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertNull(c.getCategory("My Category3"));

		c = dtm.getCategory(new CategoryPath("/MISC"));
		assertNotNull(c.getCategory("My Category3"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryMoveRenameConflict2() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root; rename
		// /Category3 to "Other Category3"
		//My Program: rename Category1/Category2/Category3 to "My Category3",
		// move Category1/Category2/My Category3 to /MISC

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category root = dtm.getCategory(CategoryPath.ROOT);
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					root.moveCategory(c, TaskMonitorAdapter.DUMMY_MONITOR);
					c = root.getCategory(c.getName());
					c.setName("Other Category3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category miscCat =
					program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("My Category3");
					miscCat.moveCategory(c, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose original program
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		assertNull(root.getCategory("Other Category3"));
		assertNull(root.getCategory("Category3"));

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertNull(c.getCategory("My Category3"));
		assertNotNull(c.getCategory("Category3"));
		c = dtm.getCategory(new CategoryPath("/MISC"));
		assertNull(c.getCategory("My Category3"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryMoveRenameConflict3() throws Exception {

		//Latest: rename Category1/Category2/Category3 to "My Category3",
		//My program : move Category1/Category2/Category3 to Root; 

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					c.setName("My Category3");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
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
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category root = dtm.getCategory(CategoryPath.ROOT);
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					root.moveCategory(c, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		// choose My program
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category root = resultProgram.getDataTypeManager().getCategory(CategoryPath.ROOT);
		assertNotNull(root.getCategory("Category3"));
		assertNull(root.getCategory("My Category3"));

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		assertNull(c.getCategory("My Category3"));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category3")));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryAddedInMyProgram() throws Exception {

		// In Latest, rename /Category1/Category2/Category5 to 
		// /Category1/Category2/My Category5;
		// in My program, create "AnotherCategory" in
		// /Category1/Category2/Category5
		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category c = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.setName("My Category5");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
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
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c = c.createCategory("AnotherCategory");
					c = c.createCategory("Subcategory");
					// move data type to new category
					DataType foo = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					c.moveDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got Data Dependency Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		// should end up with /Category1/Category2/My Category5/AnotherCategory/Subcategory
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		c = c.getCategory("Category5");
		assertNotNull(c);
		c = c.getCategory("AnotherCategory");
		assertNotNull(c);
		c = c.getCategory("Subcategory");
		assertNotNull(c);
		assertNotNull(c.getDataType("Foo"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryAddedInLatestProgram() throws Exception {
		// In Latest, add "AnotherCategory to /Category1/Category2/Category5; 
		// in my program, rename /Category1/Category2/Category5 to
		// /Category1/Category2/My Category5
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c = c.createCategory("AnotherCategory");
					c.createCategory("Subcategory");
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
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
				// change the name
				int transactionID = program.startTransaction("test");
				Category c = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.setName("My Category5");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		// should end up with /Category1/Category2/My Category5/AnotherCategory/Subcategory
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		c = c.getCategory("My Category5");
		assertNotNull(c);
		c = c.getCategory("AnotherCategory");
		assertNotNull(c);
		assertNotNull(c.getCategory("Subcategory"));
		checkConflictCount(0);
	}

	@Test
    public void testCategoryAddedInLatestProgram2() throws Exception {
		// In Latest, add "AnotherCategory to /Category1/Category2/Category5; 
		// in my program, add a category to /MISC
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c = c.createCategory("AnotherCategory");
					c.createCategory("Subcategory");
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
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
				// change the name
				int transactionID = program.startTransaction("test");
				Category c = program.getDataTypeManager().getCategory(new CategoryPath("/MISC"));
				try {
					c = c.createCategory("MyCategory");
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		// should end up with /Category1/Category2/My Category5/AnotherCategory/Subcategory
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
		c = c.getCategory("AnotherCategory");
		assertNotNull(c);
		assertNotNull(c.getCategory("Subcategory"));
		c = dtm.getCategory(new CategoryPath("/MISC/MyCategory"));
		assertNotNull(c);
		checkConflictCount(0);
	}

	@Test
    public void testCategoryAddedInBoth() throws Exception {
		// In Latest, add "AnotherCategory to /Category1/Category2/Category5; 
		// in my program, add a category to /MISC
		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c = c.createCategory("AnotherCategory");
					c = c.createCategory("Subcategory");
					c.addDataType(new ByteDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
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
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					c = c.createCategory("MyCategory");
					c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
					c.setName("My Category 5");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception! " + e.getMessage());
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		// should end up with /Category1/Category2/My Category5/AnotherCategory/Subcategory
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/My Category 5"));
		c = c.getCategory("AnotherCategory");
		assertNotNull(c);
		assertNotNull(c.getCategory("Subcategory"));
		c = dtm.getCategory(new CategoryPath("/MISC/MyCategory"));
		assertNotNull(c);
		checkConflictCount(0);
	}

	@Test
    public void testCategoryAddedInBoth2() throws Exception {
		// In Latest and My, add same category name; add new data type 
		// to category in My

		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c = c.createCategory("AnotherCategory");
					c = c.createCategory("Subcategory");
					c.addDataType(new ByteDataType(), DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
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
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c = c.createCategory("AnotherCategory");
					c = c.createCategory("Subcategory");
					Structure foo = new StructureDataType("My_Foo", 0);
					foo.add(new ByteDataType());
					foo.add(dtm.getDataType(new CategoryPath("/MISC"), "Bar"));
					c.addDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge(-1);
		// should end up with /Category1/Category2/My Category5/AnotherCategory/Subcategory
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertTrue(dtm.containsCategory(
			new CategoryPath("/Category1/Category2/Category5/AnotherCategory/Subcategory")));
		assertNotNull(dtm.getDataType(
			new CategoryPath("/Category1/Category2/Category5/AnotherCategory/Subcategory"),
			"My_Foo"));
		checkConflictCount(0);
	}
}
