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
import ghidra.util.task.TaskMonitor;

public class CategoryMerge3Test extends AbstractDataTypeMergeTest {

	public static final int MAX_WAIT = 5000;

	@Test
	public void testEditFuncSig() throws Exception {
		// test is here to see what the FunctionDefinition looks like

		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				FunctionDefinition fd =
					(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"),
						"MyFunctionDef");

				try {
					fd.setReturnType(bar);
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
			public void modifyPrivate(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				FunctionDefinition fd =
					(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"),
						"MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();

				int transactionID = program.startTransaction("test");
				try {
					vars[0].setDataType(foo);
					vars[0].setComment("this is a comment");
					Pointer p = PointerDataType.getPointer(foo, 4);
					vars[1].setDataType(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		chooseOption(DataTypeMergeManager.OPTION_MY);// 

		waitForCompletion();
	}

	@Test
	public void testCategoryDeleteMoveConflicts() throws Exception {
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
					destCat.moveCategory(miscCat, TaskMonitor.DUMMY);
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
					root.removeCategory("MISC", TaskMonitor.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// 

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category root = dtm.getCategory(CategoryPath.ROOT);
		assertNull(root.getCategory("MISC"));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category3/MISC")));
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
					root.moveCategory(c, TaskMonitor.DUMMY);
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
					miscCat.moveCategory(c, TaskMonitor.DUMMY);
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
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// 

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertTrue(dtm.containsCategory(new CategoryPath("/MISC/My Category3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Other Category3")));
		checkConflictCount(0);
	}

	@Test
	public void testCategoryMoveRename() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root
		//My Program: rename Category1/Category2/Category3 to "My Category3",

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
					root.moveCategory(c, TaskMonitor.DUMMY);
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
		});
		executeMerge();
		chooseOption(DataTypeMergeManager.OPTION_MY);// 

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/My Category3")));
		checkConflictCount(0);
	}

	@Test
	public void testCategoryMoveRename2() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root
		//My Program: rename Category1/Category2/Category3 to "My Category3",

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
					root.moveCategory(c, TaskMonitor.DUMMY);
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
		});
		executeMerge();
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// 

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		assertTrue(dtm.containsCategory(new CategoryPath("/Category3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/My Category3")));

		checkConflictCount(0);
	}

	@Test
	public void testCategoryMove() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root
		//My: move Category1/Category2/Category3 to /MISC

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
					root.moveCategory(c, TaskMonitor.DUMMY);
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
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c, TaskMonitor.DUMMY);
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
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_MY);// 

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MISC/Category3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category3")));
		checkConflictCount(0);
	}

	@Test
	public void testCategoryMove2() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root
		//My: move Category1/Category2/Category3 to /MISC

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
					root.moveCategory(c, TaskMonitor.DUMMY);
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
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c, TaskMonitor.DUMMY);
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
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// 

		waitForCompletion();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC/Category3")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category3")));
		checkConflictCount(0);
	}

	@Test
	public void testCategoryMove3() throws Exception {

		//Latest: move Category1/Category2/Category3 to Root
		//My: move Category1/Category2/Category3 to /MISC

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
					root.moveCategory(c, TaskMonitor.DUMMY);
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
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c, TaskMonitor.DUMMY);
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
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// 

		waitForCompletion();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC/Category3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category3")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/Category3")));
		checkConflictCount(0);
	}

	@Test
	public void testMoveCategoriesAndDataTypes() throws Exception {

		// Latest: move data type
		// My: move same data type

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c1 = dtm.getCategory(new CategoryPath("/Category1"));
				Category newc =
					dtm.createCategory(new CategoryPath("/Category1/Category2/TestCategory"));
				Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));

				DataType foo = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				DataType td = dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
				DataType bar = dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				DataType dll = dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				try {
					c1.moveDataType(bar, DataTypeConflictHandler.DEFAULT_HANDLER);
					c3.moveDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					newc.moveDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER);
					c1.moveDataType(dll, DataTypeConflictHandler.DEFAULT_HANDLER);

					c3.moveCategory(misc, TaskMonitor.DUMMY);

					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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
				int transactionID = program.startTransaction("test");
				Category c1 = dtm.getCategory(new CategoryPath("/Category1"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType foo = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				DataType td = dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
				DataType bar = dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				DataType dll = dtm.getDataType(CategoryPath.ROOT, "DLL_Table");

				try {
					c1.moveDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					c2.moveDataType(bar, DataTypeConflictHandler.DEFAULT_HANDLER);
					c3.moveDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER);
					c3.moveDataType(dll, DataTypeConflictHandler.DEFAULT_HANDLER);
					foo.setName("MY_Foo");
					c1.moveCategory(misc, TaskMonitor.DUMMY);

					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Latest DLL

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose My Bar

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Latest Foo 

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose original FooTypedef

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose my MISC

		waitForCompletion();

		DataType dataType = dtm.getDataType(new CategoryPath("/Category1/MISC"), "FavoriteColors");
		assertNotNull(dataType);

		assertNotNull(dtm.getDataType(new CategoryPath("/Category1"), "DLL_Table"));
		assertNull(dtm.getDataType(new CategoryPath("/"), "DLL_Table"));

		assertNotNull(dtm.getDataType(new CategoryPath("/Category1/Category2"), "Bar"));
		assertNull(dtm.getDataType(new CategoryPath("/Category1/MISC"), "Bar"));

		assertNotNull(dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "MY_Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/Category1/MISC"), "Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/Category1/MISC"), "MY_Foo"));

		assertNotNull(dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef"));
		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/TestCategory"), "FooTypedef"));
		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "FooTypedef"));
		checkConflictCount(0);
	}

	@Test
	public void testMoveCategory() throws Exception {

		// move same category in Latest and My

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));

				try {
					c5.moveCategory(c, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_MY);// 

		waitForCompletion();

		assertTrue(
			dtm.containsCategory(new CategoryPath("/Category1/Category2/Category5/Category3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category3")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC/Category3")));
		checkConflictCount(0);

	}

	@Test
	public void testMoveCategory2() throws Exception {

		// Latest: move /Category1/Category2/Category5 to
		// /Category5; move Category1 to /Category5
		// MY: create /Category1/Category2/Category5/MyNewCategory;
		// move Category2 to /Category2
		// move Category1 to /Category2

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c1 = dtm.getCategory(new CategoryPath("/Category1"));
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category root = dtm.getCategory(CategoryPath.ROOT);
				try {
					root.moveCategory(c5, TaskMonitor.DUMMY);
					c5.moveCategory(c1, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category root = dtm.getCategory(CategoryPath.ROOT);

				try {
					Category newc = c5.createCategory("MyNewCategory");
					Structure s = new StructureDataType("my_struct", 0);
					s.add(new ByteDataType());
					s.add(new FloatDataType());
					newc.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);

					root.moveCategory(c2, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got invalid name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		// no conflicts

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/Category5/Category1")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category2/Category5/MyNewCategory")));
		assertNotNull(
			dtm.getDataType(new CategoryPath("/Category2/Category5/MyNewCategory"), "my_struct"));

		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category5")));
		Category c5 = dtm.getCategory(new CategoryPath("/Category2/Category5"));
		assertEquals(0, c5.getDataTypes().length);

		c5 = dtm.getCategory(new CategoryPath("/Category5"));
		DataType[] dts = c5.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || dt instanceof Pointer) {
				continue;
			}
			++count;
		}

		assertEquals(1, count);
		checkConflictCount(0);
	}

	@Test
	public void testMoveCategory3() throws Exception {

		// Latest: rename /Category1/Category2 to myCategory2; 
		// move data types in /Category1/myCategory2/Category4 to
		// /Category1/myCategory2; 
		// MY: move data types in /Category1/Category2/Category4 to 
		// /Category1/Category2

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c1 = dtm.getCategory(new CategoryPath("/Category1"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));

				try {
					c2.setName("myCategory2");
					Category newc = c1.createCategory("Category2");
					DataType[] dts = c4.getDataTypes();
					for (DataType dt : dts) {
						newc.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got invalid name exception!");
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got data type dependency exception!");
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
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));

				try {
					DataType[] dts = c4.getDataTypes();
					for (DataType dt : dts) {
						c2.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}

					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got data type dependency exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		// no conflicts

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/myCategory2")));

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType[] dts = c2.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || dt instanceof Pointer) {
				continue;
			}
			++count;
		}
		assertEquals(1, count);
		checkConflictCount(0);
	}

	@Test
	public void testMoveMultipleCategories() throws Exception {

		// move same category in Latest and My

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c3, TaskMonitor.DUMMY);
					c5.moveCategory(misc, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));

				try {
					c4.moveCategory(c3, TaskMonitor.DUMMY);
					c5.moveCategory(misc, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// latest Category3 

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/Category5/MISC")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/Category1/Category2/Category3")));
		checkConflictCount(0);

	}

	@Test
	public void testMoveMultipleCategories2() throws Exception {

		// move same category in Latest and My

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c3, TaskMonitor.DUMMY);
					c4.moveCategory(misc, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));

				try {
					c4.moveCategory(c3, TaskMonitor.DUMMY);
					c5.moveCategory(misc, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);// my Category3 
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// latest MISC 

		waitForCompletion();

		assertTrue(
			dtm.containsCategory(new CategoryPath("/Category1/Category2/Category4/Category3")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/Category4/MISC")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC")));
		checkConflictCount(0);
	}

	@Test
	public void testMoveCategories() throws Exception {

		//Latest: Move /Category1/Category2/Category5 to /MISC
		// My: Move /MISC to /Category1/Category2/Category5

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.moveCategory(c5, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
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
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));

				try {
					c5.moveCategory(misc, TaskMonitor.DUMMY);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		waitForCompletion();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC/Category5")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/Category5/MISC")));
		checkConflictCount(0);

	}
}
