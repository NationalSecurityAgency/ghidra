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
 * Test category merge conflicts.
 */
public class CategoryMerge4Test extends AbstractDataTypeMergeTest {

	@Test
    public void testMoveDataType() throws Exception {

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
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				DataType dt = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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
				Category c =
					dtm.createCategory(new CategoryPath("/Category1/Category2/My Category"));
				DataType dt = dtm.getDataType(new CategoryPath("/MISC"), "Foo");

				try {
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					dt.setName("My_Foo");
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got invalid name exception!");
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

		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/My Category")));
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/My Category"));
		assertNotNull(c.getDataType("My_Foo"));

		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Foo"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataType2() throws Exception {

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
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				DataType dt = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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
				Category c =
					dtm.createCategory(new CategoryPath("/Category1/Category2/My Category"));
				DataType dt = dtm.getDataType(new CategoryPath("/MISC"), "Foo");

				try {
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					dt.setName("My_Foo");
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got invalid name exception!");
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
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// 

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/My Category")));
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/My Category"));
		assertNull(c.getDataType("My_Foo"));

		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "Foo"));
		assertNotNull(dtm.getDataType(new CategoryPath("/MISC"), "Foo"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypeNoConflict() throws Exception {

		// Latest: no changes 
		// My: move a data type

		mtf.initialize("notepad2", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// no-op
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c =
					dtm.createCategory(new CategoryPath("/Category1/Category2/My Category"));
				DataType dt = dtm.getDataType(new CategoryPath("/MISC"), "Foo");

				try {
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/My Category")));
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/My Category"));
		assertNotNull(c.getDataType("Foo"));

		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Foo"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveMultipleDataTypes() throws Exception {

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
				DataType foo = dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				DataType td = dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
				DataType bar = dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				DataType dll = dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				try {
					c1.moveDataType(bar, DataTypeConflictHandler.DEFAULT_HANDLER);
					c3.moveDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					newc.moveDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER);
					c1.moveDataType(dll, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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

		waitForCompletion();

		assertNotNull(dtm.getDataType(new CategoryPath("/Category1"), "DLL_Table"));
		assertNull(dtm.getDataType(new CategoryPath("/"), "DLL_Table"));

		assertNotNull(dtm.getDataType(new CategoryPath("/Category1/Category2"), "Bar"));
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Bar"));

		assertNotNull(dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Foo"));
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "MY_Foo"));

		assertNotNull(dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef"));
		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/TestCategory"), "FooTypedef"));
		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "FooTypedef"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypesNoConflict() throws Exception {

		// Latest: rename MISC to MY_MISC
		// My: create MISC_TEMP, move all data types from MISC to MISC_TEMP,
		//

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MISC_TEMP"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_MISC")));
		assertTrue(dtm.containsCategory(new CategoryPath("/MISC_TEMP")));
		Category c = dtm.getCategory(new CategoryPath("/MISC_TEMP"));
		DataType[] dts = c.getDataTypes();
		assertEquals(7, dts.length);
		checkConflictCount(0);

	}

	@Test
    public void testMoveDataTypes() throws Exception {

		// Latest: rename MISC to MY_MISC
		// My: create MISC_TEMP, move all data types from MISC to MISC_TEMP,
		// delete MISC

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MISC_TEMP"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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

		assertTrue(!dtm.containsCategory(new CategoryPath("/MY_MISC")));
		assertTrue(dtm.containsCategory(new CategoryPath("/MISC_TEMP")));
		Category c = dtm.getCategory(new CategoryPath("/MISC_TEMP"));
		DataType[] dts = c.getDataTypes();
		assertEquals(7, dts.length);
		checkConflictCount(0);

	}

	@Test
    public void testMoveDataTypes2() throws Exception {

		// Latest: rename MISC to MY_MISC
		// My: create MY_MISC, move all data types from MISC to MY_MISC,
		// delete MISC

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MY_MISC"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_MISC")));
		Category c = dtm.getCategory(new CategoryPath("/MY_MISC"));
		DataType[] dts = c.getDataTypes();
		assertEquals(7, dts.length);
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes3() throws Exception {

		// Latest: rename MISC to MY_MISC
		// My: create MY_MISC, move all data types from MISC to MY_MISC,
		// delete MISC

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MY_MISC"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_MISC")));
		Category c = dtm.getCategory(new CategoryPath("/MY_MISC"));
		DataType[] dts = c.getDataTypes();
		assertEquals(7, dts.length);
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes4() throws Exception {

		// Latest: rename MISC to MY_MISC; edit Foo
		// My: create MY_MISC, move all data types from MISC to MY_MISC,
		// delete MISC

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
					Structure foo = (Structure) misc.getDataType("Foo");
					foo.add(new FloatDataType());
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MY_MISC"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY MISC

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MY_MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(7, dts.length);
		Structure foo = (Structure) misc.getDataType("Foo");
		assertEquals(5, foo.getDefinedComponents().length);
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes5() throws Exception {

		// Latest: rename MISC to MY_MISC; edit Foo
		// My: create MY_MISC, move all data types from MISC to MY_MISC,
		// delete MISC, move Foo to /Category1

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
					Structure foo = (Structure) misc.getDataType("Foo");
					foo.add(new FloatDataType());
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();
				Structure foo = (Structure) misc.getDataType("Foo");

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MY_MISC"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					// move Foo to /Category1
					Category c1 = dtm.getCategory(new CategoryPath("/Category1"));
					c1.moveDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_MY);// my Foo in /Category1

		chooseOption(DataTypeMergeManager.OPTION_MY);// delete /MISC

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MY_MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(6, dts.length);
		Structure foo = (Structure) misc.getDataType("Foo");
		assertNull(foo);

		foo = (Structure) dtm.getDataType(new CategoryPath("/Category1"), "Foo");
		assertNotNull(foo);
		assertEquals(4, foo.getDefinedComponents().length);
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes6() throws Exception {

		// Latest: rename MISC to MY_MISC; edit Foo
		// My: create MY_MISC, move all data types from MISC to MY_MISC,
		// delete MISC, move Foo to /Category1

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				try {
					misc.setName("MY_MISC");
					Structure foo = (Structure) misc.getDataType("Foo");
					foo.add(new FloatDataType());
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();
				Structure foo = (Structure) misc.getDataType("Foo");

				try {
					Category temp = dtm.createCategory(new CategoryPath("/MY_MISC"));
					for (DataType dt : dts) {
						temp.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					// move Foo to /Category1
					Category c1 = dtm.getCategory(new CategoryPath("/Category1"));
					c1.moveDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST Foo in 

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST /MISC

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MY_MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(7, dts.length);
		Structure foo = (Structure) misc.getDataType("Foo");
		assertNotNull(foo);
		assertEquals(5, foo.getDefinedComponents().length);
		assertNull(dtm.getDataType(new CategoryPath("/Category1"), "Foo"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes7() throws Exception {

		// Latest: move data types from MISC to NEW_MISC; delete MISC;
		// rename NEW_MISC to MISC
		// My: rename data types in MISC
		// should not result in conflicts

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category newMisc = dtm.createCategory(new CategoryPath("/NEW_MISC"));
				DataType[] dts = misc.getDataTypes();
				try {
					for (DataType dt : dts) {
						newMisc.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					newMisc.setName("MISC");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got invalid name exception!");
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						dt.setName("MY_" + dt.getName());
					}
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
		executeMerge(true);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertTrue(dtm.containsCategory(new CategoryPath("/MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(7, dts.length);
		for (DataType dt : dts) {
			assertTrue(dt.getName().indexOf("MY_") == 0);
		}
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes8() throws Exception {

		// Latest: delete MISC;
		// My: move data types from MISC to /Category1/Category2
		// should result in conflicts

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
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						c2.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got exception: " + e);
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		for (int i = 0; i < 7; i++) {
			chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		}
		waitForCompletion();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC")));
		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType[] dts = c2.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || (dt instanceof Pointer)) {
				continue;
			}
			++count;
		}
		assertEquals(10, count);
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypes9() throws Exception {

		// Latest: move data types from MISC to /Category1/Category2
		// My:  delete MISC
		// should result in conflicts

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						c2.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got exception: " + e);
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
				try {
					root.removeCategory("MISC", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		for (int i = 0; i < 7; i++) {
			chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST data type 
		}
		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC")));
		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType[] dts = c2.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || (dt instanceof Pointer)) {
				continue;
			}
			++count;
		}
		assertEquals(10, count);
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypesAndEdit() throws Exception {

		// Latest: delete MISC;
		// My: move data types from MISC to /Category1/Category2
		// should result in conflicts

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
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						c2.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					// rename FooTypedef to MyFooTypedef
					DataType dt = c2.getDataType("FooTypedef");
					dt.setName("My_FooTypeDEF");
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got exception: " + e);
				}
				catch (Exception e) {
					Assert.fail(e.toString());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		for (int i = 0; i < 7; i++) {
			chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		}
		waitForCompletion();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC")));
		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType[] dts = c2.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || (dt instanceof Pointer)) {
				continue;
			}
			++count;
		}
		assertEquals(10, count);
		assertNotNull(c2.getDataType("My_FooTypeDEF"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypesAndEdit2() throws Exception {

		// Latest: delete MISC;
		// My: move data types from MISC to /Category1/Category2
		// should result in conflicts

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
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						c2.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					// rename FooTypedef to MyFooTypedef
					DataType dt = c2.getDataType("FooTypedef");
					dt.setName("My_FooTypeDEF");
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got exception: " + e);
				}
				catch (Exception e) {
					Assert.fail(e.toString());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// ORIGINAL FooTypedef 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(1, dts.length);
		assertEquals("FooTypedef", dts[0].getName());

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		dts = c2.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || (dt instanceof Pointer)) {
				continue;
			}
			++count;
		}
		assertEquals(9, count);
		assertNull(c2.getDataType("FooTypedef"));
		assertNull(c2.getDataType("My_FooTypeDEF"));
		checkConflictCount(0);
	}

	@Test
    public void testMoveDataTypesAndEdit3() throws Exception {

		// Latest: delete MISC;
		// My: move data types from MISC to /Category1/Category2
		// should result in conflicts

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
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						c2.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					}
					// edit Foo
					Structure foo = (Structure) c2.getDataType("Foo");
					foo.add(new ByteDataType());
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got exception: " + e);
				}
				catch (Exception e) {
					Assert.fail(e.toString());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// ORIGINAL Foo

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 
		chooseOption(DataTypeMergeManager.OPTION_MY);// MY data type 

		waitForCompletion();

		assertTrue(dtm.containsCategory(new CategoryPath("/MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(1, dts.length);
		assertEquals("Foo", dts[0].getName());

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		dts = c2.getDataTypes();
		int count = 0;
		for (DataType dt : dts) {
			if ((dt instanceof Array) || (dt instanceof Pointer)) {
				continue;
			}
			++count;
		}
		assertEquals(9, count);
		assertNull(c2.getDataType("Foo"));
		checkConflictCount(0);
	}

	@Test
    public void testDeleteDataTypes() throws Exception {

		// Latest: move MISC to /Category1/Category2
		// My: delete data types in MISC
		// should not result in conflicts

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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));

				try {
					c2.moveCategory(misc, TaskMonitorAdapter.DUMMY_MONITOR);
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
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						misc.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					}
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(true);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/MISC"));
		assertNull(misc);
		misc = dtm.getCategory(new CategoryPath("/Category1/Category2/MISC"));
		DataType[] dts = misc.getDataTypes();
		assertEquals(0, dts.length);
		checkConflictCount(0);
	}

	@Test
    public void testDeleteDataTypes2() throws Exception {

		// Latest: delete data types in MISC
		// My: move MISC to /Category1/Category2
		// no conflicts

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				DataType[] dts = misc.getDataTypes();

				try {
					for (DataType dt : dts) {
						misc.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
					}
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
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category misc = dtm.getCategory(new CategoryPath("/MISC"));
				Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));

				try {
					c2.moveCategory(misc, TaskMonitorAdapter.DUMMY_MONITOR);
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
		executeMerge(true);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertTrue(!dtm.containsCategory(new CategoryPath("/MISC")));
		assertTrue(dtm.containsCategory(new CategoryPath("/Category1/Category2/MISC")));
		Category misc = dtm.getCategory(new CategoryPath("/Category1/Category2/MISC"));
		assertEquals(0, misc.getDataTypes().length);
		checkConflictCount(0);
	}

	@Test
    public void testMoveCategories() throws Exception {

		// Latest: rename A to MY_A
		// My: create A_TEMP, move all categories from A to A_TEMP,
		// delete A

		mtf.initialize("notepad4", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category a = dtm.getCategory(new CategoryPath("/A"));
				try {
					a.setName("MY_A");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category a = dtm.getCategory(new CategoryPath("/A"));
				Category[] cats = a.getCategories();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/A_TEMP"));
					for (Category cat : cats) {
						temp.moveCategory(cat, TaskMonitorAdapter.DUMMY_MONITOR);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("A", TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				catch (Exception e) {
					Assert.fail(e.toString());
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

		assertTrue(!dtm.containsCategory(new CategoryPath("/MY_A")));
		assertTrue(dtm.containsCategory(new CategoryPath("/A_TEMP")));
		Category c = dtm.getCategory(new CategoryPath("/A_TEMP"));
		Category[] cats = c.getCategories();
		assertEquals(2, cats.length);
		checkConflictCount(0);

	}

	@Test
    public void testMoveCategories2() throws Exception {

		// Latest: rename A to MY_A
		// My: create A_TEMP, move all categories from A to A_TEMP,
		// delete A
		// rename A_TEMP to MY_A

		mtf.initialize("notepad4", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				DataTypeManager dtm = program.getDataTypeManager();
				Category a = dtm.getCategory(new CategoryPath("/A"));
				try {
					a.setName("MY_A");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category a = dtm.getCategory(new CategoryPath("/A"));
				Category[] cats = a.getCategories();

				try {
					Category temp = dtm.createCategory(new CategoryPath("/A_TEMP"));
					for (Category cat : cats) {
						temp.moveCategory(cat, TaskMonitorAdapter.DUMMY_MONITOR);
					}
					Category root = dtm.getCategory(CategoryPath.ROOT);
					root.removeCategory("A", TaskMonitorAdapter.DUMMY_MONITOR);
					temp.setName("MY_A");
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.toString());
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

		assertTrue(dtm.containsCategory(new CategoryPath("/MY_A")));
		assertTrue(!dtm.containsCategory(new CategoryPath("/A_TEMP")));
		Category c = dtm.getCategory(new CategoryPath("/MY_A"));
		Category[] cats = c.getCategories();
		assertEquals(2, cats.length);
		checkConflictCount(0);

	}
}
