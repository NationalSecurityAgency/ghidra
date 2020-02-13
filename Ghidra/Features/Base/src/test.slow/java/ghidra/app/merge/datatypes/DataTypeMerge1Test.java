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

import java.util.concurrent.atomic.AtomicReference;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Tests for merging data types.
 * 
 * 
 */
public class DataTypeMerge1Test extends AbstractDataTypeMergeTest {

	@Test
	public void testCategoryAddRemoveDTAdd() throws Exception {

		TypeDef td = new TypedefDataType("BF", IntegerDataType.dataType);

		AtomicReference<Structure> structRef = new AtomicReference<>();

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {

				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {

					Structure struct =
						new StructureDataType("Test", 0, program.getDataTypeManager());
					struct.add(new ByteDataType());
					struct.add(new WordDataType());
					struct.insertBitFieldAt(3, 2, 6, td, 2, "bf1", null);
					struct.insertBitFieldAt(3, 2, 4, td, 2, "bf2", null);
					struct.add(new QWordDataType());

					struct.setFlexibleArrayComponent(td, "flex", "my flex");

					structRef.set(struct);

					c.removeCategory("Category5", TaskMonitorAdapter.DUMMY);
					Category c5 = c.createCategory("Category5");
					c5.addDataType(struct, DataTypeConflictHandler.DEFAULT_HANDLER);
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
		executeMerge(-1);
		// should end up with /Category1/Category2/Category5/Test
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
		assertNotNull(c);
		DataType dt = c.getDataType("Test");
		assertNotNull(dt);
		assertTrue(structRef.get().isEquivalent(dt));

	}

	@Test
	public void testDataTypeAddedInMy() throws Exception {

		// A category was added to Category5 in the latest; 
		// in My program, rename Category5 to "My Category5" and add a new data type
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category c = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.createCategory("AnotherCategory");
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.setName("My Category5");
					Structure dt = new StructureDataType("Test", 0);
					dt.add(new ByteDataType());
					dt.add(new WordDataType());
					dt = (Structure) c.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					dt.add(new QWordDataType());
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		// should end up with /Category1/Category2/My Category5/AnotherCategory/Test
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		c = c.getCategory("My Category5");
		DataType dt = c.getDataType("Test");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		assertTrue(dtm.containsCategory(
			new CategoryPath("/Category1/Category2/My Category5/AnotherCategory")));

	}

	@Test
	public void testDataTypeAddedInMy2() throws Exception {

		TypeDef td = new TypedefDataType("BF", IntegerDataType.dataType);

		AtomicReference<Structure> structRef = new AtomicReference<>();

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					Structure s = (Structure) c.getDataType("IntStruct");
					c.remove(s, TaskMonitorAdapter.DUMMY);
					s = new StructureDataType(c.getCategoryPath(), "IntStruct", 0, dtm);
					s.add(new QWordDataType(), "f1", "my f1");
					s.add(new FloatDataType());
					s.add(new ByteDataType());
					s.insertBitFieldAt(16, 2, 6, td, 2, "bf1", "my bf1");
					s.insertBitFieldAt(16, 2, 4, td, 2, "bf2", "my bf2");
					s.add(new WordDataType());

					structRef.set(s);

					c.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
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
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNotNull(dt);
		assertTrue(structRef.get().isEquivalent(dt));

		Structure s = (Structure) dt;
		assertEquals("my f1", s.getComponent(0).getComment());
		DataTypeComponent dtc = s.getComponentAt(17);
		assertEquals(7, dtc.getOrdinal());
		assertEquals("my bf1", dtc.getComment());
	}

	@Test
	public void testDataTypeAddedInMy3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
				try {
					Structure s = (Structure) c.getDataType("IntStruct");
					c.remove(s, TaskMonitorAdapter.DUMMY);
					s = new StructureDataType(c.getCategoryPath(), "IntStruct", 0);
					s.add(new QWordDataType());
					s.add(new FloatDataType());
					s.add(new ByteDataType());
					s.add(new WordDataType());
					DataType newDt = c.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
					// move to MISC
					c = dtm.getCategory(new CategoryPath("/MISC"));
					c.moveDataType(newDt, DataTypeConflictHandler.DEFAULT_HANDLER);
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
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		c = dtm.getCategory(new CategoryPath("/MISC"));
		dt = c.getDataType("IntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertTrue(new QWordDataType().isEquivalent(s.getComponent(0).getDataType()));
		assertTrue(new FloatDataType().isEquivalent(s.getComponent(1).getDataType()));
		assertTrue(new ByteDataType().isEquivalent(s.getComponent(2).getDataType()));
		assertTrue(new WordDataType().isEquivalent(s.getComponent(3).getDataType()));

	}

	@Test
	public void testDataTypeAddedInLatest() throws Exception {

		// Add A category to Category5 in the latest, add 
		// add a new data type; 
		// in My program, rename Category5 to "My Category5" 
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category c = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.createCategory("AnotherCategory");
					Structure dt = new StructureDataType("Test", 0);
					dt.add(new ByteDataType());
					dt.add(new WordDataType());
					dt = (Structure) c.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					dt.add(new QWordDataType());
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.setName("My Category5");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		c = c.getCategory("My Category5");
		DataType dt = c.getDataType("Test");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);

	}

	@Test
	public void testDataTypeAddedInLatest2() throws Exception {

		// A category was added to Category5 in the latest; 
		// in My program, rename Category5 to "My Category5" and add a new data type
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				// change the name
				int transactionID = program.startTransaction("test");
				Category c = program.getDataTypeManager().getCategory(
					new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.createCategory("AnotherCategory");
					StructureDataType dt = new StructureDataType("Test", 0);
					dt.add(new ByteDataType());
					dt.add(new WordDataType());
					c.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got Invalid Name Exception! " + e.getMessage());
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				try {
					c.setName("My Category5");
					StructureDataType dt = new StructureDataType("struct_1", 0);
					dt.add(new QWordDataType());
					dt.add(new ByteDataType());
					c.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		c = c.getCategory("My Category5");
		DataType dt = c.getDataType("Test");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);

		dt = c.getDataType("struct_1");
		assertNotNull(dt);
		assertEquals(2, ((Structure) dt).getNumComponents());
		assertNotNull(c.getCategory("AnotherCategory"));
	}

	@Test
	public void testDataTypeDeletedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		assertNull(dtm.getDataType(c.getCategoryPath(), "IntStruct"));
	}

	@Test
	public void testDataTypeAddedDeletedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				CategoryPath path = new CategoryPath("/Category1/Category2/Category3");
				Structure s = new StructureDataType(path, "my_struct", 5);

				try {
					DataType dt = dtm.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("my_struct");
		assertNull(dt);
		assertNull(dtm.getDataType(c.getCategoryPath(), "my_struct"));
	}

	@Test
	public void testDataTypeDeletedChanged() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		assertNull(dtm.getDataType(c.getCategoryPath(), "IntStruct"));
	}

	@Test
	public void testDataTypeDeletedChanged2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
					"FloatStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
					"FloatStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_LATEST);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
		DataType dt = c.getDataType("FloatStruct");
		assertNotNull(dt);
	}

	@Test
	public void testDataTypeDeletedChanged3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNotNull(dt);
	}

	@Test
	public void testDataTypeDeletedInLatest() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");

				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				try {
					foo.insert(1, dt);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		// CoolUnion should not have been added back in
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNull(dt);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		DataTypeComponent[] dtcs = foo.getComponents();
		// components 1-97 should be default data types
		for (int i = 1; i < 97; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}
	}

	@Test
	public void testDataTypeDeletedInBoth() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		assertNull(dtm.getDataType(c.getCategoryPath(), "IntStruct"));
	}

	@Test
	public void testDataTypeRenamedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("MyIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("MyIntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
	}

	@Test
	public void testRenamedBoth() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("MyNewIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("MyNewIntStruct");
		assertNotNull(dt);
	}

	@Test
	public void testRenamedBoth2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("MyNewIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_LATEST);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("MyNewIntStruct");
		assertNull(dt);
		assertNotNull(c.getDataType("OtherIntStruct"));
	}

	@Test
	public void testDeletedInMyRenamedInLatest() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNull(c.getDataType("IntStruct"));
	}

	@Test
	public void testDeletedInLatestRenamedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dtm.remove(dt, TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNotNull(c.getDataType("OtherIntStruct"));
		assertNull(c.getDataType("IntStruct"));
	}

	@Test
	public void testDeletedInLatestChangedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					Category parent = dtm.getCategory(new CategoryPath("/Category1/Category2"));
					parent.removeCategory("Category3", TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Structure s = (Structure) dt;
					s.add(new FloatDataType());
					Category parent =
						dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
					s = (Structure) s.copy(s.getDataTypeManager());
					s.setName("My_Int_Copy");
					parent.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNotNull(c.getDataType("OtherIntStruct"));
		assertNull(c.getDataType("IntStruct"));
		assertNotNull(c.getDataType("My_Int_Copy"));
	}

	@Test
	public void testDeletedInLatestAddedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					Category parent = dtm.getCategory(new CategoryPath("/Category1/Category2"));
					parent.removeCategory("Category3", TaskMonitorAdapter.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					Category parent =
						dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
					s = (Structure) s.copy(dtm);
					s.setName("My_Int_Copy");
					parent.addDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		assertNull(c.getDataType("IntStruct"));
		assertNotNull(c.getDataType("My_Int_Copy"));
		assertEquals(1, c.getDataTypes().length);
	}

	@Test
	public void testCompositeCommentChanged() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");

				try {
					DataTypeComponent dtc = s.getComponent(0);
					dtc.setFieldName("Field One");
					commit = true;
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got duplicate name exception!");
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");

				try {
					DataTypeComponent dtc = s.getComponent(2);
					dtc.setFieldName("My Field Three");
					dtc.setComment("my comments for Field 3");
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
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		DataTypeComponent dtc = s.getComponent(2);
		assertEquals("My Field Three", dtc.getFieldName());
		assertEquals("my comments for Field 3", dtc.getComment());

		dtc = s.getComponent(0);
		assertEquals("field0", dtc.getFieldName());
	}
}
