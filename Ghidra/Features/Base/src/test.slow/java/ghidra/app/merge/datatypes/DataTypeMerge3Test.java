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

import ghidra.program.database.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * More data type merge tests.
 * 
 * 
 */
public class DataTypeMerge3Test extends AbstractDataTypeMergeTest {

	@Test
	public void testDeleteUnionComponent() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					// 2 components should get removed from CoolUnion
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
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					union.add(new FloatDataType());
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();

		// choose MY
		chooseOption(DataTypeMergeManager.OPTION_MY);// DLL_Table from MY

		// then choose LATEST
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// DLL_Table should have a Word data type as the last component
		Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		DataTypeComponent dtc = s.getComponent(s.getNumComponents() - 1);
		assertTrue(dtc.getDataType().isEquivalent(new WordDataType()));

		// CoolUnion should not have DLL_Table components
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(3, dtcs.length);
		DataType dt = dtcs[2].getDataType();
		assertTrue(dt instanceof Pointer);

		// DLL_Table should have Word added to it
		dtcs = s.getDefinedComponents();
		assertEquals(9, dtcs.length);
		assertTrue(dtcs[8].getDataType().isEquivalent(new WordDataType()));
	}

	@Test
	public void testDeleteUnionComponent2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					// 2 components should get removed from CoolUnion
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
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
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

		// choose DLL_Table from LATEST which means delete it
		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		// MY CoolUnion
		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// DLL_Table should not exist
		assertNull(dtm.getDataType(CategoryPath.ROOT, "DLL_Table"));

		// CoolUnion should not have DLL_Table components but should have Float 
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(4, dtcs.length);
		DataType dt = dtcs[3].getDataType();
		assertTrue(dt.isEquivalent(new FloatDataType()));
		assertEquals("my comments", dtcs[3].getComment());
		assertEquals("Float Field", dtcs[3].getFieldName());
	}

	@Test
	public void testDeleteUnionComponent3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					// 2 components should get removed from CoolUnion
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
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
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

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose DLL_Table from ORIGINAL

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// DLL_Table should exist
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// CoolUnion should not have DLL_Table components but should have Float 
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertEquals(dll, dtcs[3].getDataType());
		DataType dt = dtcs[5].getDataType();
		assertTrue(dt.isEquivalent(new FloatDataType()));
		assertEquals("my comments", dtcs[5].getComment());
		assertEquals("Float Field", dtcs[5].getFieldName());
	}

	@Test
	public void testStructureUpdateFailure() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					union.add(foo);
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
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.add(dt);
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		close(waitForWindow("Structure Update Failed")); // expected dependency error on Foo

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		checkConflictCount(0);

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		DataTypeComponent[] coolUnionComps = coolUnion.getComponents();
		assertEquals(6, coolUnionComps.length);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		DataTypeComponent[] fooComps = foo.getComponents();
		assertEquals(6, fooComps.length);

		// Foo should not contain CoolUnion because CoolUnion already 
		// contains Foo (from Latest)
		assertEquals("Foo", coolUnionComps[5].getDataType().getDisplayName());

		// Foo.conflict should contain CoolUnion.conflict because CoolUnion already 
		// contains Foo (from Latest), so Foo (From My) becomes Foo.conflict and its
		// original CoolUnion becomes CoolUnion.conflict.
		assertEquals("float", fooComps[5].getDataType().getDisplayName());
		assertTrue(fooComps[4].getDataType() instanceof BadDataType);
		assertTrue(fooComps[4].getComment().startsWith("Couldn't add CoolUnion here."));
	}

	@Test
	public void testStructureUpdateFailure2() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					union.add(foo);
					// Edit Foo to cause a conflict
					foo.add(new ByteDataType());

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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.add(union);
					foo.add(new FloatDataType());
					// Edit CoolUnion to cause a conflict
					union.add(new FloatDataType(), "My Float", "My comments");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY Foo

		close(waitForWindow("Structure Update Failed")); // expected dependency error on Foo

		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		DataTypeComponent[] coolUnionComps = coolUnion.getComponents();
		assertEquals(6, coolUnionComps.length);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		DataTypeComponent[] fooComps = foo.getComponents();
		assertEquals(6, fooComps.length);

		// Foo should not contain CoolUnion because CoolUnion already 
		// contains Foo (from Latest)
		assertEquals("Foo", coolUnionComps[5].getDataType().getDisplayName());

		// Foo.conflict should contain CoolUnion.conflict because CoolUnion already 
		// contains Foo (from Latest), so Foo (From My) becomes Foo.conflict and its
		// original CoolUnion becomes CoolUnion.conflict.
		assertEquals("float", fooComps[5].getDataType().getDisplayName());
		assertTrue(fooComps[4].getDataType() instanceof BadDataType);
		assertTrue(fooComps[4].getComment().startsWith("Couldn't add CoolUnion here."));
	}

	@Test
	public void testStructureUpdateFailure3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					union.add(foo);
					// Edit Foo to cause a conflict
					foo.add(new ByteDataType());

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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.add(union);
					foo.add(new FloatDataType());
					// Edit CoolUnion to cause a conflict
					union.add(new FloatDataType(), "My Float", "My comments");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST Foo

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertTrue(dtcs[5].getDataType().isEquivalent(new FloatDataType()));

		// Foo from Latest
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		dtcs = foo.getDefinedComponents();
		assertEquals(5, dtcs.length);
		assertTrue(dtcs[4].getDataType().isEquivalent(new ByteDataType()));
		checkConflictCount(0);
	}

	@Test
	public void testStructureUpdateFailure4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					union.add(bar, "My field name", "My comments");

					bar.add(new ByteDataType());

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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					bar.add(union);
					union.add(new ByteDataType(), "my field name", "some comments");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// Latest CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_MY);// My Bar

		close(waitForWindow("Structure Update Failed")); // expected dependency error on Bar

		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(coolUnion);
		assertNotNull(bar);

		DataTypeComponent[] coolUnionComps = coolUnion.getComponents();
		assertEquals(6, coolUnionComps.length);
		DataTypeComponent[] barComps = bar.getDefinedComponents();
		assertEquals(3, barComps.length);

		assertEquals(bar, coolUnionComps[5].getDataType());
		assertEquals("My field name", coolUnionComps[5].getFieldName());
		assertEquals("My comments", coolUnionComps[5].getComment());

		assertTrue(barComps[2].getDataType() instanceof BadDataType);
		assertTrue(barComps[2].getComment().startsWith("Couldn't add CoolUnion here."));
	}

	@Test
	public void testConflictUpdate() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				try {
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					bar.add(new ByteDataType());
					s1.delete(3);
					// edit Foo
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose My Bar // TODO: I see no reason for a conflict !

		setErrorsExpected(true);

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL); // choose Structure_1 from ORIGINAL

		setErrorsExpected(false);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Bar should contain original Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		DataTypeComponent[] dtcs = bar.getDefinedComponents();
		assertEquals(3, dtcs.length);
		assertTrue(dtcs[2].getDataType().isEquivalent(new ByteDataType()));
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		dtcs = s1.getComponents();
		assertEquals(4, dtcs.length);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Structure_1 should contain MY Foo
		assertEquals(foo, dtcs[2].getDataType());

		dtcs = foo.getComponents();
		assertEquals(5, dtcs.length);
		assertTrue(dtcs[4].getDataType().isEquivalent(new FloatDataType()));
		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate2() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				try {
					dtm.remove(dt, TaskMonitor.DUMMY);
					// causes Bar to be marked as changed
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					bar.add(new ByteDataType());
					s1.delete(3);
					// edit Foo
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL); // choose original Bar

		chooseOption(DataTypeMergeManager.OPTION_MY); // choose Structure_1 from MY

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Bar should contain original Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertEquals(6, bar.getLength());
		DataTypeComponent[] dtcs = bar.getComponents();
		assertEquals(2, dtcs.length);
		DataType dt = dtcs[1].getDataType();
		assertTrue(dt instanceof Pointer);

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		assertEquals(s1, ((Pointer) dt).getDataType());

		dtcs = s1.getComponents();
		assertEquals(3, dtcs.length);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Structure_1 should contain MY Foo
		assertEquals(foo, dtcs[2].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();

				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				try {
					dtm.remove(dt, TaskMonitor.DUMMY);
					// causes Bar to be marked as changed
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					bar.add(new ByteDataType());
					s1.delete(3);
					// edit Foo
					foo.add(new FloatDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose my Bar

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delele Structure_1 (choose Structure_1 from MY)

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Bar should contain undefined to replace Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertEquals(7, bar.getLength());
		DataTypeComponent[] dtcs = bar.getComponents();
		assertEquals(6, dtcs.length);
		for (int i = 1; i < 5; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}

		// Structure_1 should have been deleted
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNull(s1);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		dtcs = foo.getDefinedComponents();
		assertEquals(5, dtcs.length);
		assertEquals(bar, dtcs[3].getDataType());
		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();

				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
					"FloatStruct");
				Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				Structure ms = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"MyStruct");
				try {
					dtm.remove(dt, TaskMonitor.DUMMY);
					Structure s1 = new StructureDataType(
						new CategoryPath("/Category1/Category2/Category5"), "s1", 0);
					s1.add(ms);
					s1 = (Structure) dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);
					s1.add(new ByteDataType());
					Pointer p = PointerDataType.getPointer(a, 4);
					s1.add(p);

					// edit ArrayStruct
					a.add(s1);
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
				Structure fs =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
						"FloatStruct");
				Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				Structure ms = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"MyStruct");
				try {
					s.add(new FloatDataType());

					Structure mys1 = new StructureDataType(
						new CategoryPath("/Category1/Category2/Category5"), "my_s1", 0);
					mys1.add(s);

					mys1 =
						(Structure) dtm.addDataType(mys1, DataTypeConflictHandler.DEFAULT_HANDLER);
					// edit FloatStruct
					fs.add(mys1);

					// edit MyStruct
					ms.add(new FloatDataType());
					ms.add(new WordDataType());

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();

		// conflict on ArrayStruct (6)
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// use ORIGINAL ArrayStruct

		// conflict on MyStruct    (5)
		chooseOption(DataTypeMergeManager.OPTION_MY);// use MY MyStruct

		// conflict on FloatStruct (2)
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete FloatStruct

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"), "FloatStruct"));

		waitForCompletion();
		Structure fs =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
				"FloatStruct");
		assertNull(fs);

		// MyStruct should have a FloatDataType and a Word
		Structure ms =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "MyStruct");
		DataTypeComponent[] dtcs = ms.getDefinedComponents();
		assertEquals(4, dtcs.length);

		assertTrue(dtcs[2].getDataType().isEquivalent(new FloatDataType()));
		assertTrue(dtcs[3].getDataType().isEquivalent(new WordDataType()));

		// ArrayStruct should have 3 components
		Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
		dtcs = a.getDefinedComponents();
		assertEquals(3, dtcs.length);
	}

	@Test
	public void testConflictUpdate5() throws Exception {

		TypeDef td = new TypedefDataType(new CategoryPath("/Category1/Category2"), "BF",
			IntegerDataType.dataType);

		mtf.initialize("notepad2", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					dtm.addDataType(td, null);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2"), "BF");
				try {
					dtm.remove(dt, TaskMonitor.DUMMY);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					s1.insertBitFieldAt(3, 2, 6, td, 2, "bf1", "my bf1");
					s1.insertBitFieldAt(3, 2, 4, td, 2, "bf2", "my bf2");
					foo.add(new FloatDataType());
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.toString());
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		// bitfield silently transitions to int since typedef BF was removed

		executeMerge(true);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		DataTypeComponent[] dtcs = s1.getComponents();
		assertEquals(7, dtcs.length);

		assertEquals(4, dtcs[3].getOffset()); // base on original 2-byte length 1st byte remains undefined
		assertEquals("bf1", dtcs[3].getFieldName());
		assertEquals("my bf1", dtcs[3].getComment());

		DataType dt = dtcs[3].getDataType();
		assertTrue(dt instanceof BitFieldDataType);
		BitFieldDataType bfDt = (BitFieldDataType) dt;
		assertTrue(bfDt.getBaseDataType() instanceof IntegerDataType);
		assertEquals(2, bfDt.getDeclaredBitSize());
		assertEquals(6, bfDt.getBitOffset());

		assertEquals(4, dtcs[4].getOffset()); // base on original 2-byte length 1st byte remains undefined
		assertEquals("bf2", dtcs[4].getFieldName());
		assertEquals("my bf2", dtcs[4].getComment());

		dt = dtcs[4].getDataType();
		assertTrue(dt instanceof BitFieldDataType);
		bfDt = (BitFieldDataType) dt;
		assertTrue(bfDt.getBaseDataType() instanceof IntegerDataType);
		assertEquals(2, bfDt.getDeclaredBitSize());
		assertEquals(4, bfDt.getBitOffset());

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Structure_1 should contain MY Foo
		assertEquals(foo, dtcs[5].getDataType());

		dtcs = foo.getComponents();
		assertEquals(5, dtcs.length);
		assertTrue(dtcs[4].getDataType().isEquivalent(new FloatDataType()));
		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate6() throws Exception {

		TypeDef td = new TypedefDataType(new CategoryPath("/Category1/Category2"), "BF",
			IntegerDataType.dataType);

		mtf.initialize("notepad2", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					// add new BF not compatible with BitFields
					dtm.addDataType(
						new StructureDataType(new CategoryPath("/Category1/Category2"), "BF", 0),
						null);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					s1.insertBitFieldAt(3, 2, 6, td, 2, "bf1", "my bf1");
					s1.insertBitFieldAt(3, 2, 4, td, 2, "bf2", "my bf2");
					foo.add(new FloatDataType());
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.toString());
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		// bitfield silently transitions to BF.conflict since two different BF types were added

		executeMerge(true);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		DataTypeComponent[] dtcs = s1.getComponents();
		assertEquals(7, dtcs.length);

		assertEquals(4, dtcs[3].getOffset()); // base on original 2-byte length 1st byte remains undefined
		assertEquals("bf1", dtcs[3].getFieldName());
		assertEquals("my bf1", dtcs[3].getComment());

		DataType dt = dtcs[3].getDataType();
		assertTrue(dt instanceof BitFieldDataType);
		BitFieldDataType bfDt = (BitFieldDataType) dt;
		DataType bdt = bfDt.getBaseDataType();
		assertEquals("/Category1/Category2/BF.conflict", bdt.getPathName());
		assertTrue(bdt.isEquivalent(td));
		assertEquals(2, bfDt.getDeclaredBitSize());
		assertEquals(6, bfDt.getBitOffset());

		assertEquals(4, dtcs[4].getOffset()); // base on original 2-byte length 1st byte remains undefined
		assertEquals("bf2", dtcs[4].getFieldName());
		assertEquals("my bf2", dtcs[4].getComment());

		dt = dtcs[4].getDataType();
		assertTrue(dt instanceof BitFieldDataType);
		bfDt = (BitFieldDataType) dt;
		bdt = bfDt.getBaseDataType();
		assertEquals("/Category1/Category2/BF.conflict", bdt.getPathName());
		assertTrue(bdt.isEquivalent(td));
		assertEquals(2, bfDt.getDeclaredBitSize());
		assertEquals(4, bfDt.getBitOffset());

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Structure_1 should contain MY Foo
		assertEquals(foo, dtcs[5].getDataType());

		dtcs = foo.getComponents();
		assertEquals(5, dtcs.length);
		assertTrue(dtcs[4].getDataType().isEquivalent(new FloatDataType()));
		checkConflictCount(1);
	}

	@Test
	public void testConflictUpdate7() throws Exception {

		TypeDef td = new TypedefDataType(new CategoryPath("/Category1/Category2"), "TD",
			IntegerDataType.dataType);

		mtf.initialize("notepad2", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					Structure s1 =
						(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
							"Structure_1");
					s1.setFlexibleArrayComponent(td, null, null);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					Structure s1 =
						(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
							"Structure_1");
					s1.setFlexibleArrayComponent(IntegerDataType.dataType, "flex1", "cmt1");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY Structure_1

		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		DataTypeComponent[] dtcs = s1.getComponents();
		assertEquals(4, dtcs.length);

		DataTypeComponent flexDtc = s1.getFlexibleArrayComponent();
		assertNotNull(flexDtc);
		assertTrue(IntegerDataType.class == flexDtc.getDataType().getClass());
		assertEquals("flex1", flexDtc.getFieldName());
		assertEquals("cmt1", flexDtc.getComment());
	}

	@Test
	public void testConflictUpdate8() throws Exception {

		TypeDef td = new TypedefDataType(new CategoryPath("/Category1/Category2"), "TD",
			IntegerDataType.dataType);

		mtf.initialize("notepad2", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					Structure s1 =
						(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
							"Structure_1");
					s1.setFlexibleArrayComponent(IntegerDataType.dataType, null, null);
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					Structure s1 =
						(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
							"Structure_1");
					s1.setFlexibleArrayComponent(td, "flex1", "cmt1");
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					Structure s1 =
						(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
							"Structure_1");
					s1.insertBitFieldAt(3, 2, 6, td, 2, "bf1", "my bf1");
					s1.insertBitFieldAt(3, 2, 4, td, 2, "bf2", "my bf2");
					s1.clearFlexibleArrayComponent();
				}
				catch (InvalidDataTypeException e) {
					e.printStackTrace();
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, true);
				}
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY Structure_1

		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);

		DataTypeComponent flexDtc = s1.getFlexibleArrayComponent();
		assertNull(flexDtc);

		DataTypeComponent[] dtcs = s1.getComponents();
		assertEquals(7, dtcs.length);

		assertEquals(4, dtcs[3].getOffset()); // base on original 2-byte length 1st byte remains undefined
		assertEquals("bf1", dtcs[3].getFieldName());
		assertEquals("my bf1", dtcs[3].getComment());

		DataType dt = dtcs[3].getDataType();
		assertTrue(dt instanceof BitFieldDataType);
		BitFieldDataType bfDt = (BitFieldDataType) dt;
		assertTrue(td.isEquivalent(bfDt.getBaseDataType()));
		assertEquals(2, bfDt.getDeclaredBitSize());
		assertEquals(6, bfDt.getBitOffset());

		assertEquals(4, dtcs[4].getOffset()); // base on original 2-byte length 1st byte remains undefined
		assertEquals("bf2", dtcs[4].getFieldName());
		assertEquals("my bf2", dtcs[4].getComment());

		dt = dtcs[4].getDataType();
		assertTrue(dt instanceof BitFieldDataType);
		bfDt = (BitFieldDataType) dt;
		assertTrue(td.isEquivalent(bfDt.getBaseDataType()));
		assertEquals(2, bfDt.getDeclaredBitSize());
		assertEquals(4, bfDt.getBitOffset());

	}

//	TODO   See GP-585 for design issue preventing this test from passing
//	@Test
	public void testEditStructureWithReplacementAndRemoval() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					Structure s = (Structure) dtm.getDataType("/Category5/Test");
					DataType dt = dtm.getDataType("/MISC/FooTypedef");
					s.setFlexibleArrayComponent(dt, "foo", "");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					TypeDef td = (TypeDef) dtm.getDataType("/BF");
					//
					// NOTE: Merge does not handle datatype replacements as one might hope
					// If latest version has defined data/components based upon a type which has
					// been replaced in private, the replaced datatype will be treated as removed
					//
					dtm.replaceDataType(td, new TypedefDataType("NewBF", IntegerDataType.dataType),
						true);
					DataType dt = dtm.getDataType("/MISC/FooTypedef");
					dtm.remove(dt, TaskMonitor.DUMMY);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

				DataType dt1 = dtm.getDataType("/BF");
				assertNull(dt1);
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					TypeDef td = new TypedefDataType("BF", IntegerDataType.dataType);

					Structure struct = new StructureDataType(new CategoryPath("/Category5"), "Test",
						0, program.getDataTypeManager());
					struct.add(td);
					struct.insertBitFieldAt(3, 2, 6, td, 2, "bf1", null);
					struct.insertBitFieldAt(3, 2, 4, td, 2, "bf2", null);
					struct.add(new WordDataType());
					struct.add(new QWordDataType());

					struct.setFlexibleArrayComponent(td, "flex", "my flex");

					dtm.addDataType(struct, null);
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

		executeMerge(DataTypeMergeManager.OPTION_MY);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		DataType dt = dtm.getDataType("/Category5/Test");
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		/** Current Result for /Category5/Test
		 * 
				Unaligned
				Structure Test {
				   4   int:2(6)   1   bf1   ""
				   4   int:2(4)   1   bf2   ""
				   5   word   2   null   ""
				   7   qword   8   null   ""
				}
				Size = 15   Actual Alignment = 1
		 *	
		 * See assertion below for preferred result
		 */
		//@formatter:off
		assertEquals("/Category5/Test\n" + 
			"Unaligned\n" + 
			"Structure Test {\n" + 
			"   0   NewBF   4   null   \"\"\n" + 
			"   4   NewBF:2(6)   1   bf1   \"\"\n" + 
			"   4   NewBF:2(4)   1   bf2   \"\"\n" + 
			"   5   word   2   null   \"\"\n" + 
			"   7   qword   8   null   \"\"\n" + 
			"   Undefined1[0]   0   foo   \"\"\n" +  // reflects removal of /MISC/FooTypedef
			"}\n" + 
			"Size = 15   Actual Alignment = 1\n", s.toString());
		//@formatter:on
	}

	@Test
	public void testEditUnions() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					// 2 components should get removed from CoolUnion
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
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_DLL_Table", s);
					Pointer p = PointerDataType.getPointer(td, 4);
					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(p);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
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

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose DLL_Table from ORIGINAL

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// DLL_Table should exist

		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// AnotherUnion should contain DLL_Table from the Original
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
		assertNotNull(union);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_DLL_Table");
		assertNotNull(td);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(3, dtcs.length);
		assertEquals(dll, dtcs[0].getDataType());
		DataType dt = dtcs[1].getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(td, ((Pointer) dt).getDataType());
		assertTrue(dtcs[2].getDataType().isEquivalent(new ByteDataType()));

		union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertEquals("my comments", dtcs[5].getComment());
		assertEquals("Float Field", dtcs[5].getFieldName());

	}

	@Test
	public void testEditUnions2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					// 2 components should get removed from CoolUnion
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
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
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

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete DLL_Table

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// DLL_Table should not exist

		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNull(dll);

		// AnotherUnion should contain one component since DLL_Table was deleted
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
		assertNotNull(union);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(1, dtcs.length);
		assertTrue(dtcs[0].getDataType().isEquivalent(new ByteDataType()));

		union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		dtcs = union.getComponents();
		assertEquals(4, dtcs.length);
		assertEquals("my comments", dtcs[3].getComment());
		assertEquals("Float Field", dtcs[3].getFieldName());
	}

	@Test
	public void testEditUnions3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					union.add(enumm);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		assertEquals(enumm, dtcs[6].getDataType());
		assertEquals(dll, dtcs[3].getDataType());
	}

	@Test
	public void testEditUnions4() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					union.add(enumm);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(5, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		assertEquals(enumm, dtcs[4].getDataType());
		assertTrue(dtcs[3].getDataType().isEquivalent(new FloatDataType()));

	}

	@Test
	public void testEditUnions5() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					union.add(enumm);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		chooseOption(DataTypeMergeManager.OPTION_MY);// my DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// enumm should have been added
		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);

		DataTypeComponent[] dtcs = dll.getComponents();
		assertEquals(9, dtcs.length);
		assertTrue(dtcs[8].getDataType().isEquivalent(new WordDataType()));
	}

	@Test
	public void testEditUnions6() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm);
					union.add(td);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);
		assertEquals(td, dtcs[6].getDataType());
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testEditUnions7() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm);
					Pointer p = PointerDataType.getPointer(td, 4);// TD_MyEnum *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * * *
					union.add(p);

					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		for (int i = 0; i < 3; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(td, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testEditUnions8() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitor.DUMMY);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitor.DUMMY);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm);
					Pointer p = PointerDataType.getPointer(td, 4);// TD_MyEnum *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * *
					p = PointerDataType.getPointer(p, 4);// TD_MyEnum * * *

					// create an array of TD_MyEnum * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					dtc = union.add(array);
					dtc.setComment("an array");
					dtc.setFieldName("array field name");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());

					union =
						new UnionDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
					union.add(s);
					union.add(new ByteDataType());
					dtm.addDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();
		assertTrue(dt instanceof Pointer);

		for (int i = 0; i < 3; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(td, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
	public void testEditUnions9() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "XYZ", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					dtm.addDataType(
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm),
						null);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					DataType enumm = dtm.getDataType(new CategoryPath("/Category1"), "XYZ");
					dtm.remove(enumm, TaskMonitor.DUMMY);

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					// NOTE: bit field component byte sizing is currently auto-sized and packed within unions
					union.insertBitField(1, IntegerDataType.dataType, 4, "bf1", "latest bf1");
					union.insertBitField(2, IntegerDataType.dataType, 2, "bf2", "latest bf2");
					commit = true;
				}
				catch (InvalidDataTypeException e) {
					e.printStackTrace();
					Assert.fail();
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

				try {
					DataType enumm = dtm.getDataType(new CategoryPath("/Category1"), "XYZ");
					assertTrue(enumm instanceof Enum);

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					// NOTE: bit field component byte sizing is currently auto-sized and packed within unions
					union.insertBitField(1, enumm, 4, "BF1", "my bf1");
					union.insertBitField(2, enumm, 2, "BF2", "my bf2");

					commit = true;
				}
				catch (InvalidDataTypeException e) {
					e.printStackTrace();
					Assert.fail();
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY bitfields w/ enum

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// primitive type of byte used in absence of enum
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8   null   \"\"\n" + 
			"   0   byte:4(4)   1   BF1   \"my bf1\"\n" + 
			"   0   byte:2(6)   1   BF2   \"my bf2\"\n" + 
			"   0   word   2   null   \"\"\n" + 
			"   0   undefined * * * * *   4   null   \"\"\n" + 
			"   0   DLL_Table   96   null   \"\"\n" + 
			"   0   DLL_Table *32   4   null   \"\"\n" + 
			"}\n" + 
			"Size = 96   Actual Alignment = 1\n", union.toString());
		//@formatter:on
	}

}
