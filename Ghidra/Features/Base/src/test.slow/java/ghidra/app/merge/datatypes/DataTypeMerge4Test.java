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

import java.util.ArrayList;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * More data type merge tests.
 * 
 * 
 */
public class DataTypeMerge4Test extends AbstractDataTypeMergeTest {

	@Test
	public void testMultiEdits() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					union.add(new ByteDataType());
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");

		// choose MY
		chooseOption(DataTypeMergeManager.OPTION_MY);

		// then choose LATEST
		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		// DLL_Table should have a Word data type as the last component
		Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		DataTypeComponent dtc = s.getComponent(s.getNumComponents() - 1);
		assertTrue(dtc.getDataType().isEquivalent(new WordDataType()));

		// CoolUnion should have a Byte data type as the last component
		dtc = union.getComponent(5);
		assertTrue(dtc.getDataType().isEquivalent(new ByteDataType()));

		dtc = union.getComponent(3);
		assertEquals(s, dtc.getDataType());
	}

	@Test
	public void testMultiEdits2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					union.add(new ByteDataType());
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new ByteDataType());
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got Data Type Dependency Exception! " + e.getMessage());
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// then choose LATEST
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// Latest DLL_Table

		// choose MY
		chooseOption(DataTypeMergeManager.OPTION_MY);// my Union

		waitForCompletion();

		// DLL_Table should have a Byte data type as the last component
		Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		DataTypeComponent dtc = s.getComponent(s.getNumComponents() - 1);
		assertTrue(dtc.getDataType().isEquivalent(new ByteDataType()));

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertNotNull(union);
		assertEquals(6, union.getNumComponents());

		// CoolUnion should have a Float data type as the last component
		dtc = union.getComponent(5);
		assertTrue(dtc.getDataType().isEquivalent(new FloatDataType()));

		dtc = union.getComponent(3);
		assertEquals(s, dtc.getDataType());

		dtc = union.getComponent(4);
		assertTrue(PointerDataType.getPointer(s, 4).isEquivalent(dtc.getDataType()));

	}

	@Test
	public void testMultiEdits3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				Structure s1 = (Structure) dt;
				try {
					s1.add(new QWordDataType());
					// move Structure_1 to /MISC
					s1.setCategoryPath(new CategoryPath("/MISC"));

					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.delete(2);
					foo.delete(2);

					dt = dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
					dt.setName("OtherFoo_Typedef");

					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					bar.add(dt);
					commit = true;
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				Structure s1 = (Structure) dt;
				try {
					s1.setName("My_Structure_One");
					s1.add(new FloatDataType());

					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					foo.delete(3);

					dt = dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
					dt.setName("My_Foo_Typedef");

					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					bar.add(new ByteDataType());
					bar.add(PointerDataType.getPointer(foo, 4));
					commit = true;
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

		chooseOption(DataTypeMergeManager.OPTION_MY);// my Bar

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original Structure_1

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// latest Foo

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// latest FooTypedef

		waitForCompletion();

		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Structure_1"));

		// Structure_1 should be intact from original
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		// Should be 8 undefineds from Foo choice.
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(3).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(4).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(5).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(6).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(7).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(8).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(9).getDataType()));
		assertTrue(DataType.DEFAULT.isEquivalent(s1.getComponent(10).getDataType()));
		assertTrue(new ByteDataType().isEquivalent(s1.getComponent(11).getDataType()));
		assertEquals(12, s1.getNumComponents());

		// Structure_1 should have Foo from Latest
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertEquals(foo, s1.getComponent(2).getDataType());

		// Bar should have 3 components (from MY)
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertEquals(4, bar.getNumComponents());
		DataTypeComponent dtc = bar.getComponent(1);
		DataType dt = dtc.getDataType();

		// Bar should contain Structure_1* 

		assertTrue(dt.isEquivalent(PointerDataType.getPointer(s1, 4)));
		dt = dtm.getDataType(new CategoryPath("/MISC"), "OtherFoo_Typedef");
		assertNotNull(dt);
		// component index 2 should be a byte
		dtc = bar.getComponent(2);
		assertTrue(new ByteDataType().isEquivalent(dtc.getDataType()));

		// last component should be pointer to Foo (from latest);
		dtc = bar.getComponent(3);
		Pointer p = (Pointer) dtc.getDataType();
		assertEquals(foo, p.getDataType());

		// Foo should have 2 components (from latest)
		assertEquals(2, foo.getNumComponents());
		dtc = foo.getComponent(1);
		assertTrue(dtc.getDataType().isEquivalent(new ByteDataType()));
	}

	@Test
	public void testMultiEdits4() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				try {
					s.add(new FloatDataType());
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
					dt.setName("MyIntStruct");
					dt.setCategoryPath(new CategoryPath("/MyCategory/Ints"));
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
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
		executeMerge();
		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
		Structure intstruct =
			(Structure) dtm.getDataType(new CategoryPath("/MyCategory/Ints"), "MyIntStruct");
		assertNotNull(intstruct);
		// ArrayStruct should contain MyIntStruct now
		DataTypeComponent[] dtcs = s.getDefinedComponents();
		assertEquals(4, dtcs.length);
		DataType dt = dtcs[0].getDataType();
		assertEquals("MyIntStruct * *[10]", dt.getDisplayName());
		dt = dtcs[1].getDataType();
		assertTrue(dt instanceof Array);
		DataType baseDt = ((Array) dt).getDataType();
		assertEquals(intstruct, baseDt);

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testMultiEdits5() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				try {
					s.add(new FloatDataType());
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
					dt.setName("MyIntStruct");
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
					Structure ns = new StructureDataType(
						new CategoryPath("/Category1/Category2/Category3"), "my_struct", 0);
					ns.add(new ByteDataType());
					ns = (Structure) dtm.addDataType(ns, DataTypeConflictHandler.DEFAULT_HANDLER);
					ns.add(PointerDataType.getPointer(s, 4));

					s.add(PointerDataType.getPointer(ns, 4));

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
		executeMerge();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
		Structure intstruct =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"MyIntStruct");
		DataTypeComponent[] idtcs = intstruct.getDefinedComponents();
		assertEquals(7, idtcs.length);
		DataType dt = idtcs[6].getDataType();
		assertTrue(dt instanceof Pointer);

		Structure mystruct =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"my_struct");
		assertNotNull(mystruct);

		assertEquals(mystruct, ((Pointer) dt).getDataType());

		DataTypeComponent dtc = mystruct.getComponent(1);
		dt = dtc.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(intstruct, ((Pointer) dt).getDataType());

		// ArrayStruct should contain MyIntStruct now
		DataTypeComponent[] dtcs = s.getDefinedComponents();
		assertEquals(4, dtcs.length);
		dt = dtcs[0].getDataType();
		assertEquals("MyIntStruct * *[10]", dt.getDisplayName());
		dt = dtcs[1].getDataType();
		assertTrue(dt instanceof Array);
		DataType baseDt = ((Array) dt).getDataType();
		assertEquals(intstruct, baseDt);

		// should be no .conflict data types
		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("*.conflict", list, false, null);
		assertEquals(0, list.size());
	}

	@Test
	public void testMultiEdits6() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					dtm.remove(foo, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					foo.deleteAll();
					foo.add(new QWordDataType());
					foo.add(bar);
					foo.add(PointerDataType.getPointer(foo, 4));

					Structure ms = new StructureDataType(
						new CategoryPath("/Category1/Category2/Category3"), "my_struct", 0);
					ms.add(foo);
					ms.add(new ByteDataType());
					ms = (Structure) dtm.addDataType(ms, DataTypeConflictHandler.DEFAULT_HANDLER);

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Thread.sleep(250);
		chooseOption(DataTypeMergeManager.OPTION_MY);// Choose my Foo

		waitForCompletion();

		// Foo should exist
		Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(fs);
		DataTypeComponent[] dtcs = fs.getDefinedComponents();
		assertEquals(3, dtcs.length);
		DataTypeComponent dtc = fs.getComponent(2);
		DataType dt = dtc.getDataType();
		assertTrue(dt instanceof Pointer);

		// Foo should have a pointer to Foo
		assertEquals(fs, ((Pointer) dt).getDataType());

		// my_struct should have a Foo and Byte
		Structure ms =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"my_struct");
		assertNotNull(ms);

		assertEquals(2, ms.getDefinedComponents().length);
		dtc = ms.getComponent(0);
		assertEquals(fs, dtc.getDataType());
		dtc = ms.getComponent(1);
		assertTrue(new ByteDataType().isEquivalent(dtc.getDataType()));

		// Structure1 should exist as modified by Latest. (My didn't change it.)
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		DataTypeComponent[] dtcs1 = s1.getDefinedComponents();
		assertEquals(3, dtcs1.length);
		DataType dt0 = dtcs1[0].getDataType();
		DataType dt1 = dtcs1[1].getDataType();
		DataType dt2 = dtcs1[2].getDataType();
		assertTrue(dt0 instanceof ByteDataType);
		assertTrue(dt1 instanceof WordDataType);
		assertTrue(dt2 instanceof ByteDataType);

		// should be no .conflict data types
		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("*.conflict", list, false, null);
		assertEquals(0, list.size());
	}

	@Test
	public void testMultiEdits7() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					// delete Bar from Foo
					fs.delete(3);
					// add Foo to Bar
					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					bar.add(fs);
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
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
				try {
					fs.add(new QWordDataType());
					fs.add(bs);
					fs.add(PointerDataType.getPointer(fs, 4));

					// change Bar
					bs.add(new ByteDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// Bar gets a Foo

		chooseOption(DataTypeMergeManager.OPTION_MY);// Foo keeps its Bar, which creates Foo.conflict.

		close(waitForWindow("Structure Update Failed")); // expected dependency error on Bar (2 occurances of Bar use)

		waitForCompletion();

		// should be two .conflict data types
		checkConflictCount(0);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

		assertNotNull(foo);
		assertNotNull(bar);

		DataTypeComponent[] barComps = bar.getDefinedComponents();
		assertEquals(3, barComps.length);

		assertEquals(foo, barComps[2].getDataType());

		DataTypeComponent[] fooComps = foo.getComponents();
		assertEquals(7, fooComps.length);
		assertEquals("byte", fooComps[0].getDataType().getDisplayName());
		assertEquals("byte", fooComps[1].getDataType().getDisplayName());
		assertEquals("word", fooComps[2].getDataType().getDisplayName());
		assertTrue(fooComps[3].getDataType() instanceof BadDataType);
		String comment3 = fooComps[3].getComment();
		assertTrue(comment3.startsWith("Couldn't add Bar here."));
		assertEquals("qword", fooComps[4].getDataType().getDisplayName());
		assertTrue(fooComps[5].getDataType() instanceof BadDataType);
		String comment5 = fooComps[5].getComment();
		assertTrue(comment5.startsWith("Couldn't add Bar here."));
		assertEquals("Foo *", fooComps[6].getDataType().getDisplayName());

		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		// Update should fail for Foo
		for (DataTypeComponent dtc : dtcs) {
			if (dtc.getDataType() == bar) {
				Assert.fail("Bar should not have been added to Foo!");
			}
		}

		// Structure_1 should have a Foo component
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		DataType dt = s1.getComponent(2).getDataType();
		assertEquals(foo, dt);

		// FooTypedef should have Foo as its base type
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
		assertNotNull(td);
		assertEquals(foo, td.getBaseDataType());
	}

	@Test
	public void testMultiEdits8() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure array =
					(Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				try {
					// delete Bar from Foo
					fs.delete(3);
					// add Foo to Bar
					dtm.remove(bs, TaskMonitor.DUMMY);

					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(array);
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(PointerDataType.getPointer(fs, 4));
					s2.add(new QWordDataType());
					s2.add(PointerDataType.getPointer(array, 4));
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef"));

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// edit Foo to include s1 and s2
					fs.add(s1);
					fs.add(s2);
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
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(new ByteDataType());
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(PointerDataType.getPointer(fs, 4));
					s2.add(new QWordDataType());
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(new QWordDataType());

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// edit Foo to include s1 and s2
					fs.add(s1);
					fs.add(s2);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		// new data types from MY should go in as .conflicts
		checkConflictCount(3);

		// Structure_1 should contain Foo from MY
		Structure struct_1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		DataTypeComponent[] dtcs = struct_1.getDefinedComponents();
		Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertEquals(fs, dtcs[2].getDataType());
	}

	@Test
	public void testMultiEdits9() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure array =
					(Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				try {
					// delete Bar from Foo
					foo.delete(3);
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);

					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(array);
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(PointerDataType.getPointer(foo, 4));
					s2.add(new QWordDataType());
					s2.add(PointerDataType.getPointer(array, 4));
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef"));

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// edit Foo to include s1 and s2
					foo.add(s1);
					foo.add(s2);
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
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(new ByteDataType());
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(PointerDataType.getPointer(fs, 4));
					s2.add(new QWordDataType());
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(new QWordDataType());

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// edit Foo to include s1 and s2
					fs.add(s1);
					fs.add(s2);

					// edit Bar to create conflict because Latest deleted it
					bs.add(PointerDataType.getPointer(s3, 4));

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose Bar from Original

		chooseOption(DataTypeMergeManager.OPTION_MY);// Choose Foo from MY

		waitForCompletion();

		// new data types from MY should go in as .conflicts
		checkConflictCount(4);// get .conflict for pointer to s3

		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		// Foo from ORIGINAL 
		assertEquals(2, bar.getNumComponents());

		// Structure_1 should contain Foo from MY
		Structure struct_1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		DataTypeComponent[] dtcs = struct_1.getDefinedComponents();
		Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");

		assertEquals(fs, dtcs[2].getDataType());
	}

	@Test
	public void testMultiEdits10() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure array =
					(Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				try {
					// delete Bar from Foo
					fs.delete(3);
					// remove Bar from the data type manager
					dtm.remove(bs, TaskMonitor.DUMMY);

					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(array);
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(PointerDataType.getPointer(fs, 4));
					s2.add(new QWordDataType());
					s2.add(PointerDataType.getPointer(array, 4));
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef"));

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// edit Foo to include s1 and s2
					fs.add(s1);
					fs.add(s2);
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
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(new ByteDataType());
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(PointerDataType.getPointer(fs, 4));
					s2.add(new QWordDataType());
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(new QWordDataType());

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// edit Foo to include s1 and s2
					fs.add(s1);
					fs.add(s2);

					// edit Bar to create conflict because Latest deleted it
					bs.add(PointerDataType.getPointer(s3, 4));

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Latest
		// which means to delete BAR

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo from MY

		waitForCompletion();

		// new data types from MY should go in as .conflicts
		checkConflictCount(4);// get .conflict for pointer to s3

		Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bs);
		Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");

		// Foo should have undefined bytes where Bar was
		DataTypeComponent[] dtcs = fs.getDefinedComponents();
		assertEquals(5, dtcs.length);
		Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "S1.conflict");
		assertEquals(s1, dtcs[3].getDataType());
		Structure s2 = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "S2.conflict");
		assertEquals(s2, dtcs[4].getDataType());

		// Structure_1 should contain Foo from MY
		Structure struct_1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		dtcs = struct_1.getDefinedComponents();

		assertEquals(fs, dtcs[2].getDataType());
	}

	@Test
	public void testMultiEdits11() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					// delete Foo from the data type manager
					dtm.remove(fs, TaskMonitor.DUMMY);
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
				dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// delete Foo from the data type manager
					dtm.remove(foo, TaskMonitor.DUMMY);

					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(new ByteDataType());
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					s1 = (Structure) dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(new QWordDataType());
					s2.add(new ByteDataType());
					s2.add(PointerDataType.getPointer(s1, 4));
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(new QWordDataType());

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// create a new Foo
					foo = new StructureDataType(new CategoryPath("/MISC"), "Foo", 0);
					// edit Foo to include s1 and s2
					foo.add(s1);
					foo.add(s2);
					foo = (Structure) dtm.addDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					Pointer p = PointerDataType.getPointer(foo, 4);
					p = PointerDataType.getPointer(p, 4);
					p = PointerDataType.getPointer(p, 4);
					// add Foo * * * to Foo
					foo.add(p);

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		waitForCompletion();

		// there should be no .conflict names
		checkConflictCount(0);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(3, dtcs.length);
		DataType dt = dtcs[2].getDataType();
		assertTrue(dt instanceof Pointer);// foo * * *

		Pointer p = (Pointer) dt;
		dt = p.getDataType();// foo * *
		assertTrue(dt instanceof Pointer);
		p = (Pointer) dt;

		dt = p.getDataType();// foo *
		assertTrue(dt instanceof Pointer);
		p = (Pointer) dt;

		dt = p.getDataType();// foo
		assertEquals(foo, dt);
	}

	@Test
	public void testMultiEdits12() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					// delete Foo from the data type manager
					dtm.remove(fs, TaskMonitor.DUMMY);
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
				dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// delete Foo from the data type manager
					dtm.remove(foo, TaskMonitor.DUMMY);

					// Add s1, s2, s3
					Structure s1 = new StructureDataType(new CategoryPath("/MISC"), "S1", 0);
					s1.add(new ByteDataType());
					s1.add(PointerDataType.getPointer(new ByteDataType(), 4));
					s1 = (Structure) dtm.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s2 = new StructureDataType(new CategoryPath("/MISC"), "S2", 0);
					s2.add(new QWordDataType());
					s2.add(new ByteDataType());
					s2.add(PointerDataType.getPointer(s1, 4));
					dtm.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

					Structure s3 = new StructureDataType(new CategoryPath("/MISC"), "S3", 0);
					s3.add(new ByteDataType());
					s3.add(new QWordDataType());

					dtm.addDataType(s3, DataTypeConflictHandler.DEFAULT_HANDLER);

					// create a new Foo
					foo = new StructureDataType(new CategoryPath("/MISC"), "Foo", 0);
					// edit Foo to include s1 and s2
					foo.add(s1);
					foo.add(s2);
					foo = (Structure) dtm.addDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);
					Pointer p = PointerDataType.getPointer(foo, 4);
					p = PointerDataType.getPointer(p, 4);
					p = PointerDataType.getPointer(p, 4);
					// add Foo * * * to Foo
					foo.add(p);

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		waitForCompletion();

		checkConflictCount(0);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(3, dtcs.length);
		DataType dt = dtcs[2].getDataType();
		assertTrue(dt instanceof Pointer);// foo * * *

		Pointer p = (Pointer) dt;
		dt = p.getDataType();// foo * *
		assertTrue(dt instanceof Pointer);
		p = (Pointer) dt;

		dt = p.getDataType();// foo *
		assertTrue(dt instanceof Pointer);
		p = (Pointer) dt;

		dt = p.getDataType();// foo
		assertEquals(foo, dt);
	}

	@Test
	public void testMultiEdits13() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					// delete Bar from Foo
					foo.delete(3);
					// add Foo to Bar
					Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
					bar.add(foo);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
				try {
					foo.add(new QWordDataType());
					foo.add(bar);
					foo.add(PointerDataType.getPointer(foo, 4));

					// change Bar
					bar.add(new ByteDataType());
					Pointer p = PointerDataType.getPointer(td, 4);// FooTypedef *
					p = PointerDataType.getPointer(p, 4);// FooTypedef * * 
					p = PointerDataType.getPointer(p, 4);// FooTypedef * * *
					p = PointerDataType.getPointer(p, 4);// FooTypedef * * * *
					p = PointerDataType.getPointer(p, 4);// FooTypedef * * * * *
					bar.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose MY Bar

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose Foo ORIGINAL

		waitForCompletion();

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(4, dtcs.length);
		assertEquals(bar, dtcs[3].getDataType());

		// Structure_1 should have a Foo component from ORIGINAL
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		DataType dt = s1.getComponent(2).getDataType();
		assertEquals(foo, dt);

		// FooTypedef should have Foo as its base type
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
		assertNotNull(td);
		assertEquals(foo, td.getBaseDataType());

		dt = bar.getComponent(3).getDataType();
		assertTrue(dt instanceof Pointer);// FooTypedef * * * * *
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof Pointer);// FooTypedef * * * *
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof Pointer);// FooTypedef * * * 
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof Pointer);// FooTypedef * * 
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof Pointer);// FooTypedef * 
		dt = ((Pointer) dt).getDataType();
		assertEquals(td, dt);

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBaseTypeDef() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// edit Bar to create conflict because Latest deleted it
					Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
					p = PointerDataType.getPointer(p, 4);// Foo * * 
					p = PointerDataType.getPointer(p, 4);// Foo * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
					bar.add(p);

					// create a multi-dimension array on Bar
					Array array = new ArrayDataType(bar, 11, bar.getLength());
					array = new ArrayDataType(array, 10, array.getLength());
					array = new ArrayDataType(array, 9, array.getLength());
					array = new ArrayDataType(array, 8, array.getLength());
					array = new ArrayDataType(array, 7, array.getLength());
					array = new ArrayDataType(array, 6, array.getLength());

					// create a TypeDef on the array
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyArray_Typedef", array);
					// create a Pointer to typedef on MyArray_Typedef
					p = PointerDataType.getPointer(td, 4);// MyArray_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * * * *
					// add pointer to Foo
					foo.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose MY Bar

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Foo LATEST

		waitForCompletion();

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);

		// Bar should have pointers to Foo from Latest

		DataType dt = bar.getComponent(2).getDataType();
		assertTrue(dt instanceof Pointer);//Foo * * * * * *
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * * * * 
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * * *  
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * * 
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * 
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * 
		dt = ((Pointer) dt).getDataType();

		assertEquals(foo, dt);

		// MyArray_Typedef should  exist
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyArray_Typedef");
		assertNotNull(td);

		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("MyArray_Typedef*", list, false, null);
		assertEquals(9, list.size());

		assertNotNull(dtm.getDataType(new CategoryPath("/MISC"), "Bar[6][7][8][9][10][11]"));

		// other Arrays on Bar should exist
		dtm.findDataTypes("Bar[*", list, false, null);
		assertTrue(list.size() > 0);

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBaseTypeDef2() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// edit Bar to create conflict because Latest deleted it
					Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
					p = PointerDataType.getPointer(p, 4);// Foo * * 
					p = PointerDataType.getPointer(p, 4);// Foo * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
					bar.add(p);

					// create a multi-dimension array on Bar
					Array array = new ArrayDataType(bar, 11, bar.getLength());
					array = new ArrayDataType(array, 10, array.getLength());
					array = new ArrayDataType(array, 9, array.getLength());
					array = new ArrayDataType(array, 8, array.getLength());
					array = new ArrayDataType(array, 7, array.getLength());
					array = new ArrayDataType(array, 6, array.getLength());
					array = new ArrayDataType(array, 5, array.getLength());

					// create a TypeDef on the array
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyArray_Typedef", array);
					// create a Pointer to typedef on MyArray_Typedef
					p = PointerDataType.getPointer(td, 4);// MyArray_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * * * *
					// add pointer to Foo
					foo.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose ORIGINAL Bar

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo MY

		waitForCompletion();

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);

		// Bar should NOT have Foo * * * * * *
		DataTypeComponent[] dtcs = bar.getDefinedComponents();
		assertEquals(2, dtcs.length);
		assertTrue(dtcs[1].getDataType() instanceof Pointer);

		//Foo should have MyArray_Typedef * * * * * * * * 
		dtcs = foo.getDefinedComponents();
		assertEquals(5, dtcs.length);
		DataType dt = dtcs[4].getDataType();
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyArray_Typedef");
		assertNotNull(td);
		assertTrue(dt instanceof Pointer);
		for (int i = 0; i < 7; i++) {
			dt = ((Pointer) dt).getDataType();
			assertTrue(dt instanceof Pointer);
		}
		dt = ((Pointer) dt).getDataType();
		assertEquals(td, dt);

		assertTrue(td.getBaseDataType() instanceof Array);
		Array array = (Array) td.getDataType();
		// base type for MyArray_Typedef should be Bar[5][6][7][8][9][10][11]
		assertEquals("Bar[5][6][7][8][9][10][11]", array.getDisplayName());
		for (int i = 0; i < 6; i++) {
			assertEquals(5 + i, array.getNumElements());
			array = (Array) array.getDataType();
		}
		assertEquals(bar, array.getDataType());
	}

	@Test
	public void testDeletedBaseTypeDef3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// create a multi-dimension array on Foo
					Array array = new ArrayDataType(foo, 11, foo.getLength());
					array = new ArrayDataType(array, 10, array.getLength());
					array = new ArrayDataType(array, 9, array.getLength());
					array = new ArrayDataType(array, 8, array.getLength());
					array = new ArrayDataType(array, 7, array.getLength());
					array = new ArrayDataType(array, 6, array.getLength());

					// create a TypeDef on the array
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyFooArray_Typedef", array);
					// create a Pointer to typedef on MyArray_Typedef
					Pointer p = PointerDataType.getPointer(td, 4);// MyArray_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyArray_Typedef * * * * * * * *
					// add pointer to Bar
					bar.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose MY Bar

		// NOTE: while Foo grows because of Bar it was not explicitly change in 
		// MY so no conflict should be detected for Foo

		waitForCompletion();

		dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);

		// MyArray_Typedef should exist
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyFooArray_Typedef");
		assertNotNull(td);

		assertNotNull(dtm.getDataType(new CategoryPath("/MISC"), "Foo[6][7][8][9][10][11]"));

		ArrayList<DataType> list = new ArrayList<DataType>();
		// other Arrays on Foo should exist
		dtm.findDataTypes("Foo[*", list, false, null);
		assertTrue(list.size() > 0);

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBasePointerDT() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// edit Bar to create conflict because Latest deleted it
					Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
					p = PointerDataType.getPointer(p, 4);// Foo * * 
					p = PointerDataType.getPointer(p, 4);// Foo * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
					bar.add(p);

					// create a TypeDef on Bar
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
					// create a Pointer to typedef on Bar
					p = PointerDataType.getPointer(td, 4);// MyBar_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * * *
					// add pointer to Foo
					foo.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose MY Bar

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Foo LATEST

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);

		// Bar should have pointers to Foo from Latest

		DataType dt = bar.getComponent(2).getDataType();
		assertTrue(dt instanceof Pointer);//Foo * * * * * *
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * * * * 
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * * *  
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * * 
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * * 
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Pointer);// Foo * 
		dt = ((Pointer) dt).getDataType();

		assertEquals(foo, dt);

		// TypeDef on Bar should exist
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef");
		assertNotNull(td);

		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("MyBar_Typedef*", list, false, null);
		assertEquals(9, list.size());

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBasePointerLatest() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// edit Bar to create conflict because Latest deleted it
					Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
					p = PointerDataType.getPointer(p, 4);// Foo * * 
					p = PointerDataType.getPointer(p, 4);// Foo * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
					bar.add(p);

					// create a TypeDef on Bar
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
					// create a Pointer to typedef on Bar
					p = PointerDataType.getPointer(td, 4);// MyBar_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * * *
					// add pointer to Foo
					foo.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose LATEST Bar so delete it

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo MY

		waitForCompletion();

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);

		// TypeDef on Bar should not exist
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef");
		assertNull(td);

		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(3, dtcs.length);
		dtcs = foo.getComponents();

		// pointer gets converted to default 
		for (int i = 4; i < dtcs.length; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}
		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("MyBar_Typedef*", list, false, null);
		assertEquals(0, list.size());

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBasePointerOrig() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// edit Bar to create conflict because Latest deleted it
					Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
					p = PointerDataType.getPointer(p, 4);// Foo * * 
					p = PointerDataType.getPointer(p, 4);// Foo * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
					bar.add(p);

					// create a TypeDef on Bar
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
					// create a Pointer to typedef on Bar
					p = PointerDataType.getPointer(td, 4);// MyBar_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * * *
					// add pointer to Foo
					foo.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// choose original Bar

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo MY

		waitForCompletion();

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);

		// TypeDef on Bar should exist
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef");
		assertNotNull(td);
		assertEquals(bar, td.getBaseDataType());

		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(5, dtcs.length);
		DataType dt = dtcs[4].getDataType();
		assertTrue(dt instanceof Pointer);
		for (int i = 0; i < 7; i++) {
			dt = ((Pointer) dt).getDataType();
			assertTrue(dt instanceof Pointer);
		}
		dt = ((Pointer) dt).getDataType();
		assertNotNull(td);
		assertEquals(td, dt);

		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("MyBar_Typedef*", list, false, null);
		assertEquals(9, list.size());

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBaseTypeDefLatest() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					// remove Bar from the data type manager
					dtm.remove(bar, TaskMonitor.DUMMY);
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
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {

					// edit Bar to create conflict because Latest deleted it
					Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
					p = PointerDataType.getPointer(p, 4);// Foo * * 
					p = PointerDataType.getPointer(p, 4);// Foo * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * *
					p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
					bar.add(p);// This causes Bar to increase by 4 bytes 
					// and Foo contains Bar at the end so it also increases by 4.

					// create a TypeDef on Bar
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
					// create a Pointer to typedef on Bar
					p = PointerDataType.getPointer(td, 4);// MyBar_Typedef *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * 
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * *
					p = PointerDataType.getPointer(p, 4);// MyBar_Typedef * * * * * * * *
					// add pointer to Foo
					foo.add(p);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose to Delete Bar

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo MY

		waitForCompletion();

		// Bar should have been removed 
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(3, dtcs.length);
		assertEquals("Structure Foo was the wrong size.", 18, foo.getLength());

		// MyBar_Typedef should not exist since the option to delete Bar was chosen
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef"));

		dtcs = foo.getComponents();

		// pointer gets converted to default 
		for (int i = 4; i < dtcs.length; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}

	}

	@Test
	public void testMovedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				try {
					s.add(new FloatDataType());
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
					dt.setName("MyIntStruct");
					dt.setCategoryPath(new CategoryPath("/MyCategory/Ints"));
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
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
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// my IntStruct

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure intstruct =
			(Structure) dtm.getDataType(new CategoryPath("/MyCategory/Ints"), "MyIntStruct");
		assertNotNull(intstruct);

		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct"));

		// should be no .conflict data types
		checkConflictCount(0);
	}

}
