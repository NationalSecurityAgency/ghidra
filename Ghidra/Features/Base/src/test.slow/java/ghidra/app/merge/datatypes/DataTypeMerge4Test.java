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

import javax.swing.JDialog;

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
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Union union = (Union) dt;
				union.add(new ByteDataType());
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				s.add(new ByteDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Union union = (Union) dt;
				union.add(new FloatDataType());
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				s.add(new WordDataType());
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
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					union.add(new ByteDataType());
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new ByteDataType());
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(union, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got Data Type Dependency Exception! " + e.getMessage());
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Union union = (Union) dt;
				union.add(new FloatDataType());
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				s.add(new WordDataType());
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
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				s.add(new FloatDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("MyIntStruct");
					dt.setCategoryPath(new CategoryPath("/MyCategory/Ints"));
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				s.add(new FloatDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}
		});
		executeMerge();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
		Structure intstruct = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "MyIntStruct");
		DataTypeComponent[] idtcs = intstruct.getDefinedComponents();
		assertEquals(7, idtcs.length);
		DataType dt = idtcs[6].getDataType();
		assertTrue(dt instanceof Pointer);

		Structure mystruct = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "my_struct");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.remove(foo, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				foo.deleteAll();
				foo.add(new QWordDataType());
				foo.add(bar);
				foo.add(PointerDataType.getPointer(foo, 4));

				Structure ms = new StructureDataType(
					new CategoryPath("/Category1/Category2/Category3"), "my_struct", 0);
				ms.add(foo);
				ms.add(new ByteDataType());
				ms = (Structure) dtm.addDataType(ms, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// Choose my Foo

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Foo should exist
		Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(fs);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   8   Bar   6      \"\"\n" + 
			"   14   Foo *32   4      \"\"\n" + 
			"}\n" + 
			"Length: 18 Alignment: 1\n", fs.toString());
		//@formatter:on

		// my_struct should have a Foo and Byte
		Structure ms = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "my_struct");
		assertNotNull(ms);
		//@formatter:off
		assertEquals("/Category1/Category2/Category3/my_struct\n" + 
			"pack(disabled)\n" + 
			"Structure my_struct {\n" + 
			"   0   Foo   18      \"\"\n" + 
			"   18   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 19 Alignment: 1\n", ms.toString());
		//@formatter:on

		// Structure1 should exist as modified by Latest. (My didn't change it.)
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		//@formatter:off
		assertEquals("/Category1/Category2/Structure_1\n" + 
			"pack(disabled)\n" + 
			"Structure Structure_1 {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   word   2      \"\"\n" + 
			"   3   -BAD-   10      \"Type 'Foo' was deleted\"\n" + 
			"   13   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1\n", s1.toString());
		//@formatter:on

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				// delete Bar from Foo
				fs.delete(3);
				// add Foo to Bar
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				bar.add(fs);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
				fs.add(new QWordDataType());
				fs.add(bs);
				fs.add(PointerDataType.getPointer(fs, 4));

				// change Bar
				bs.add(new ByteDataType());
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// Bar gets a Foo

		chooseOption(DataTypeMergeManager.OPTION_MY);// Foo keeps its Bar, which creates Foo.conflict.

		pressButtonByName(waitForWindow("Structure Update Failed"), "OK"); // expected dependency error on Bar (2 occurances of Bar use)

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// should be two .conflict data types
		checkConflictCount(0);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   -BAD-   6      \"Failed to apply 'Bar', Data type Bar has Foo within it.\"\n" + 
			"   10   qword   8      \"\"\n" + 
			"   18   -BAD-   6      \"Failed to apply 'Bar', Data type Bar has Foo within it.\"\n" + 
			"   24   Foo *32   4      \"\"\n" + 
			"}\n" + 
			"Length: 28 Alignment: 1\n", foo.toString());
		//@formatter:on

		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);
		//@formatter:off
		assertEquals("/MISC/Bar\n" + 
			"pack(disabled)\n" + 
			"Structure Bar {\n" + 
			"   0   word   2      \"\"\n" + 
			"   2   Structure_1 *32   4      \"\"\n" + 
			"   6   Foo   28      \"\"\n" + 
			"}\n" + 
			"Length: 34 Alignment: 1\n", bar.toString());
		//@formatter:on

		// Structure_1 should have a Foo component
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		//@formatter:off
		assertEquals("/Category1/Category2/Structure_1\n" + 
			"pack(disabled)\n" + 
			"Structure Structure_1 {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   word   2      \"\"\n" + 
			"   3   Foo   10      \"\"\n" + 
			"   13   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1\n", s1.toString());
		//@formatter:on

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure array =
					(Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");

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
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		dismissUnresolvedDataTypesPopup();

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure array =
					(Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");

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
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure array =
					(Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");

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
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Latest
		// which means to delete BAR

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo from MY

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		// new data types from MY should go in as .conflicts
		checkConflictCount(4);// get .conflict for pointer to s3

		Structure bs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bs);

		Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(fs);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   -BAD-   6      \"Failed to apply 'Bar'\"\n" + 
			"   10   S1.conflict   5      \"\"\n" + 
			"   15   S2.conflict   12      \"\"\n" + 
			"}\n" + 
			"Length: 27 Alignment: 1\n", fs.toString());
		//@formatter:on

		Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "S1.conflict");
		assertNotNull(s1);
		//@formatter:off
		assertEquals("/MISC/S1.conflict\n" + 
			"pack(disabled)\n" + 
			"Structure S1.conflict {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte *32   4      \"\"\n" + 
			"}\n" + 
			"Length: 5 Alignment: 1\n", s1.toString());
		//@formatter:on

		Structure s2 = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "S2.conflict");
		assertNotNull(s2);
		//@formatter:off
		assertEquals("/MISC/S2.conflict\n" + 
			"pack(disabled)\n" + 
			"Structure S2.conflict {\n" + 
			"   0   Foo *32   4      \"\"\n" + 
			"   4   qword   8      \"\"\n" + 
			"}\n" + 
			"Length: 12 Alignment: 1\n", s2.toString());
		//@formatter:on

		Structure struct_1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(struct_1);
		//@formatter:off
		assertEquals("/Category1/Category2/Structure_1\n" + 
			"pack(disabled)\n" + 
			"Structure Structure_1 {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   word   2      \"\"\n" + 
			"   3   Foo   10      \"\"\n" + 
			"   13   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1\n", struct_1.toString());
		//@formatter:on

		// Structure_1 should contain Foo from MY although its component will not reflect
		// change in Foo size.
		assertTrue(struct_1.getDefinedComponents()[2].getDataType() == fs);

	}

	@Test
	public void testMultiEdits11() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				// delete Foo from the data type manager
				dtm.remove(fs, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.getDataType(new CategoryPath("/MISC"), "Bar");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				// delete Foo from the data type manager
				dtm.remove(fs, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				// delete Bar from Foo
				foo.delete(3);
				// add Foo to Bar
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				bar.add(foo);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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

				foo.add(new ArrayDataType(p, 0, 0, dtm));

				array = new ArrayDataType(bar, 0, 0, dtm);
				foo.add(array);

				foo.add(new PointerDataType(array, dtm));

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
		assertEquals(10, list.size());

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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

				foo.add(new ArrayDataType(p, 0, 0, dtm));

				array = new ArrayDataType(bar, 0, 0, dtm);
				foo.add(array);

				foo.add(new PointerDataType(array, dtm));
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

		assertEquals("/MISC/Foo\n" + "pack(disabled)\n" + "Structure Foo {\n" +
			"   0   byte   1      \"\"\n" + "   1   byte   1      \"\"\n" +
			"   2   word   2      \"\"\n" + "   4   Bar   6      \"\"\n" +
			"   14   MyArray_Typedef *32 *32 *32 *32 *32 *32 *32 *32   4      \"\"\n" +
			"   18   MyArray_Typedef *32 *32 *32 *32 *32 *32 *32 *32[0]   0      \"\"\n" +
			"   18   Bar[0]   0      \"\"\n" + "   18   Bar[0] *   4      \"\"\n" + "}\n" +
			"Length: 22 Alignment: 1\n" + "", foo.toString());

		// Bar should NOT have Foo * * * * * *
		DataTypeComponent[] dtcs = bar.getDefinedComponents();
		assertEquals(2, dtcs.length);
		assertTrue(dtcs[1].getDataType() instanceof Pointer);

		//Foo should have MyArray_Typedef * * * * * * * * 
		dtcs = foo.getDefinedComponents();
		assertEquals(8, dtcs.length);
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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
	public void testDeletedBaseTypeDef4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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

				foo.add(new ArrayDataType(p, 0, 0, dtm));

				array = new ArrayDataType(bar, 0, 0, dtm);
				foo.add(array);

				foo.add(new PointerDataType(array, dtm));

			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose Bar deleted

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose My Foo - Bar removal will cause problems

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   -BAD-   10      \"Failed to apply 'Bar'\"\n" + 
			"   14   -BAD-   4      \"Failed to apply 'MyArray_Typedef * * * * * * * *'\"\n" + 
			"   18   -BAD-   0      \"Failed to apply 'MyArray_Typedef * * * * * * * *[0]'\"\n" + 
			"   18   -BAD-   0      \"Failed to apply 'Bar[0]'\"\n" + 
			"   18   -BAD-   4      \"Failed to apply 'Bar[0] *'\"\n" + 
			"}\n" + 
			"Length: 22 Alignment: 1\n", foo.toString());
		//@formatter:on

		// should be no .conflict data types
		checkConflictCount(0);
	}

	@Test
	public void testDeletedBasePointerDT() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

				// edit Bar to create conflict because Latest deleted it
				Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
				p = PointerDataType.getPointer(p, 4);// Foo * * 
				p = PointerDataType.getPointer(p, 4);// Foo * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
				bar.add(p);

				// create a TypeDef on Bar
				TypeDef td = new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

				// edit Bar to create conflict because Latest deleted it
				Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
				p = PointerDataType.getPointer(p, 4);// Foo * * 
				p = PointerDataType.getPointer(p, 4);// Foo * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
				bar.add(p);

				// create a TypeDef on Bar
				TypeDef td = new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
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
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose LATEST Bar so delete it

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo MY

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   -BAD-   10      \"Failed to apply 'Bar'\"\n" + 
			"   14   -BAD-   4      \"Failed to apply 'MyBar_Typedef * * * * * * * *'\"\n" + 
			"}\n" + 
			"Length: 18 Alignment: 1\n", foo.toString());
		//@formatter:on

		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);

		// TypeDef on Bar should not exist
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef");
		assertNull(td);

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

				// edit Bar to create conflict because Latest deleted it
				Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
				p = PointerDataType.getPointer(p, 4);// Foo * * 
				p = PointerDataType.getPointer(p, 4);// Foo * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * * *
				p = PointerDataType.getPointer(p, 4);// Foo * * * * * *
				bar.add(p);

				// create a TypeDef on Bar
				TypeDef td = new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");

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
				TypeDef td = new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
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
			}
		});
		executeMerge();
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Conflict on Bar
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// choose to Delete Bar

		// Conflict on Foo
		chooseOption(DataTypeMergeManager.OPTION_MY);// choose Foo MY

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		// Bar should have been removed 
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   -BAD-   10      \"Failed to apply 'Bar'\"\n" + 
			"   14   -BAD-   4      \"Failed to apply 'MyBar_Typedef * * * * * * * *'\"\n" + 
			"}\n" + 
			"Length: 18 Alignment: 1\n", foo.toString());
		//@formatter:on

		// MyBar_Typedef should not exist since the option to delete Bar was chosen
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef"));

	}

	@Test
	public void testMovedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				// change ArrayStruct
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.add(new FloatDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("MyIntStruct");
					dt.setCategoryPath(new CategoryPath("/MyCategory/Ints"));
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
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
