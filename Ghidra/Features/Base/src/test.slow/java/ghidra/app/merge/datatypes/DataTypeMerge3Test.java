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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				// 2 components should get removed from CoolUnion
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

		// choose MY
		chooseOption(DataTypeMergeManager.OPTION_MY);// DLL_Table from MY

		// then choose LATEST
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertNotNull(union);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   -BAD-   96      \"Type 'DLL_Table' was deleted\"\n" + 
			"   0   -BAD-   4      \"Type 'DLL_Table *' was deleted\"\n" + 
			"}\n" + 
			"Length: 96 Alignment: 1\n", union.toString());
		//@formatter:on;

		// DLL_Table should have a Word data type as the last component
		Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(s);
		//@formatter:off
		assertEquals("/DLL_Table\n" + 
			"pack(disabled)\n" + 
			"Structure DLL_Table {\n" + 
			"   0   string   13   COMDLG32   \"\"\n" + 
			"   13   string   12   SHELL32   \"\"\n" + 
			"   25   string   11   MSVCRT   \"\"\n" + 
			"   36   string   13   ADVAPI32   \"\"\n" + 
			"   49   string   13   KERNEL32   \"\"\n" + 
			"   62   string   10   GDI32   \"\"\n" + 
			"   72   string   11   USER32   \"\"\n" + 
			"   83   string   13   WINSPOOL32   \"\"\n" + 
			"   96   word   2      \"\"\n" + 
			"}\n" + 
			"Length: 98 Alignment: 1\n", s.toString());
		//@formatter:on;
	}

	@Test
	public void testDeleteUnionComponent2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				// 2 components should be bad in CoolUnion
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
			}
		});
		executeMerge();

		// choose DLL_Table from LATEST which means delete it
		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		// MY CoolUnion
		chooseOption(DataTypeMergeManager.OPTION_MY);

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertNotNull(union);

		// DLL_Table should not exist
		assertNull(dtm.getDataType(CategoryPath.ROOT, "DLL_Table"));

		// CoolUnion should not have DLL_Table components but should have Float
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   -BAD-   98      \"Failed to apply 'DLL_Table'\"\n" + 
			"   0   -BAD-   4      \"Failed to apply 'DLL_Table *'\"\n" + 
			"   0   float   4   Float_Field   \"my comments\"\n" + 
			"}\n" + 
			"Length: 98 Alignment: 1\n", union.toString());
		//@formatter:on
	}

	@Test
	public void testDeleteUnionComponent3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				// 2 components should get removed from CoolUnion
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					Union union = (Union) dt;
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					s.add(new WordDataType());
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		assertEquals("Float_Field", dtcs[5].getFieldName());
	}

	@Test
	public void testStructureUpdateFailure() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Union union = (Union) dt;
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				union.add(foo);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				foo.add(dt);
				foo.add(new FloatDataType());
			}
		});

		executeMerge();

		pressButtonByName(waitForWindow("Structure Update Failed"), "OK"); // expected dependency error on Foo

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
		assertEquals("Failed to apply 'CoolUnion', Data type CoolUnion has Foo within it.",
			fooComps[4].getComment());
	}

	@Test
	public void testStructureUpdateFailure2() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Union union = (Union) dt;
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				union.add(foo);
				// Edit Foo to cause a conflict
				foo.add(new ByteDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				foo.add(union);
				foo.add(new FloatDataType());
				// Edit CoolUnion to cause a conflict
				union.add(new FloatDataType(), "My Float", "My comments");
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY Foo

		pressButtonByName(waitForWindow("Structure Update Failed"), "OK"); // expected dependency error on Foo

		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(coolUnion);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   DLL_Table   96      \"\"\n" + 
			"   0   DLL_Table *32   4      \"\"\n" + 
			"   0   Foo   110      \"\"\n" + 
			"}\n" + 
			"Length: 110 Alignment: 1\n", coolUnion.toString());
		//@formatter:on

		// Foo should not contain CoolUnion because CoolUnion already 
		// contains Foo (from Latest)

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   Bar   6      \"\"\n" + 
			"   10   -BAD-   96      \"Failed to apply 'CoolUnion', Data type CoolUnion has Foo within it.\"\n" + 
			"   106   float   4      \"\"\n" + 
			"}\n" + 
			"Length: 110 Alignment: 1\n", foo.toString());
		//@formatter:on

	}

	@Test
	public void testStructureUpdateFailure3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Union union = (Union) dt;
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				union.add(foo);
				// Edit Foo to cause a conflict
				foo.add(new ByteDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				foo.add(union);
				foo.add(new FloatDataType());
				// Edit CoolUnion to cause a conflict
				union.add(new FloatDataType(), "My Float", "My comments");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				union.add(bar, "My field name", "My comments");
				bar.add(new ByteDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				bar.add(union);
				union.add(new ByteDataType(), "my field name", "some comments");
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// Latest CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_MY);// My Bar

		pressButtonByName(waitForWindow("Structure Update Failed"), "OK"); // expected dependency error on Bar

		waitForCompletion();

		checkConflictCount(0);

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(coolUnion);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   DLL_Table   96      \"\"\n" + 
			"   0   DLL_Table *32   4      \"\"\n" + 
			"   0   Bar   102   My_field_name   \"My comments\"\n" + 
			"}\n" + 
			"Length: 102 Alignment: 1\n", coolUnion.toString());
		//@formatter:on

		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);
		//@formatter:off
		assertEquals("/MISC/Bar\n" + 
			"pack(disabled)\n" + 
			"Structure Bar {\n" + 
			"   0   word   2      \"\"\n" + 
			"   2   Structure_1 *32   4      \"\"\n" + 
			"   6   -BAD-   96      \"Failed to apply 'CoolUnion', Data type CoolUnion has Bar within it.\"\n" + 
			"}\n" + 
			"Length: 102 Alignment: 1\n", bar.toString());
		//@formatter:on
	}

	@Test
	public void testConflictUpdate() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				bar.add(new ByteDataType());
				s1.delete(3);
				// edit Foo
				foo.add(new FloatDataType());
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
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				dtm.remove(dt, TaskMonitor.DUMMY);
				// causes Bar to be marked as changed
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				bar.add(new ByteDataType());
				s1.delete(3);
				// edit Foo
				foo.add(new FloatDataType());
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
				DataTypeManager dtm = program.getDataTypeManager();

				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
				dtm.remove(dt, TaskMonitor.DUMMY);
				// causes Bar to be marked as changed
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				bar.add(new ByteDataType());
				s1.delete(3);
				// edit Foo
				foo.add(new FloatDataType());
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// choose my Bar

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delele Structure_1 (choose Structure_1 from MY)

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// Bar should contain undefined to replace Structure_1
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNotNull(bar);
		//@formatter:off
		assertEquals("/MISC/Bar\n" + 
			"pack(disabled)\n" + 
			"Structure Bar {\n" + 
			"   0   word   2      \"\"\n" + 
			"   2   -BAD-   4      \"Failed to apply 'Structure_1 *'\"\n" + 
			"   6   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 7 Alignment: 1\n", bar.toString());
		//@formatter:on;

		// Structure_1 should have been deleted
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNull(s1);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   Bar   7      \"\"\n" + 
			"   11   float   4      \"\"\n" + 
			"}\n" + 
			"Length: 15 Alignment: 1\n", foo.toString());
		//@formatter:on;

		checkConflictCount(0);
	}

	@Test
	public void testConflictUpdate4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();

				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
					"FloatStruct");
				Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				Structure ms = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"MyStruct");
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
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure fs =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"),
						"FloatStruct");
				Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
				Structure ms = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"MyStruct");
				a.add(new FloatDataType());

				Structure mys1 = new StructureDataType(
					new CategoryPath("/Category1/Category2/Category5"), "my_s1", 0);
				mys1.add(a);

				mys1 = (Structure) dtm.addDataType(mys1, DataTypeConflictHandler.DEFAULT_HANDLER);
				// edit FloatStruct
				fs.add(mys1);

				// edit MyStruct
				ms.add(new FloatDataType());
				ms.add(new WordDataType());
			}
		});
		executeMerge();

		// conflict on ArrayStruct (6)
		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// use ORIGINAL ArrayStruct

		// conflict on MyStruct    (5)
		chooseOption(DataTypeMergeManager.OPTION_MY);// use MY MyStruct

		// conflict on FloatStruct (2)
		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete FloatStruct

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category5"), "FloatStruct"));

		Structure fs = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category5"), "FloatStruct");
		assertNull(fs);

		// MyStruct should have a FloatDataType and a Word
		Structure ms =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "MyStruct");
		assertNotNull(ms);
		//@formatter:off
		assertEquals("/Category1/Category2/MyStruct\n" + 
			"pack(disabled)\n" + 
			"Structure MyStruct {\n" + 
			"   0   -BAD-   120      \"Failed to apply 'FloatStruct[10]'\"\n" + 
			"   120   IntStruct[3]   45      \"\"\n" + 
			"   165   CharStruct * * *   4      \"\"\n" + 
			"   169   float   4      \"\"\n" + 
			"   173   word   2      \"\"\n" + 
			"}\n" + 
			"Length: 175 Alignment: 1\n", ms.toString());
		//@formatter:on;

		// ArrayStruct should have 3 components
		Structure a = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "ArrayStruct");
		assertNotNull(a);
		//@formatter:off
		assertEquals("/MISC/ArrayStruct\n" + 
			"pack(disabled)\n" + 
			"Structure ArrayStruct {\n" + 
			"   0   IntStruct * *[10]   40      \"\"\n" + 
			"   40   IntStruct[3]   45      \"\"\n" + 
			"   85   undefined * * * * *   4      \"\"\n" + 
			"}\n" + 
			"Length: 89 Alignment: 1\n", a.toString());
		//@formatter:on;
	}

	@Test
	public void testConflictUpdate5() throws Exception {

		TypeDef td = new TypedefDataType(new CategoryPath("/Category1/Category2"), "BF",
			IntegerDataType.dataType);

		mtf.initialize("notepad2", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				dtm.addDataType(td, null);
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2"), "BF");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				try {
					s1.insertBitFieldAt(3, 2, 6, td, 2, "bf1", "my bf1");
					s1.insertBitFieldAt(3, 2, 4, td, 2, "bf2", "my bf2");

					// foo grows but does alter size of existing component in s1
					foo.add(new FloatDataType());
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.toString());
				}
			}
		});

		// bitfield silently transitions to int since typedef BF was removed

		executeMerge();

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		assertNotNull(s1);
		//@formatter:off
		assertEquals("/Category1/Category2/Structure_1\n" + 
			"pack(disabled)\n" + 
			"Structure Structure_1 {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   word   2      \"\"\n" + 
			"   4   int:2(6)   1   bf1   \"Failed to apply 'BF'; my bf1\"\n" + 
			"   4   int:2(4)   1   bf2   \"Failed to apply 'BF'; my bf2\"\n" + 
			"   5   Foo   10      \"\"\n" + 
			"   15   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 16 Alignment: 1\n", s1.toString());
		//@formatter:on

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   Bar   6      \"\"\n" + 
			"   10   float   4      \"\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1\n", foo.toString());
		//@formatter:on

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
				// add new BF not compatible with BitFields
				dtm.addDataType(
					new StructureDataType(new CategoryPath("/Category1/Category2"), "BF", 0), null);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				s1.add(new ArrayDataType(td, 0, -1), 0, null, null);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				s1.add(new ArrayDataType(IntegerDataType.dataType, 0, -1), "flex1", "cmt1");
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
		assertEquals(5, dtcs.length);

		DataTypeComponent flexDtc = s1.getComponent(4);
		assertEquals(0, flexDtc.getLength());
		DataType dt = flexDtc.getDataType();
		assertTrue(dt instanceof Array);
		Array a = (Array) dt;
		assertEquals(0, a.getNumElements());
		assertTrue(a.getDataType() instanceof IntegerDataType);
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
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				s1.add(new ArrayDataType(IntegerDataType.dataType, 0, -1), 0, null, null);
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				// last component is flex array to be replaced
				s1.replace(s1.getNumComponents() - 1, new ArrayDataType(td, 0, -1), 0, "flex1",
					"cmt1");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				try {
					Structure s1 = (Structure) dtm
							.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
					s1.deleteAtOffset(s1.getLength());
					s1.insertBitFieldAt(3, 2, 6, td, 2, "bf1", "my bf1");
					s1.insertBitFieldAt(3, 2, 4, td, 2, "bf2", "my bf2");
				}
				catch (InvalidDataTypeException e) {
					e.printStackTrace();
					Assert.fail();
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

		for (DataTypeComponent dtc : s1.getComponents()) {
			assertNotEquals(0, dtc.getLength());
		}

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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType("/Category5/Test");
				DataType td = dtm.getDataType("/MISC/FooTypedef");
				s.replaceAtOffset(s.getLength(), new ArrayDataType(td, 0, -1), 0, "foo", null);
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
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

				DataType dt1 = dtm.getDataType("/BF");
				assertNull(dt1);
			}

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				try {
					TypeDef td = new TypedefDataType("BF", IntegerDataType.dataType);

					Structure struct = new StructureDataType(new CategoryPath("/Category5"), "Test",
						0, program.getDataTypeManager());
					struct.add(td);
					struct.insertBitFieldAt(3, 2, 6, td, 2, "bf1", null);
					struct.insertBitFieldAt(3, 2, 4, td, 2, "bf2", null);
					struct.add(new WordDataType());
					struct.add(new QWordDataType());
					struct.add(new ArrayDataType(td, 0, -1), 0, "flex", "my flex");

					dtm.addDataType(struct, null);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail(e.toString());
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				// 2 components should get removed from CoolUnion
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
		assertEquals("Float_Field", dtcs[5].getFieldName());

	}

	@Test
	public void testEditUnions2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				// 2 components should get removed from CoolUnion
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete DLL_Table

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// DLL_Table should not exist

		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNull(dll);

		// AnotherUnion should contain one component since DLL_Table was deleted
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "AnotherUnion");
		assertNotNull(union);
		//@formatter:off
		assertEquals("/Category1/Category2/AnotherUnion\n" + 
			"pack(disabled)\n" + 
			"Union AnotherUnion {\n" + 
			"   0   -BAD-   98      \"Failed to apply 'DLL_Table'\"\n" + 
			"   0   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 98 Alignment: 1\n", union.toString());
		//@formatter:on;

		union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   -BAD-   98      \"Failed to apply 'DLL_Table'\"\n" + 
			"   0   -BAD-   4      \"Failed to apply 'DLL_Table *'\"\n" + 
			"   0   float   4   Float_Field   \"my comments\"\n" + 
			"}\n" + 
			"Length: 98 Alignment: 1\n", union.toString());
		//@formatter:on;
	}

	@Test
	public void testEditUnions3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY CoolUnion

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   -BAD-   98      \"Failed to apply 'DLL_Table'\"\n" + 
			"   0   -BAD-   4      \"Failed to apply 'DLL_Table *'\"\n" + 
			"   0   float   4   Float_Field   \"my comments\"\n" + 
			"   0   MyEnum   1      \"\"\n" + 
			"}\n" + 
			"Length: 98 Alignment: 1\n", union.toString());
		//@formatter:on;

		// DLL_Table should be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNull(dll);

	}

	@Test
	public void testEditUnions5() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnum");
		assertNotNull(td);

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   DLL_Table   96      \"\"\n" + 
			"   0   DLL_Table *32   4      \"\"\n" + 
			"   0   float   4   Float_Field   \"my comments\"\n" + 
			"   0   TD_MyEnum   1      \"\"\n" + 
			"}\n" + 
			"Length: 96 Alignment: 1\n", union.toString());
		//@formatter:on;

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);
		//@formatter:off
		assertEquals("/DLL_Table\n" + 
			"pack(disabled)\n" + 
			"Structure DLL_Table {\n" + 
			"   0   string   13   COMDLG32   \"\"\n" + 
			"   13   string   12   SHELL32   \"\"\n" + 
			"   25   string   11   MSVCRT   \"\"\n" + 
			"   36   string   13   ADVAPI32   \"\"\n" + 
			"   49   string   13   KERNEL32   \"\"\n" + 
			"   62   string   10   GDI32   \"\"\n" + 
			"   72   string   11   USER32   \"\"\n" + 
			"   83   string   13   WINSPOOL32   \"\"\n" + 
			"}\n" + 
			"Length: 96 Alignment: 1\n", dll.toString());
		//@formatter:on;

		checkConflictCount(0);
	}

	@Test
	public void testEditUnions7() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
				dtm.remove(s, TaskMonitor.DUMMY);
				DataType dt =
					dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				dtm.remove(dt, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
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
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
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
				DataTypeManager dtm = program.getDataTypeManager();
				Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "XYZ", 1);
				enumm.add("one", 1);
				enumm.add("two", 2);
				enumm.add("three", 3);
				dtm.addDataType(
					new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnum", enumm), null);
			}

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();

				try {
					DataType enumm = dtm.getDataType(new CategoryPath("/Category1"), "XYZ");
					dtm.remove(enumm, TaskMonitor.DUMMY);

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					// NOTE: bit field component byte sizing is currently auto-sized and packed within unions
					union.insertBitField(1, IntegerDataType.dataType, 4, "bf1", "latest bf1");
					union.insertBitField(2, IntegerDataType.dataType, 2, "bf2", "latest bf2");
				}
				catch (InvalidDataTypeException e) {
					e.printStackTrace();
					Assert.fail();
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();

				try {
					DataType enumm = dtm.getDataType(new CategoryPath("/Category1"), "XYZ");
					assertTrue(enumm instanceof Enum);

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					// NOTE: bit field component byte sizing is currently auto-sized and packed within unions
					union.insertBitField(1, enumm, 4, "BF1", "my bf1");
					union.insertBitField(2, enumm, 2, "BF2", "my bf2");
				}
				catch (InvalidDataTypeException e) {
					e.printStackTrace();
					Assert.fail();
				}
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY bitfields w/ enum

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		// primitive type of byte used in absence of enum
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack(disabled)\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   byte:4(4)   1   BF1   \"Failed to apply 'XYZ'; my bf1\"\n" + 
			"   0   byte:2(6)   1   BF2   \"Failed to apply 'XYZ'; my bf2\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   DLL_Table   96      \"\"\n" + 
			"   0   DLL_Table *32   4      \"\"\n" + 
			"}\n" + 
			"Length: 96 Alignment: 1\n", union.toString());
		//@formatter:on
	}

}
