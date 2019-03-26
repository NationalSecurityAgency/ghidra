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
import ghidra.program.model.data.Enum;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *
 * More data type merge tests.
 * 
 * 
 */
public class DataTypeMerge5Test extends AbstractDataTypeMergeTest {

	@Test
    public void testTypeDefUndefined() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");

					TypeDef td = new TypedefDataType(new CategoryPath("/Category1"), "TD_Default",
						DataType.DEFAULT);

					dtc = union.add(td);
					dtc.setComment("a typedef");
					dtc.setFieldName("typedef field name TD_Default");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_Default");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof TypeDef);
		dt = ((TypeDef) dt).getBaseDataType();
		assertEquals(dt, DataType.DEFAULT);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
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
					Pointer p = PointerDataType.getPointer(enumm, 4);// MyEnum *
					p = PointerDataType.getPointer(p, 4);// MyEnum * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * * * *

					// create an array of MyEnum * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());

					TypeDef td = new TypedefDataType(new CategoryPath("/Category1"),
						"TD_MyEnumPointer", array);

					dtc = union.add(td);
					dtc.setComment("a typedef");
					dtc.setFieldName("typedef field name TD_MyEnumPointer");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

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
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof TypeDef);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);
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

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// MyEnum *
					p = PointerDataType.getPointer(p, 4);// MyEnum * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * * * *

					// create an array of MyEnum * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// MyEnum * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);

					dtc = union.add(td);
					dtc.setComment("a typedef");
					dtc.setFieldName("typedef field name TD_MyEnumPointer");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);
		assertEquals("typedef field name TD_MyEnumPointer", dtcs[6].getFieldName());
		assertEquals("a typedef", dtcs[6].getComment());

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof TypeDef);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs3() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.remove("Red");
					enumm.remove("Black");
					enumm.add("Crimson", 6);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);

					dtc = union.add(td);
					dtc.setComment("a typedef");
					dtc.setFieldName("typedef field name TD_MyEnumPointer");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST FavoriteColors

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);
		assertEquals("typedef field name TD_MyEnumPointer", dtcs[6].getFieldName());
		assertEquals("a typedef", dtcs[6].getComment());

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNotNull(enumm);
		assertEquals(3, enumm.getCount());
		assertEquals("Crimson", enumm.getName(6));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof TypeDef);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs4() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// delete FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					dtm.remove(enumm, TaskMonitorAdapter.DUMMY_MONITOR);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);

					dtc = union.add(td);
					dtc.setComment("a typedef");
					dtc.setFieldName("typedef field name TD_MyEnumPointer");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_MY);// MY FavoriteColors

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);
		assertEquals("typedef field name TD_MyEnumPointer", dtcs[6].getFieldName());
		assertEquals("a typedef", dtcs[6].getComment());

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNotNull(enumm);
		assertEquals(6, enumm.getCount());
		assertEquals("Gold", enumm.getName(8));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof TypeDef);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs5() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// delete FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					dtm.remove(enumm, TaskMonitorAdapter.DUMMY_MONITOR);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);

					dtc = union.add(td);
					dtc.setComment("a typedef");
					dtc.setFieldName("typedef field name TD_MyEnumPointer");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// delete FavoriteColors

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		// Typedef should not have been created because we chose to 
		// delete FavoriteColors (deleted in LATEST)
		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNull(enumm);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(6, dtcs.length);
		assertEquals("Float Field", dtcs[5].getFieldName());
		assertEquals("my comments", dtcs[5].getComment());

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNull(td);
		assertEquals(dll, dtcs[3].getDataType());

		ArrayList<DataType> list = new ArrayList<DataType>();
		dtm.findDataTypes("FavoriteColors*", list, false, null);
		assertEquals(0, list.size());
		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs6() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.remove("Red");
					enumm.remove("Black");
					enumm.add("Crimson", 6);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);
					p = PointerDataType.getPointer(td, 4);//TD_MyEnumPointer *
					dtc = union.add(p);
					dtc.setComment("a pointer to a typedef");
					dtc.setFieldName("typedef field name TD_MyEnumPointer *");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST FavoriteColors

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);
		assertEquals("typedef field name TD_MyEnumPointer *", dtcs[6].getFieldName());
		assertEquals("a pointer to a typedef", dtcs[6].getComment());

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNotNull(enumm);
		assertEquals(3, enumm.getCount());
		assertEquals("Crimson", enumm.getName(6));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof TypeDef);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs7() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.remove("Red");
					enumm.remove("Black");
					enumm.add("Crimson", 6);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);
					p = PointerDataType.getPointer(td, 4);//TD_MyEnumPointer *

					// create a TypeDef on p
					td = new TypedefDataType(new CategoryPath("/Category1"), "TD_on_Pointer", p);
					dtc = union.add(td);
					dtc.setFieldName("typedef field name");
					dtc.setComment("a typedef on a pointer to a typedef");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST FavoriteColors

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);
		assertEquals("typedef field name", dtcs[6].getFieldName());
		assertEquals("a typedef on a pointer to a typedef", dtcs[6].getComment());

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNotNull(enumm);
		assertEquals(3, enumm.getCount());
		assertEquals("Crimson", enumm.getName(6));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		TypeDef td2 = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_on_Pointer");
		assertNotNull(td2);
		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td2);

		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs8() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.remove("Red");
					enumm.remove("Black");
					enumm.add("Crimson", 6);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);
					p = PointerDataType.getPointer(td, 4);//TD_MyEnumPointer *

					// create a TypeDef on p
					td = new TypedefDataType(new CategoryPath("/Category1"), "TD_on_Pointer", p);

					// create an Array of TD_on_Pointer
					array = new ArrayDataType(td, 7, td.getLength());
					dtc = union.add(array);
					dtc.setFieldName("array of typedef field name");
					dtc.setComment("an array of typedefs on a pointer to a typedef");
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST FavoriteColors

		waitForCompletion();

		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);
		assertEquals("array of typedef field name", dtcs[6].getFieldName());
		assertEquals("an array of typedefs on a pointer to a typedef", dtcs[6].getComment());

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNotNull(enumm);
		assertEquals(3, enumm.getCount());
		assertEquals("Crimson", enumm.getName(6));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		TypeDef td2 = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_on_Pointer");
		assertNotNull(td2);

		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof Array);
		dt = ((Array) dt).getDataType();

		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td2);

		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

	@Test
    public void testTypeDefs9() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					// rename FooTypedef
					DataType td = dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef");
					td.setName("My_FooTypeDef");
					// move typedef to /Category1/Category2/Category5
					Category c =
						dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
					c.moveDataType(td, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got DuplicateNameException!");
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

				try {
					// Edit Foo
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					Enum enumm = new EnumDataType(new CategoryPath("/Category1"), "MyEnum", 1);
					enumm.add("one", 1);
					enumm.add("two", 2);
					enumm.add("three", 3);
					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// MyEnum *
					p = PointerDataType.getPointer(p, 4);// MyEnum * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * * *
					p = PointerDataType.getPointer(p, 4);// MyEnum * * * * *

					// create an array of MyEnum * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// MyEnum * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);
					p = PointerDataType.getPointer(td, 4);//TD_MyEnumPointer *

					// create a TypeDef on p
					td = new TypedefDataType(new CategoryPath("/Category1"), "TD_on_Pointer", p);

					// create an Array of TD_on_Pointer
					array = new ArrayDataType(td, 7, td.getLength());
					foo.add(array);

					// create a pointer to an Array of IntStruct's
					DataType intStruct = dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					array = new ArrayDataType(intStruct, 5, intStruct.getLength());
					foo.add(array);

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(true);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/Category1"), "MyEnum");
		assertNotNull(enumm);
		assertEquals(3, enumm.getCount());
		assertEquals("one", enumm.getName(1));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		TypeDef td2 = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_on_Pointer");
		assertNotNull(td2);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");

		DataTypeComponent[] dtcs = foo.getDefinedComponents();
		assertEquals(6, dtcs.length);
		DataType dt = dtcs[4].getDataType();
		assertTrue(dt instanceof Array);
		assertEquals(7, ((Array) dt).getNumElements());

		dt = ((Array) dt).getDataType();

		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td2);

		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);

		dt = dtcs[5].getDataType();
		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();
		assertTrue(dt instanceof Structure);

		DataType intStruct =
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertNotNull(intStruct);
		assertEquals(intStruct, dt);

		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "FooTypedef"));
		checkConflictCount(0);
	}

	@Test
    public void testArrays() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);
					DataType dt =
						dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
					dtm.remove(dt, TaskMonitorAdapter.DUMMY_MONITOR);

					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.remove("Red");
					enumm.remove("Black");
					enumm.add("Crimson", 6);
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
				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");

				try {
					DataTypeComponent dtc = union.add(new FloatDataType());
					dtc.setComment("my comments");
					dtc.setFieldName("Float Field");
					// edit FavoriteColors
					Enum enumm =
						(Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
					enumm.add("Cyan", 5);
					enumm.add("Gold", 8);

					// create TypeDef on pointer to an Array of pointers

					Pointer p = PointerDataType.getPointer(enumm, 4);// FavoriteColors *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * *
					p = PointerDataType.getPointer(p, 4);// FavoriteColors * * * * *

					// create an array of FavoriteColors * * * * *
					Array array = new ArrayDataType(p, 5, p.getLength());
					p = PointerDataType.getPointer(array, 4);// FavoriteColors * * * * *[5] *

					TypeDef td =
						new TypedefDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer", p);
					p = PointerDataType.getPointer(td, 4);//TD_MyEnumPointer *

					// create a TypeDef on p
					td = new TypedefDataType(new CategoryPath("/Category1"), "TD_on_Pointer", p);

					// create an Array of TD_on_Pointer
					array = new ArrayDataType(td, 11, td.getLength());
					array = new ArrayDataType(array, 10, array.getLength());
					array = new ArrayDataType(array, 9, array.getLength());
					array = new ArrayDataType(array, 8, array.getLength());
					array = new ArrayDataType(array, 7, array.getLength());
					array = new ArrayDataType(array, 6, array.getLength());
					array = new ArrayDataType(array, 5, array.getLength());

					// create a pointer to array
					p = PointerDataType.getPointer(array, 4);//TD_on_Pointer[5][6][7][8][9][10][11] *
					dtc = union.add(p);
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
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);// original DLL_Table 

		chooseOption(DataTypeMergeManager.OPTION_MY);// my CoolUnion

		chooseOption(DataTypeMergeManager.OPTION_LATEST);// LATEST FavoriteColors

		waitForCompletion();
		// CoolUnion should not be null
		Union union =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(union);

		// DLL_Table should not be null
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(7, dtcs.length);

		Enum enumm = (Enum) dtm.getDataType(new CategoryPath("/MISC"), "FavoriteColors");
		assertNotNull(enumm);
		assertEquals(3, enumm.getCount());
		assertEquals("Crimson", enumm.getName(6));

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_MyEnumPointer");
		assertNotNull(td);
		TypeDef td2 = (TypeDef) dtm.getDataType(new CategoryPath("/Category1"), "TD_on_Pointer");
		assertNotNull(td2);

		DataType dt = dtcs[6].getDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof Array);
		assertEquals("TD_on_Pointer[5][6][7][8][9][10][11]", dt.getDisplayName());

		for (int i = 0; i < 7; i++) {
			assertTrue(dt instanceof Array);
			dt = ((Array) dt).getDataType();
		}

		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td2);

		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();
		assertTrue(dt instanceof TypeDef);
		assertEquals(dt, td);
		dt = ((TypeDef) dt).getBaseDataType();
		assertTrue(dt instanceof Pointer);
		dt = ((Pointer) dt).getDataType();

		assertTrue(dt instanceof Array);
		assertEquals(5, ((Array) dt).getNumElements());
		dt = ((Array) dt).getDataType();

		for (int i = 0; i < 5; i++) {
			assertTrue(dt instanceof Pointer);
			dt = ((Pointer) dt).getDataType();
		}
		assertEquals(enumm, dt);
		assertEquals(dll, dtcs[3].getDataType());

		checkConflictCount(0);
	}

}
