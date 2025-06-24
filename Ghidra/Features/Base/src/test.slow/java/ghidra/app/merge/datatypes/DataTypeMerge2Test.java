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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for merging data types.
 *
 *
 */
public class DataTypeMerge2Test extends AbstractDataTypeMergeTest {

	@Test
	public void testDataTypeEditedInMy() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("MyIntStruct");
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
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("MyIntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
	}

	@Test
	public void testDataTypeEditedInBoth() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				DataType cdt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category4"),
					"CharStruct");
				Structure s = (Structure) dt;
				Array array = new ArrayDataType(cdt, 0, cdt.getLength());
				s.add(new ByteDataType());
				s.add(new WordDataType());
				s.add(new PointerDataType(array, dtm));
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				DataType cdt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category4"),
					"CharStruct");
				Structure s = (Structure) dt;
				Array array = new ArrayDataType(cdt, 0, cdt.getLength());
				s.add(new PointerDataType(array, dtm));
				s.add(new ByteDataType());
				s.add(new WordDataType());
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(7, s.getNumComponents());
		DataTypeComponent dtc = s.getComponent(4);
		System.out.println(dtc.getDataType());
		//assertTrue(dtc.getDataType() instanceof Array);
	}

	@Test
	public void testDataTypeRenamedChanged() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
			}
		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		dt = c.getDataType("OtherIntStruct");
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
	}

	@Test
	public void testDataTypeRenamedChanged2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_IntStruct");
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
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(4, s.getNumComponents());
	}

	@Test
	public void testDataTypeRenamedChanged3() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_Int_Struct");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("My_Int_Struct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(4, s.getNumComponents());
	}

	@Test
	public void testDataTypeRenamedChanged4() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_IntStruct");
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
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("My_IntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
		assertNull(c.getDataType("OtherIntStruct"));
	}

	@Test
	public void testDataTypeRenamedInBoth() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
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

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_Int_Struct");
					Structure s = (Structure) dt;
					Pointer p = PointerDataType.getPointer(new ByteDataType(), 4);
					s.add(p);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("My_Int_Struct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(5, s.getNumComponents());
		assertNull(c.getDataType("OtherIntStruct"));
	}

	@Test
	public void testRenamedChanged() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Structure s = (Structure) dt;
					Pointer p = PointerDataType.getPointer(new ByteDataType(), 4);
					s.add(p);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("OtherIntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(5, s.getNumComponents());
		assertNull(c.getDataType("IntStruct"));
	}

	@Test
	public void testRenamedMoved() throws Exception {
		// in Latest move data type; in MY change the name;
		// should be a conflict
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category3/IntStruct to
				// /Category1
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_Int_Struct");
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertNotNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "My_Int_Struct"));
		assertNull(dtm.getDataType(new CategoryPath("/Category1"), "IntStruct"));
	}

	@Test
	public void testRenamedChangedMoved() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category3/IntStruct to
				// /Category1 and rename it
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		c = dtm.getCategory(new CategoryPath("/Category1"));
		dt = c.getDataType("OtherIntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
	}

	@Test
	public void testRenamedChangedMovedNoConflict() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
			}
		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);

		c = dtm.getCategory(new CategoryPath("/Category1"));
		dt = c.getDataType("OtherIntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
	}

	@Test
	public void testRenamedChangedMovedNoConflict2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt = c.getDataType("IntStruct");
		assertNull(dt);
		assertNull(c.getDataType("OtherIntStruct"));
		c = dtm.getCategory(new CategoryPath("/Category1"));
		dt = c.getDataType("OtherIntStruct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
	}

	@Test
	public void testEditSubType() throws Exception {
		// edit DLL_Table in latest; edit DLL_Table in private
		// only DLL_Table should be in conflict; not the ones where it is used.
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
				// move to /Category1/Category2
				c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.moveDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");

				try {
					dt.setName("MY_DLLs");
					Structure s = (Structure) dt;
					s.add(new FloatDataType());
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

		});
		//
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		assertNull(dtm.getDataType(CategoryPath.ROOT, "DLL_Table"));
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "MY_DLLs");
		assertNotNull(dll);
		assertEquals(9, dll.getNumComponents());
		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2"), "DLL_Table"));
	}

	@Test
	public void testEditSubType2() throws Exception {
		// edit DLL_Table in latest; edit DLL_Table in private
		// only DLL_Table should be in conflict; not the ones where it is used.
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
				// move to /Category1/Category2
				c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.moveDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");

				try {
					dt.setName("MY_DLLs");
					Structure s = (Structure) dt;
					s.add(new FloatDataType());
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

		});
		executeMerge(DataTypeMergeManager.OPTION_ORIGINAL);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2"), "DLL_Table"));
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertNotNull(dll);
		assertEquals(8, dll.getNumComponents());
		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2"), "DLL_Table"));
		assertNull(dtm.getDataType(CategoryPath.ROOT, "MY_DLLs"));
	}

	@Test
	public void testEditSubTypeArray() throws Exception {
		// edit ArrayStruct in latest; edit ArrayStruct in private
		// only ArrayStruct should be in conflict; not the ones where it is used.
		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("ArrayStruct");
				Structure s = (Structure) dt;
				s.add(new ByteDataType());
				s.add(new WordDataType());
				// move to /Category1/Category2
				c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
				try {
					c.moveDataType(s, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (DataTypeDependencyException e) {
					Assert.fail("Got DataTypeDependencyException!");
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("ArrayStruct");
				Category c5 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category5"));
				DataType floatStruct = c5.getDataType("FloatStruct");

				try {
					dt.setName("MY_ArrayStruct");
					Structure s = (Structure) dt;
					s.add(new FloatDataType());
					Array array = new ArrayDataType(floatStruct, 4, floatStruct.getLength());
					s.add(array);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		assertNull(dtm.getDataType(new CategoryPath("/Category1/Category2"), "ArrayStruct"));
		Structure s = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "MY_ArrayStruct");
		assertNotNull(s);
		assertEquals(5, s.getNumComponents());
		DataTypeComponent dtc = s.getComponent(4);
		assertTrue(dtc.getDataType() instanceof Array);
	}

	@Test
	public void testEditEnum() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				Enum enumm = (Enum) dt;
				enumm.add("Purple", 0x10);
				enumm.add("Grey", 0x20);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");

				try {
					dt.setName("MY_Favorite_Colors");
					Enum enumm = (Enum) dt;
					enumm.remove("Pink");
					enumm.add("Pink", 0x10);
				}
				catch (DuplicateNameException e) {
					Assert.fail("Got Duplicate name exception!");
				}
				catch (InvalidNameException e) {
					Assert.fail("Got InvalidNameException!");
				}
			}

		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/MISC"));
		DataType dt = c.getDataType("MY_Favorite_Colors");
		assertNotNull(dt);
		Enum enumm = (Enum) dt;
		assertEquals(0x10, enumm.getValue("Pink"));
	}

	@Test
	public void testEditEnumComments_NoConflict_CommentAddedInLatest() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				Enum enumm = (Enum) dt;
				String valueName = "Pink";
				long value = enumm.getValue(valueName);
				enumm.remove(valueName);
				enumm.add(valueName, value, "This is the latest comment on server");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				// no change
			}

		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/MISC"));
		DataType dt = c.getDataType("FavoriteColors");
		assertNotNull(dt);
		Enum enumm = (Enum) dt;
		assertEquals(0x3, enumm.getValue("Pink"));
		assertEquals("This is the latest comment on server", enumm.getComment("Pink"));
	}

	@Test
	public void testEditEnumComments_Conflict_TakeMyChanges() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				Enum enumm = (Enum) dt;
				String valueName = "Pink";
				long value = enumm.getValue(valueName);
				enumm.remove(valueName);
				enumm.add(valueName, value, "This is the latest comment on server");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				Enum enumm = (Enum) dt;
				String valueName = "Pink";
				long value = enumm.getValue(valueName);
				enumm.remove(valueName);
				enumm.add(valueName, value, "This my local updated comment");
			}

		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/MISC"));
		DataType dt = c.getDataType("FavoriteColors");
		assertNotNull(dt);
		Enum enumm = (Enum) dt;
		assertEquals(0x3, enumm.getValue("Pink"));
		assertEquals("This my local updated comment", enumm.getComment("Pink"));
	}

	@Test
	public void testEditEnumComments_Conflict_TakeLatestChanges() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				Enum enumm = (Enum) dt;
				String valueName = "Pink";
				long value = enumm.getValue(valueName);
				enumm.remove(valueName);
				enumm.add(valueName, value, "This is the latest comment on server");
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				Enum enumm = (Enum) dt;
				String valueName = "Pink";
				long value = enumm.getValue(valueName);
				enumm.remove(valueName);
				enumm.add(valueName, value, "This my local updated comment");
			}

		});
		executeMerge(DataTypeMergeManager.OPTION_LATEST);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c = dtm.getCategory(new CategoryPath("/MISC"));
		DataType dt = c.getDataType("FavoriteColors");
		assertNotNull(dt);
		Enum enumm = (Enum) dt;
		assertEquals(0x3, enumm.getValue("Pink"));
		assertEquals("This is the latest comment on server", enumm.getComment("Pink"));
	}

	@Test
	public void testDeletedInLatest() throws Exception {

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
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				// create a TypeDef on Bar
				TypeDef td = new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
				// create a Pointer to typedef on Bar
				Pointer p = PointerDataType.getPointer(foo, 4);// Foo *
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

				// edit Structure_1 to contain Bar
				s1.add(bar);
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		// Bar should not have been added back in
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);
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
			"   14   -BAD-   6      \"Failed to apply 'Bar'\"\n" + 
			"}\n" + 
			"Length: 20 Alignment: 1\n", s1.toString());
		//@formatter:on

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef");
		assertNull(td);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNotNull(foo);
		// Foo should not have MyBar_Typedef * * * * * * * *
		//@formatter:off
		assertEquals("/MISC/Foo\n" + 
			"pack(disabled)\n" + 
			"Structure Foo {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   byte   1      \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   -BAD-   6      \"Failed to apply 'Bar'\"\n" + 
			"   10   -BAD-   4      \"Failed to apply 'MyBar_Typedef * * * * * * * *'\"\n" + 
			"}\n" + 
			"Length: 14 Alignment: 1\n", foo.toString());
		//@formatter:on
	}

	@Test
	public void testAddedFuncSig() throws Exception {

		ParameterDefinitionImpl p1 =
			new ParameterDefinitionImpl("pw", WordDataType.dataType, "Comment1");
		ParameterDefinitionImpl p2 =
			new ParameterDefinitionImpl("pwp", new PointerDataType(WordDataType.dataType), null);
		ParameterDefinitionImpl p3 =
			new ParameterDefinitionImpl("pwa", new ArrayDataType(WordDataType.dataType, 1), null);

		mtf.initialize("notepad2", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				// remove Bar from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
				DataType word = dtm.getDataType(new CategoryPath("/"), "word");
				// remove Bar and word from the data type manager
				dtm.remove(bar, TaskMonitor.DUMMY);
				dtm.remove(word, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) {
				DataTypeManager dtm = program.getDataTypeManager();
				Symbol symbol = getUniqueSymbol(program, "entry");
				Address addr = symbol.getAddress();
				Listing listing = program.getListing();
				AddressSet set = new AddressSet();
				set.addRange(addr.getNewAddress(0x01006420), addr.getNewAddress(0x01006581));
				set.addRange(addr.getNewAddress(0x010065a4), addr.getNewAddress(0x010065cd));
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				try {
					symbol.delete();
					Function func =
						listing.createFunction("entry", addr, set, SourceType.USER_DEFINED);
					FunctionDefinitionDataType functionDef =
						new FunctionDefinitionDataType(func, false);
					functionDef.setReturnType(bar);
					functionDef.setCategoryPath(new CategoryPath("/MISC"));
					functionDef.setArguments(p1, p2, p3);
					dtm.addDataType(functionDef, DataTypeConflictHandler.DEFAULT_HANDLER);
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail("Modifying private program failed: " + e);
				}
			}
		});
		executeMerge();

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Bar"));
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "entry");
		assertNotNull(fd);
		assertEquals(DataType.DEFAULT, fd.getReturnType());
		ParameterDefinition[] arguments = fd.getArguments();
		assertEquals(3, arguments.length);
		assertSameArgument(p1, arguments[0]);
		assertSameArgument(p2, arguments[1]);
		assertSameArgument(p3, arguments[2]);
	}

	private void assertSameArgument(ParameterDefinition p1, ParameterDefinition p2) {
		assertTrue(p1.getDataType().isEquivalent(p2.getDataType()));
		assertEquals(p1.getName(), p2.getName());
		assertEquals(p1.getComment(), p2.getComment());
	}

	@Test
	public void testEditFuncSig() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				fd.setReturnType(bar);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();
				vars[0].setDataType(foo);
				vars[0].setComment("this is a comment");
				Pointer p = PointerDataType.getPointer(foo, 4);
				vars[1].setDataType(p);
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
		assertNotNull(fd);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertEquals(dll, fd.getReturnType());
		ParameterDefinition[] vars = fd.getArguments();
		assertEquals(foo, vars[0].getDataType());
		assertEquals("this is a comment", vars[0].getComment());
		DataType dt = vars[1].getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(foo, ((Pointer) dt).getDataType());
	}

	@Test
	public void testEditFuncSig2() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				fd.setReturnType(bar);
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.remove(foo, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();
				vars[0].setDataType(foo);
				vars[0].setComment("this is a comment");
				Pointer p = PointerDataType.getPointer(foo, 4);
				vars[1].setDataType(p);
			}
		});
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
		assertNotNull(fd);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNull(foo);
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertEquals(dll, fd.getReturnType());
		ParameterDefinition[] vars = fd.getArguments();
		assertEquals(DataType.DEFAULT, vars[0].getDataType());
		assertEquals("Failed to apply 'Foo'; this is a comment", vars[0].getComment());
		assertEquals(DataType.DEFAULT, vars[1].getDataType());
		assertEquals("Failed to apply 'Foo *'", vars[1].getComment());

	}

	@Test
	public void testEditFuncSig3() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				fd.setVarArgs(true);
				fd.setNoReturn(true);
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.remove(foo, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();
				vars[0].setDataType(foo);
				vars[0].setComment("this is a comment");
				Pointer p = PointerDataType.getPointer(foo, 4);
				vars[1].setDataType(p);
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
		assertNotNull(fd);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNull(foo);
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertEquals(dll, fd.getReturnType());
		ParameterDefinition[] vars = fd.getArguments();
		assertEquals(DataType.DEFAULT, vars[0].getDataType());
		assertEquals("Failed to apply 'Foo'; this is a comment", vars[0].getComment());
		assertEquals(DataType.DEFAULT, vars[1].getDataType());
		assertEquals("Failed to apply 'Foo *'", vars[1].getComment());
		assertFalse(fd.hasVarArgs());
		assertFalse(fd.hasNoReturn());
	}

	@Test
	public void testEditFuncSig4() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				fd.setVarArgs(true);
				fd.setNoReturn(true);
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				dtm.remove(foo, TaskMonitor.DUMMY);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();
				vars[0].setDataType(foo);
				vars[0].setComment("this is a comment");
				Pointer p = PointerDataType.getPointer(foo, 4);
				vars[1].setDataType(p);
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_LATEST);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
		assertNotNull(fd);
		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		assertNull(foo);
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertEquals(dll, fd.getReturnType());
		ParameterDefinition[] vars = fd.getArguments();
		assertEquals(4, vars.length);
		checkDataType(new WordDataType(), vars[0].getDataType());
		assertEquals("", vars[0].getComment());
		checkDataType(new CharDataType(), vars[1].getDataType());
		checkDataType(new Undefined4DataType(), vars[2].getDataType());
		checkDataType(new Undefined4DataType(), vars[3].getDataType());
		assertTrue(fd.hasVarArgs());
		assertTrue(fd.hasNoReturn());
	}

	@Test
	public void testEditFuncSig5() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");

				fd.setReturnType(VoidDataType.dataType);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();
				ParameterDefinition[] newVars = new ParameterDefinition[vars.length + 1];
				System.arraycopy(vars, 0, newVars, 0, vars.length);
				newVars[vars.length] = new ParameterDefinitionImpl("Bar", WordDataType.dataType,
					"this is another comment");
				fd.setArguments(newVars);
				fd.setVarArgs(true);
				fd.setNoReturn(true);
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
		assertNotNull(fd);
		Structure dll = (Structure) dtm.getDataType(CategoryPath.ROOT, "DLL_Table");
		assertEquals(dll, fd.getReturnType());
		ParameterDefinition[] vars = fd.getArguments();
		assertTrue(vars[0].getDataType() instanceof WordDataType);
		assertTrue(vars[1].getDataType() instanceof CharDataType);
		assertTrue(vars[2].getDataType() instanceof Undefined4DataType);
		assertTrue(vars[3].getDataType() instanceof Undefined4DataType);
		assertTrue(vars[4].getDataType() instanceof WordDataType);
		assertEquals("Bar", vars[4].getName());
		assertEquals("this is another comment", vars[4].getComment());
		assertTrue(fd.hasVarArgs());
		assertTrue(fd.hasNoReturn());
	}

	private void checkDataType(DataType expectedDataType, DataType actualDataType) {
		assertTrue("Expected " + expectedDataType + ", but is " + actualDataType + ".",
			actualDataType.isEquivalent(expectedDataType));
	}

	@Test
	public void testAddConflictFuncSig1() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				FunctionDefinition fd =
					new FunctionDefinitionDataType(new CategoryPath("/MISC"), "printf");
				fd.setReturnType(new WordDataType());
				fd.setArguments(new ParameterDefinition[] { new ParameterDefinitionImpl("format",
					new Pointer32DataType(new StringDataType()), null) });
				fd.setVarArgs(false);
				dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				FunctionDefinition fd =
					new FunctionDefinitionDataType(new CategoryPath("/MISC"), "printf");
				fd.setReturnType(new WordDataType());
				fd.setArguments(new ParameterDefinition[] { new ParameterDefinitionImpl("format",
					new Pointer32DataType(new StringDataType()), null) });
				fd.setVarArgs(true);
				dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		FunctionDefinition fd1 =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "printf");
		assertNotNull(fd1);
		ParameterDefinition[] vars = fd1.getArguments();
		assertEquals(1, vars.length);
		checkDataType(new Pointer32DataType(new StringDataType()), vars[0].getDataType());
		assertEquals("format", vars[0].getName());
		assertEquals(null, vars[0].getComment());
		checkDataType(new WordDataType(), fd1.getReturnType());
		assertFalse(fd1.hasVarArgs());

		FunctionDefinition fd2 =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "printf.conflict");
		assertNotNull(fd2);
		ParameterDefinition[] vars2 = fd2.getArguments();
		assertEquals(1, vars2.length);
		checkDataType(new Pointer32DataType(new StringDataType()), vars2[0].getDataType());
		assertEquals("format", vars2[0].getName());
		assertEquals(null, vars2[0].getComment());
		checkDataType(new WordDataType(), fd2.getReturnType());
		assertTrue(fd2.hasVarArgs());
	}

	@Test
	public void testAddConflictFuncSig2() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				FunctionDefinition fd =
					new FunctionDefinitionDataType(new CategoryPath("/MISC"), "exit");
				fd.setReturnType(VoidDataType.dataType);
				fd.setNoReturn(false);
				fd.setArguments(new ParameterDefinition[] {
					new ParameterDefinitionImpl("rc", IntegerDataType.dataType, null) });
				dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				FunctionDefinition fd =
					new FunctionDefinitionDataType(new CategoryPath("/MISC"), "exit");
				fd.setReturnType(VoidDataType.dataType);
				fd.setNoReturn(true);
				fd.setArguments(new ParameterDefinition[] {
					new ParameterDefinitionImpl("rc", IntegerDataType.dataType, null) });
				dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		FunctionDefinition fd1 =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "exit");
		assertNotNull(fd1);
		ParameterDefinition[] vars = fd1.getArguments();
		assertEquals(1, vars.length);
		checkDataType(IntegerDataType.dataType, vars[0].getDataType());
		assertEquals("rc", vars[0].getName());
		assertEquals(null, vars[0].getComment());
		checkDataType(VoidDataType.dataType, fd1.getReturnType());
		assertFalse(fd1.hasNoReturn());

		FunctionDefinition fd2 =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "exit.conflict");
		assertNotNull(fd2);
		ParameterDefinition[] vars2 = fd2.getArguments();
		assertEquals(1, vars2.length);
		checkDataType(IntegerDataType.dataType, vars2[0].getDataType());
		assertEquals("rc", vars2[0].getName());
		assertEquals(null, vars2[0].getComment());
		checkDataType(VoidDataType.dataType, fd2.getReturnType());
		assertTrue(fd2.hasNoReturn());
	}

}
