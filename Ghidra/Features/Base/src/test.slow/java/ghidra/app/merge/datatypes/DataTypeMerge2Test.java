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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				// Make no changes to Latest.
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");
				DataType cdt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category4"),
					"CharStruct");
				try {
					Structure s = (Structure) dt;
					Array array = new ArrayDataType(cdt, 5, cdt.getLength());
					s.add(new ByteDataType());
					s.add(new WordDataType());
					s.add(array);
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
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				DataType cdt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category4"),
					"CharStruct");
				try {
					Structure s = (Structure) dt;
					Array array = new ArrayDataType(cdt, 3, cdt.getLength());
					s.add(array);
					s.add(new ByteDataType());
					s.add(new WordDataType());
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
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(7, s.getNumComponents());
		DataTypeComponent dtc = s.getComponent(4);
		assertTrue(dtc.getDataType() instanceof Array);
	}

	@Test
	public void testDataTypeRenamedChanged() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
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
					s.add(new WordDataType());
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
		dt = c.getDataType("OtherIntStruct");
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(6, s.getNumComponents());
	}

	@Test
	public void testDataTypeRenamedChanged2() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
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
					dt.setName("My_IntStruct");
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
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
					dt.setName("My_Int_Struct");
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
		DataType dt = c.getDataType("My_Int_Struct");
		assertNotNull(dt);
		assertTrue(dt instanceof Structure);
		Structure s = (Structure) dt;
		assertEquals(4, s.getNumComponents());
	}

	@Test
	public void testDataTypeRenamedChanged4() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
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
					dt.setName("My_IntStruct");
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_Int_Struct");
					Structure s = (Structure) dt;
					Pointer p = PointerDataType.getPointer(new ByteDataType(), 4);
					s.add(p);
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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
					s.add(new WordDataType());
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
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Structure s = (Structure) dt;
					Pointer p = PointerDataType.getPointer(new ByteDataType(), 4);
					s.add(p);
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category3/IntStruct to
				// /Category1
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
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
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("My_Int_Struct");
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

		assertNotNull(
			dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"), "My_Int_Struct"));
		assertNull(dtm.getDataType(new CategoryPath("/Category1"), "IntStruct"));
	}

	@Test
	public void testRenamedChangedMoved() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				// move /Category1/Category2/Category3/IntStruct to
				// /Category1 and rename it
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
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
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
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
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					Structure s = (Structure) dt;
					s.add(new ByteDataType());
					s.add(new WordDataType());
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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
					s.add(new WordDataType());
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
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
				DataType dt = dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
					"IntStruct");

				try {
					dt.setName("OtherIntStruct");
					Category c = dtm.getCategory(new CategoryPath("/Category1"));
					c.moveDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");
				try {
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
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");

				try {
					dt.setName("MY_DLLs");
					Structure s = (Structure) dt;
					s.add(new FloatDataType());
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");
				try {
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
				Category c = dtm.getCategory(CategoryPath.ROOT);
				DataType dt = c.getDataType("DLL_Table");

				try {
					dt.setName("MY_DLLs");
					Structure s = (Structure) dt;
					s.add(new FloatDataType());
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("ArrayStruct");
				try {
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
				// move /Category1/Category2/Category5 to
				// /Category1/Category2/Category3
				int transactionID = program.startTransaction("test");
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
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				try {
					Enum enumm = (Enum) dt;
					enumm.add("Purple", 0x10);
					enumm.add("Grey", 0x20);

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
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");

				try {
					dt.setName("MY_Favorite_Colors");
					Enum enumm = (Enum) dt;
					enumm.remove("Pink");
					enumm.add("Pink", 0x10);
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
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				try {
					Enum enumm = (Enum) dt;
					String valueName = "Pink";
					long value = enumm.getValue(valueName);
					enumm.remove(valueName);
					enumm.add(valueName, value, "This is the latest comment on server");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
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
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				try {
					Enum enumm = (Enum) dt;
					String valueName = "Pink";
					long value = enumm.getValue(valueName);
					enumm.remove(valueName);
					enumm.add(valueName, value, "This is the latest comment on server");
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
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");

				try {
					Enum enumm = (Enum) dt;
					String valueName = "Pink";
					long value = enumm.getValue(valueName);
					enumm.remove(valueName);
					enumm.add(valueName, value, "This my local updated comment");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
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
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");
				try {
					Enum enumm = (Enum) dt;
					String valueName = "Pink";
					long value = enumm.getValue(valueName);
					enumm.remove(valueName);
					enumm.add(valueName, value, "This is the latest comment on server");
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
				Category c = dtm.getCategory(new CategoryPath("/MISC"));
				DataType dt = c.getDataType("FavoriteColors");

				try {
					Enum enumm = (Enum) dt;
					String valueName = "Pink";
					long value = enumm.getValue(valueName);
					enumm.remove(valueName);
					enumm.add(valueName, value, "This my local updated comment");
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"),
					"Structure_1");
				try {
					// create a TypeDef on Bar
					TypeDef td =
						new TypedefDataType(new CategoryPath("/MISC"), "MyBar_Typedef", bar);
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
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(DataTypeMergeManager.OPTION_MY);// choose my Foo

		// Bar should not have been added back in
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
		assertNull(bar);
		Structure s1 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2"), "Structure_1");
		DataTypeComponent[] dtcs = s1.getDefinedComponents();
		assertEquals(4, dtcs.length);
		assertEquals(20, s1.getLength());

		dtcs = s1.getComponents();
		for (int i = 6; i < 10; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}

		TypeDef td = (TypeDef) dtm.getDataType(new CategoryPath("/MISC"), "MyBar_Typedef");
		assertNull(td);

		Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
		// Foo should not have MyBar_Typedef * * * * * * * *
		dtcs = foo.getDefinedComponents();
		assertEquals(3, dtcs.length);
		assertEquals(14, foo.getLength());
		dtcs = foo.getComponents();
		for (int i = 10; i < 13; i++) {
			assertEquals(DataType.DEFAULT, dtcs[i].getDataType());
		}
	}

	@Test
	public void testAddedFuncSig() throws Exception {

		mtf.initialize("notepad2", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
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

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyPrivate(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyPrivate(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Symbol symbol = getUniqueSymbol(program, "entry");
				Address addr = symbol.getAddress();
				Listing listing = program.getListing();
				AddressSet set = new AddressSet();
				set.addRange(addr.getNewAddress(0x01006420), addr.getNewAddress(0x01006581));
				set.addRange(addr.getNewAddress(0x010065a4), addr.getNewAddress(0x010065cd));
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				int transactionID = program.startTransaction("test");
				try {
					symbol.delete();
					Function func =
						listing.createFunction("entry", addr, set, SourceType.USER_DEFINED);
					FunctionDefinitionDataType functionDef =
						new FunctionDefinitionDataType(func, false);
					functionDef.setReturnType(bar);
					functionDef.setCategoryPath(new CategoryPath("/MISC"));
					dtm.addDataType(functionDef, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				catch (Exception e) {
					e.printStackTrace();
					Assert.fail("Modifying private program failed: " + e);
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
		executeMerge(-1);
		DataTypeManager dtm = resultProgram.getDataTypeManager();
		assertNull(dtm.getDataType(new CategoryPath("/MISC"), "Bar"));
		FunctionDefinition fd =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "entry");
		assertNotNull(fd);
		assertEquals(DataType.DEFAULT, fd.getReturnType());
	}

	@Test
	public void testEditFuncSig() throws Exception {

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
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");

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
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
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
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure bar = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Bar");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");

				try {
					fd.setReturnType(bar);
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					dtm.remove(foo, TaskMonitor.DUMMY);
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
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
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
		executeMerge(DataTypeMergeManager.OPTION_MY);
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
		assertEquals("this is a comment", vars[0].getComment());
		assertEquals(DataType.DEFAULT, vars[1].getDataType());
	}

	@Test
	public void testEditFuncSig3() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");

				try {
					fd.setVarArgs(true);
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					dtm.remove(foo, TaskMonitor.DUMMY);
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
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
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
		executeMerge(DataTypeMergeManager.OPTION_MY);
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
		assertEquals("this is a comment", vars[0].getComment());
		assertEquals(DataType.DEFAULT, vars[1].getDataType());
		assertEquals(false, fd.hasVarArgs());
	}

	@Test
	public void testEditFuncSig4() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");

				try {
					fd.setVarArgs(true);
					Structure foo = (Structure) dtm.getDataType(new CategoryPath("/MISC"), "Foo");
					dtm.remove(foo, TaskMonitor.DUMMY);
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
				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
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
		assertEquals(true, fd.hasVarArgs());
	}

	@Test
	public void testEditFuncSig5() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");

				try {
					fd.setReturnType(VoidDataType.dataType);

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

				FunctionDefinition fd = (FunctionDefinition) dtm
						.getDataType(new CategoryPath("/MISC"), "MyFunctionDef");
				ParameterDefinition[] vars = fd.getArguments();

				int transactionID = program.startTransaction("test");
				try {
					ParameterDefinition[] newVars = new ParameterDefinition[vars.length + 1];
					System.arraycopy(vars, 0, newVars, 0, vars.length);
					newVars[vars.length] = new ParameterDefinitionImpl("Bar", WordDataType.dataType,
						"this is another comment");
					fd.setArguments(newVars);
					fd.setVarArgs(true);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
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
	}

	private void checkDataType(DataType expectedDataType, DataType actualDataType) {
		assertTrue("Expected " + expectedDataType + ", but is " + actualDataType + ".",
			actualDataType.isEquivalent(expectedDataType));
	}

	@Test
	public void testAddConflictFuncSig1() throws Exception {

		mtf.initialize("notepad3", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				try {
					FunctionDefinition fd =
						new FunctionDefinitionDataType(new CategoryPath("/MISC"), "printf");
					fd.setReturnType(new WordDataType());
					fd.setArguments(
						new ParameterDefinition[] { new ParameterDefinitionImpl("format",
							new Pointer32DataType(new StringDataType()), null) });
					fd.setVarArgs(false);
					dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
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
				int transactionID = program.startTransaction("test");
				try {
					FunctionDefinition fd =
						new FunctionDefinitionDataType(new CategoryPath("/MISC"), "printf");
					fd.setReturnType(new WordDataType());
					fd.setArguments(
						new ParameterDefinition[] { new ParameterDefinitionImpl("format",
							new Pointer32DataType(new StringDataType()), null) });
					fd.setVarArgs(true);
					dtm.addDataType(fd, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
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
		assertEquals(false, fd1.hasVarArgs());

		FunctionDefinition fd2 =
			(FunctionDefinition) dtm.getDataType(new CategoryPath("/MISC"), "printf.conflict");
		assertNotNull(fd2);
		ParameterDefinition[] vars2 = fd2.getArguments();
		assertEquals(1, vars2.length);
		checkDataType(new Pointer32DataType(new StringDataType()), vars2[0].getDataType());
		assertEquals("format", vars2[0].getName());
		assertEquals(null, vars2[0].getComment());
		checkDataType(new WordDataType(), fd2.getReturnType());
		assertEquals(true, fd2.hasVarArgs());
	}

}
