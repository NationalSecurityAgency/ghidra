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

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.database.ProgramModifierListener;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Tests for merging data types.
 */
public class DataTypeMergeUseForAllTest extends AbstractDataTypeMergeTest {

	@Test
	public void testDataTypeDeletedChangedDoNotUseForAll() throws Exception {

		setupTestDataTypeDeletedChangedUseForAll();

		executeMerge();
		resolveConflict(DataTypeMergePanel.class, DataTypeMergePanel.class,
			DataTypeMergeManager.OPTION_MY, false);// IntStruct

		resolveConflict(DataTypeMergePanel.class, DataTypeMergePanel.class,
			DataTypeMergeManager.OPTION_ORIGINAL, false);// CharStruct

		resolveConflict(DataTypeMergePanel.class, DataTypeMergePanel.class,
			DataTypeMergeManager.OPTION_LATEST, false);// CoolUnion

		waitForMergeCompletion();

		// Verify results
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt3 = c3.getDataType("IntStruct");
		assertNull(dt3);
		assertNull(dtm.getDataType(c3.getCategoryPath(), "IntStruct"));

		Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
		DataType dt4 = c4.getDataType("CharStruct");
		assertNotNull(dt4);
		assertNotNull(dtm.getDataType(c4.getCategoryPath(), "CharStruct"));
		Structure struct4 = (Structure) dt4;
		assertEquals(5, struct4.getNumComponents());
		assertEquals("float", struct4.getComponent(4).getDataType().getDisplayName());

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType dt2 = c2.getDataType("CoolUnion");
		assertNotNull(dt2);
		assertNotNull(dtm.getDataType(c2.getCategoryPath(), "CoolUnion"));
		Union union2 = (Union) dt2;
		assertEquals(5, union2.getNumComponents());
		assertEquals("DLL_Table *", union2.getComponent(4).getDataType().getDisplayName());
	}

	public void setupTestDataTypeDeletedChangedUseForAll() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");
				Structure intStruct =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				Union coolUnion =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure charStruct =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category4"),
						"CharStruct");

				try {
					intStruct.add(new ByteDataType());// Change data type.
					dtm.remove(coolUnion, TaskMonitorAdapter.DUMMY_MONITOR);// Remove the data type.
					charStruct.add(new FloatDataType());
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
				Structure intStruct =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				Union coolUnion =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				Structure charStruct =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category4"),
						"CharStruct");

				try {
					dtm.remove(intStruct, TaskMonitorAdapter.DUMMY_MONITOR);// Remove the data type.
					coolUnion.delete(2);
					charStruct.add(new CharDataType());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testDataTypeDeletedChangedUseForAllPickLatest() throws Exception {

		setupTestDataTypeDeletedChangedUseForAll();

		executeMerge();
		resolveConflict(DataTypeMergePanel.class, DataTypeMergePanel.class,
			DataTypeMergeManager.OPTION_LATEST, true);
		waitForMergeCompletion();

		// Verify results
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt3 = c3.getDataType("IntStruct");
		assertNotNull(dt3);
		assertNotNull(dtm.getDataType(c3.getCategoryPath(), "IntStruct"));
		Structure struct3 = (Structure) dt3;
		assertEquals(5, struct3.getNumComponents());
		assertEquals("byte", struct3.getComponent(4).getDataType().toString());

		Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
		DataType dt4 = c4.getDataType("CharStruct");
		assertNotNull(dt4);
		assertNotNull(dtm.getDataType(c4.getCategoryPath(), "CharStruct"));
		Structure struct4 = (Structure) dt4;
		assertEquals(5, struct4.getNumComponents());
		assertEquals("float", struct4.getComponent(4).getDataType().toString());

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType dt2 = c2.getDataType("CoolUnion");
		assertNull(dt2);
		assertNull(dtm.getDataType(c2.getCategoryPath(), "CoolUnion"));
	}

	@Test
	public void testDataTypeDeletedChangedUseForAllPickMy() throws Exception {

		setupTestDataTypeDeletedChangedUseForAll();

		executeMerge();
		resolveConflict(DataTypeMergePanel.class, DataTypeMergePanel.class,
			DataTypeMergeManager.OPTION_MY, true);
		waitForMergeCompletion();

		// Verify results
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt3 = c3.getDataType("IntStruct");
		assertNull(dt3);
		assertNull(dtm.getDataType(c3.getCategoryPath(), "IntStruct"));

		Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
		DataType dt4 = c4.getDataType("CharStruct");
		assertNotNull(dt4);
		assertNotNull(dtm.getDataType(c4.getCategoryPath(), "CharStruct"));
		Structure struct4 = (Structure) dt4;
		assertEquals(5, struct4.getNumComponents());
		assertEquals("char", struct4.getComponent(4).getDataType().getDisplayName());

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType dt2 = c2.getDataType("CoolUnion");
		assertNotNull(dt2);
		assertNotNull(dtm.getDataType(c2.getCategoryPath(), "CoolUnion"));
		Union union2 = (Union) dt2;
		assertEquals(4, union2.getNumComponents());
		assertEquals("qword", union2.getComponent(0).getDataType().getDisplayName());
		assertEquals("word", union2.getComponent(1).getDataType().getDisplayName());
		assertEquals("DLL_Table", union2.getComponent(2).getDataType().getDisplayName());
		assertEquals("DLL_Table *", union2.getComponent(3).getDataType().getDisplayName());
	}

	@Test
	public void testDataTypeDeletedChangedUseForAllPickOriginal() throws Exception {

		setupTestDataTypeDeletedChangedUseForAll();

		executeMerge();
		resolveConflict(DataTypeMergePanel.class, DataTypeMergePanel.class,
			DataTypeMergeManager.OPTION_ORIGINAL, true);
		waitForMergeCompletion();

		// Verify results
		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Category c3 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		DataType dt3 = c3.getDataType("IntStruct");
		assertNotNull(dt3);
		assertNotNull(dtm.getDataType(c3.getCategoryPath(), "IntStruct"));
		Structure struct3 = (Structure) dt3;
		assertEquals(4, struct3.getNumComponents());
		assertEquals("qword", struct3.getComponent(3).getDataType().getDisplayName());

		Category c4 = dtm.getCategory(new CategoryPath("/Category1/Category2/Category4"));
		DataType dt4 = c4.getDataType("CharStruct");
		assertNotNull(dt4);
		assertNotNull(dtm.getDataType(c4.getCategoryPath(), "CharStruct"));
		Structure struct4 = (Structure) dt4;
		assertEquals(4, struct4.getNumComponents());
		assertEquals("unicode", struct4.getComponent(3).getDataType().getDisplayName());

		Category c2 = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		DataType dt2 = c2.getDataType("CoolUnion");
		assertNotNull(dt2);
		assertNotNull(dtm.getDataType(c2.getCategoryPath(), "CoolUnion"));
		Union union2 = (Union) dt2;
		assertEquals(5, union2.getNumComponents());
		assertEquals("DLL_Table *", union2.getComponent(4).getDataType().getDisplayName());
	}
}
