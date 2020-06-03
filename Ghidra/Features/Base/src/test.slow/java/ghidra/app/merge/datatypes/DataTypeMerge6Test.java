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

import ghidra.program.database.*;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Data type merge tests for aligned data types.
 */
public class DataTypeMerge6Test extends AbstractDataTypeMergeTest {

	private void setupStructureMachineAlignedVsValue() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.setInternallyAligned(true);
					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setToMachineAlignment();
					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(8, s.getAlignment());
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
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setMinimumAlignment(4);
					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructureMachineAlignedVsValuePickLatest() throws Exception {

		setupStructureMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		Structure s = (Structure) c.getDataType("IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(false, s.isDefaultAligned());
		assertEquals(true, s.isMachineAligned());
		assertEquals(8, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(8, s.getAlignment());
	}

	@Test
	public void testStructureMachineAlignedVsValuePickMy() throws Exception {

		setupStructureMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		Structure s = (Structure) c.getDataType("IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(false, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(4, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	@Test
	public void testStructureMachineAlignedVsValuePickOriginal() throws Exception {

		setupStructureMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		Structure s = (Structure) c.getDataType("IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	private void setupStructurePack1VsPack2() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.setInternallyAligned(true);

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					assertEquals(Composite.NOT_PACKING, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setPackingValue(1);

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(1, s.getComponent(1).getOffset());
					assertEquals(3, s.getComponent(2).getOffset());
					assertEquals(7, s.getComponent(3).getOffset());
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					assertEquals(1, s.getPackingValue());
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
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setPackingValue(2);

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(2, s.getAlignment());
					assertEquals(2, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructurePack1VsPack2PickLatest() throws Exception {

		setupStructurePack1VsPack2();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(1, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	@Test
	public void testStructurePack1VsPack2PickMy() throws Exception {

		setupStructurePack1VsPack2();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(2, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(2, s.getAlignment());
	}

	@Test
	public void testStructurePack1VsPack2PickOriginal() throws Exception {

		setupStructurePack1VsPack2();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2/Category3"));
		Structure s = (Structure) c.getDataType("IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	private void setupStructureMinAlignVsPack() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.setInternallyAligned(true);

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					assertEquals(Composite.NOT_PACKING, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setToMachineAlignment();

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(8, s.getAlignment());
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
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setPackingValue(1);

					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(1, s.getComponent(1).getOffset());
					assertEquals(3, s.getComponent(2).getOffset());
					assertEquals(7, s.getComponent(3).getOffset());
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					assertEquals(1, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructureMinAlignVsPackPickLatest() throws Exception {

		setupStructureMinAlignVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(false, s.isDefaultAligned());
		assertEquals(true, s.isMachineAligned());
		assertEquals(8, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(8, s.getAlignment());
	}

	@Test
	public void testStructureMinAlignVsPackPickMy() throws Exception {

		setupStructureMinAlignVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(1, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	private void setupStructureAddVsAlign() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.add(new IntegerDataType());

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(1, s.getComponent(1).getOffset());
					assertEquals(3, s.getComponent(2).getOffset());
					assertEquals(7, s.getComponent(3).getOffset());
					assertEquals(15, s.getComponent(4).getOffset());
					assertEquals(19, s.getLength());
					assertEquals(1, s.getAlignment());
					assertEquals(Composite.NOT_PACKING, s.getPackingValue());
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
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.setInternallyAligned(true);

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					assertEquals(Composite.NOT_PACKING, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructureAddVsAlignPickLatest() throws Exception {

		setupStructureAddVsAlign();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(false, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getComponent(4).getOffset());
		assertEquals(19, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	@Test
	public void testStructureAddVsAlignPickMy() throws Exception {

		setupStructureAddVsAlign();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	private void setupStructureFieldNameVsPack() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.setInternallyAligned(true);
					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					s.getComponent(1).setFieldName("MyComponentOne");

					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals("MyComponentOne", s.getComponent(1).getFieldName());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					assertEquals(Composite.NOT_PACKING, s.getPackingValue());
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
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					s.setPackingValue(1);

					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(1, s.getComponent(1).getOffset());
					assertEquals(3, s.getComponent(2).getOffset());
					assertEquals(7, s.getComponent(3).getOffset());
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					assertEquals(1, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructureNameVsPackPickLatest() throws Exception {

		setupStructureFieldNameVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	@Test
	public void testStructureNameVsPackPickMy() throws Exception {

		setupStructureFieldNameVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(1, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	private void setupStructureRemoveVsPack() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					s.setInternallyAligned(true);

					// Offsets change to 0,2,4,8.
					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(2, s.getComponent(1).getOffset());
					assertEquals(4, s.getComponent(2).getOffset());
					assertEquals(8, s.getComponent(3).getOffset());
					assertEquals(16, s.getLength());
					assertEquals(4, s.getAlignment());
					assertEquals(Composite.NOT_PACKING, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					dtm.remove(s, TaskMonitorAdapter.DUMMY_MONITOR);

					// Offsets change to 0,2,4,8.
					Structure intStruct = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertNull(intStruct);
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
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setPackingValue(1);

					assertEquals(0, s.getComponent(0).getOffset());
					assertEquals(1, s.getComponent(1).getOffset());
					assertEquals(3, s.getComponent(2).getOffset());
					assertEquals(7, s.getComponent(3).getOffset());
					assertEquals(15, s.getLength());
					assertEquals(1, s.getAlignment());
					assertEquals(1, s.getPackingValue());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructureRemoveVsPackPickLatest() throws Exception {

		setupStructureRemoveVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure intStruct =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertNull(intStruct);
	}

	@Test
	public void testStructureRemoveVsPackPickMy() throws Exception {

		setupStructureRemoveVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, s.isInternallyAligned());
		assertEquals(true, s.isDefaultAligned());
		assertEquals(false, s.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, s.getMinimumAlignment());
		assertEquals(1, s.getPackingValue());
		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	private void setupStructureInUnionAndViceVersa() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure s = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					s.setInternallyAligned(true);

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					union.setInternallyAligned(true);

					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Structure structure = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(16, structure.getLength());
					assertEquals(4, structure.getAlignment());

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					assertEquals(96, union.getLength());
					assertEquals(4, union.getAlignment());

					structure.add(union);
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
					Structure structure = (Structure) dtm.getDataType(
						new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
					assertEquals(16, structure.getLength());
					assertEquals(4, structure.getAlignment());

					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					assertEquals(96, union.getLength());
					assertEquals(4, union.getAlignment());

					union.add(structure);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testStructureInUnionAndViceVersa() throws Exception {

		setupStructureInUnionAndViceVersa();
		executeMerge();

		close(waitForWindow("Union Update Failed")); // expected dependency error on CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure intStruct =
			(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
				"IntStruct");
		assertEquals(true, intStruct.isInternallyAligned());
		assertEquals(true, intStruct.isDefaultAligned());
		assertEquals(false, intStruct.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, intStruct.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, intStruct.getPackingValue());
		assertEquals(5, intStruct.getNumComponents());
		assertEquals(0, intStruct.getComponent(0).getOffset());
		assertEquals(2, intStruct.getComponent(1).getOffset());
		assertEquals(4, intStruct.getComponent(2).getOffset());
		assertEquals(8, intStruct.getComponent(3).getOffset());
		assertEquals(16, intStruct.getComponent(4).getOffset());
		assertEquals("CoolUnion", intStruct.getComponent(4).getDataType().getDisplayName());
		assertEquals(112, intStruct.getLength());
		assertEquals(4, intStruct.getAlignment());

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertEquals(true, coolUnion.isInternallyAligned());
		assertEquals(true, coolUnion.isDefaultAligned());
		assertEquals(false, coolUnion.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, coolUnion.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, coolUnion.getPackingValue());
		assertEquals(6, coolUnion.getNumComponents());
		assertEquals("qword", coolUnion.getComponent(0).getDataType().getDisplayName());
		assertEquals("word", coolUnion.getComponent(1).getDataType().getDisplayName());
		assertEquals("undefined * * * * *",
			coolUnion.getComponent(2).getDataType().getDisplayName());
		assertEquals("DLL_Table", coolUnion.getComponent(3).getDataType().getDisplayName());
		assertEquals("DLL_Table *", coolUnion.getComponent(4).getDataType().getDisplayName());
		assertTrue(coolUnion.getComponent(5).getDataType() instanceof BadDataType);
		String comment5 = coolUnion.getComponent(5).getComment();
		assertTrue(comment5.startsWith("Couldn't add IntStruct here."));
		assertEquals(96, coolUnion.getLength());
		assertEquals(4, coolUnion.getAlignment());

	}

	/////////////////////////////////////////////////

	public void setupUnionMachineAlignedVsValue() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					assertEquals(96, union.getLength());
					assertEquals(1, union.getAlignment());
					union.setInternallyAligned(true);

					assertEquals(8, union.getComponent(0).getLength());
					assertEquals(2, union.getComponent(1).getLength());
					assertEquals(4, union.getComponent(2).getLength());
					assertEquals(96, union.getComponent(3).getLength());
					assertEquals(4, union.getComponent(4).getLength());
					assertEquals(96, union.getLength());
					assertEquals(4, union.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					union.setToMachineAlignment();

					assertEquals(8, union.getComponent(0).getLength());
					assertEquals(2, union.getComponent(1).getLength());
					assertEquals(4, union.getComponent(2).getLength());
					assertEquals(96, union.getComponent(3).getLength());
					assertEquals(4, union.getComponent(4).getLength());
					assertEquals(96, union.getLength());
					assertEquals(8, union.getAlignment());
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
					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					union.setMinimumAlignment(4);

					assertEquals(8, union.getComponent(0).getLength());
					assertEquals(2, union.getComponent(1).getLength());
					assertEquals(4, union.getComponent(2).getLength());
					assertEquals(96, union.getComponent(3).getLength());
					assertEquals(4, union.getComponent(4).getLength());
					assertEquals(96, union.getLength());
					assertEquals(4, union.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testUnionMachineAlignedVsValuePickLatest() throws Exception {

		setupUnionMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertEquals(true, union.isInternallyAligned());
		assertEquals(false, union.isDefaultAligned());
		assertEquals(true, union.isMachineAligned());
		assertEquals(8, union.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, union.getPackingValue());
		assertEquals(8, union.getComponent(0).getLength());
		assertEquals(2, union.getComponent(1).getLength());
		assertEquals(4, union.getComponent(2).getLength());
		assertEquals(96, union.getComponent(3).getLength());
		assertEquals(4, union.getComponent(4).getLength());
		assertEquals(96, union.getLength());
		assertEquals(8, union.getAlignment());
	}

	@Test
	public void testUnionMachineAlignedVsValuePickMy() throws Exception {

		setupUnionMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertEquals(true, union.isInternallyAligned());
		assertEquals(false, union.isDefaultAligned());
		assertEquals(false, union.isMachineAligned());
		assertEquals(4, union.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, union.getPackingValue());
		assertEquals(8, union.getComponent(0).getLength());
		assertEquals(2, union.getComponent(1).getLength());
		assertEquals(4, union.getComponent(2).getLength());
		assertEquals(96, union.getComponent(3).getLength());
		assertEquals(4, union.getComponent(4).getLength());
		assertEquals(96, union.getLength());
		assertEquals(4, union.getAlignment());
	}

	@Test
	public void testUnionMachineAlignedVsValuePickOriginal() throws Exception {

		setupUnionMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertEquals(true, union.isInternallyAligned());
		assertEquals(true, union.isDefaultAligned());
		assertEquals(false, union.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, union.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, union.getPackingValue());
		assertEquals(8, union.getComponent(0).getLength());
		assertEquals(2, union.getComponent(1).getLength());
		assertEquals(4, union.getComponent(2).getLength());
		assertEquals(96, union.getComponent(3).getLength());
		assertEquals(4, union.getComponent(4).getLength());
		assertEquals(96, union.getLength());
		assertEquals(4, union.getAlignment());
	}

	public void setupUnionPack1VsPack2() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.OriginalProgramModifierListener#modifyOriginal(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					assertEquals(96, union.getLength());
					assertEquals(1, union.getAlignment());
					union.setInternallyAligned(true);

					assertEquals(8, union.getComponent(0).getLength());
					assertEquals(2, union.getComponent(1).getLength());
					assertEquals(4, union.getComponent(2).getLength());
					assertEquals(96, union.getComponent(3).getLength());
					assertEquals(4, union.getComponent(4).getLength());
					assertEquals(96, union.getLength());
					assertEquals(4, union.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					union.setPackingValue(1);

					assertEquals(8, union.getComponent(0).getLength());
					assertEquals(2, union.getComponent(1).getLength());
					assertEquals(4, union.getComponent(2).getLength());
					assertEquals(96, union.getComponent(3).getLength());
					assertEquals(4, union.getComponent(4).getLength());
					assertEquals(96, union.getLength());
					assertEquals(1, union.getAlignment());
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
					Union union = (Union) dtm.getDataType(new CategoryPath("/Category1/Category2"),
						"CoolUnion");
					union.setPackingValue(2);

					assertEquals(8, union.getComponent(0).getLength());
					assertEquals(2, union.getComponent(1).getLength());
					assertEquals(4, union.getComponent(2).getLength());
					assertEquals(96, union.getComponent(3).getLength());
					assertEquals(4, union.getComponent(4).getLength());
					assertEquals(96, union.getLength());
					assertEquals(2, union.getAlignment());
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
	public void testUnionPack1VsPack2PickLatest() throws Exception {

		setupUnionPack1VsPack2();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertEquals(true, union.isInternallyAligned());
		assertEquals(true, union.isDefaultAligned());
		assertEquals(false, union.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, union.getMinimumAlignment());
		assertEquals(1, union.getPackingValue());
		assertEquals(8, union.getComponent(0).getLength());
		assertEquals(2, union.getComponent(1).getLength());
		assertEquals(4, union.getComponent(2).getLength());
		assertEquals(96, union.getComponent(3).getLength());
		assertEquals(4, union.getComponent(4).getLength());
		assertEquals(96, union.getLength());
		assertEquals(1, union.getAlignment());
	}

	@Test
	public void testUnionPack1VsPack2PickMy() throws Exception {

		setupUnionPack1VsPack2();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertEquals(true, union.isInternallyAligned());
		assertEquals(true, union.isDefaultAligned());
		assertEquals(false, union.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, union.getMinimumAlignment());
		assertEquals(2, union.getPackingValue());
		assertEquals(8, union.getComponent(0).getLength());
		assertEquals(2, union.getComponent(1).getLength());
		assertEquals(4, union.getComponent(2).getLength());
		assertEquals(96, union.getComponent(3).getLength());
		assertEquals(4, union.getComponent(4).getLength());
		assertEquals(96, union.getLength());
		assertEquals(2, union.getAlignment());
	}

	@Test
	public void testUnionPack1VsPack2PickOriginal() throws Exception {

		setupUnionMachineAlignedVsValue();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_ORIGINAL);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Category c = dtm.getCategory(new CategoryPath("/Category1/Category2"));
		Union union = (Union) c.getDataType("CoolUnion");
		assertEquals(true, union.isInternallyAligned());
		assertEquals(true, union.isDefaultAligned());
		assertEquals(false, union.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, union.getMinimumAlignment());
		assertEquals(Composite.NOT_PACKING, union.getPackingValue());
		assertEquals(8, union.getComponent(0).getLength());
		assertEquals(2, union.getComponent(1).getLength());
		assertEquals(4, union.getComponent(2).getLength());
		assertEquals(96, union.getComponent(3).getLength());
		assertEquals(4, union.getComponent(4).getLength());
		assertEquals(96, union.getLength());
		assertEquals(4, union.getAlignment());
	}

	@Test
	public void testStructureAddSameNameDiffCompsPickMy() throws Exception {

		final StructureDataType struct1 =
			new StructureDataType(new CategoryPath("/Category1"), "ABCStructure", 0);
		struct1.add(new PointerDataType(new FloatDataType()));
		struct1.add(new FloatDataType());

		final StructureDataType struct2 =
			new StructureDataType(new CategoryPath("/Category1"), "ABCStructure", 0);
		struct2.add(new CharDataType());
		struct2.add(new StringDataType(), 4);

		mtf.initialize("notepad", new ProgramModifierListener() {
			/* (non-Javadoc)
			 * @see ghidra.framework.data.ProgramModifierListener#modifyLatest(ghidra.program.database.ProgramDB)
			 */
			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				try {
					dtm.addDataType(struct1, null);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1"), "ABCStructure");
				assertEquals(8, s.getLength());
				assertEquals(1, s.getAlignment());
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(4, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(0).getLength());
				assertEquals(4, s.getComponent(1).getLength());
				assertTrue(new PointerDataType(new FloatDataType()).isEquivalent(
					s.getComponent(0).getDataType()));
				assertTrue(new FloatDataType().isEquivalent(s.getComponent(1).getDataType()));
				assertEquals(Composite.NOT_PACKING, s.getPackingValue());
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
					dtm.addDataType(struct2, null);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1"), "ABCStructure");
				assertEquals(5, s.getLength());
				assertEquals(1, s.getAlignment());
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(1, s.getComponent(1).getOffset());
				assertEquals(1, s.getComponent(0).getLength());
				assertEquals(4, s.getComponent(1).getLength());
				assertTrue(new CharDataType().isEquivalent(s.getComponent(0).getDataType()));
				assertTrue(new StringDataType().isEquivalent(s.getComponent(1).getDataType()));
				assertEquals(Composite.NOT_PACKING, s.getPackingValue());
			}
		});

		executeMerge();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		Structure s1 = (Structure) dtm.getDataType(new CategoryPath("/Category1"), "ABCStructure");
		assertNotNull(s1);
		assertEquals(8, s1.getLength());
		assertEquals(1, s1.getAlignment());
		assertEquals(0, s1.getComponent(0).getOffset());
		assertEquals(4, s1.getComponent(1).getOffset());
		assertEquals(4, s1.getComponent(0).getLength());
		assertEquals(4, s1.getComponent(1).getLength());
		assertTrue(new PointerDataType(new FloatDataType()).isEquivalent(
			s1.getComponent(0).getDataType()));
		assertTrue(new FloatDataType().isEquivalent(s1.getComponent(1).getDataType()));
		assertEquals(Composite.NOT_PACKING, s1.getPackingValue());

		Structure s2 =
			(Structure) dtm.getDataType(new CategoryPath("/Category1"), "ABCStructure.conflict");
		assertNotNull(s2);
		assertEquals(5, s2.getLength());
		assertEquals(1, s2.getAlignment());
		assertEquals(0, s2.getComponent(0).getOffset());
		assertEquals(1, s2.getComponent(1).getOffset());
		assertEquals(1, s2.getComponent(0).getLength());
		assertEquals(4, s2.getComponent(1).getLength());
		assertTrue(new CharDataType().isEquivalent(s2.getComponent(0).getDataType()));
		assertTrue(new StringDataType().isEquivalent(s2.getComponent(1).getDataType()));
		assertEquals(Composite.NOT_PACKING, s2.getPackingValue());
	}
}
