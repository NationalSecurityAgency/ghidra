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

import ghidra.program.database.OriginalProgramModifierListener;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Data type merge tests with fixup for data types added in My program.
 */
public class DataTypeMergeFixupTest extends AbstractDataTypeMergeTest {

	private void setupRemoveInnerVsAddOuterContainingChangedInner() throws Exception {

		final CategoryPath rootPath = new CategoryPath("/");

		/*
		 * 	Original  (Create inner structure)
		 * 		inner
		 * 			byte
		 * 			word
		 * 
		 * 	Latest  (Remove inner)
		 * 
		 * 	My  (Create outer containing inner as last component. Change inner)
		 * 		outer
		 * 			byte
		 * 			inner
		 * 				ascii
		 * 				word
		 */

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				Structure inner = new StructureDataType("inner", 0);
				inner.add(new ByteDataType());
				inner.add(new WordDataType());
				inner.setPackingEnabled(true);

				try {
					Category rootCategory = dtm.getCategory(rootPath);
					rootCategory.addDataType(inner, null);

					inner = (Structure) dtm.getDataType(rootPath, "inner");
					assertNotNull(inner);

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
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				int transactionID = program.startTransaction("delete inner struct");
				try {
					// Remove inner struct
					dtm.remove(inner, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {

				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				Structure outer = new StructureDataType("outer", 0);
				outer.add(new ByteDataType());
				outer.add(inner);
				outer.setPackingEnabled(true);

				int transactionID = program.startTransaction("create outer struct, modify inner");
				try {
					// Add outer struct
					dtm.addDataType(outer, DataTypeConflictHandler.DEFAULT_HANDLER);
					// Modify inner struct
					inner.replace(0, new CharDataType(), 1);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});
	}

	@Test
    public void testRemoveInnerAddOuterChangeInnerPickLatest() throws Exception {

		final CategoryPath rootPath = new CategoryPath("/");

		setupRemoveInnerVsAddOuterContainingChangedInner();

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNull(inner);
		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		assertEquals(true, outer.isPackingEnabled());
		assertEquals(true, outer.isDefaultAligned());
		assertEquals(CompositeInternal.DEFAULT_ALIGNMENT, outer.getStoredMinimumAlignment());
		assertEquals(CompositeInternal.DEFAULT_PACKING, outer.getStoredPackingValue());
		assertEquals(1, outer.getNumComponents());
		assertTrue(new ByteDataType().isEquivalent(outer.getComponent(0).getDataType()));
		assertEquals(1, outer.getLength());
		assertEquals(1, outer.getAlignment());
	}

	@Test
    public void testRemoveInnerAddOuterChangeInnerPickMy() throws Exception {

		final CategoryPath rootPath = new CategoryPath("/");

		setupRemoveInnerVsAddOuterContainingChangedInner();

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNotNull(inner);
		assertEquals(true, inner.isPackingEnabled());
		assertEquals(true, inner.isDefaultAligned());
		assertEquals(CompositeInternal.DEFAULT_ALIGNMENT, inner.getStoredMinimumAlignment());
		assertEquals(CompositeInternal.DEFAULT_PACKING, inner.getStoredPackingValue());
		assertEquals(2, inner.getNumComponents());
		assertTrue(new CharDataType().isEquivalent(inner.getComponent(0).getDataType()));
		assertTrue(new WordDataType().isEquivalent(inner.getComponent(1).getDataType()));
		assertEquals(4, inner.getLength());
		assertEquals(2, inner.getAlignment());

		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		assertEquals(true, outer.isPackingEnabled());
		assertEquals(true, outer.isDefaultAligned());
		assertEquals(CompositeInternal.DEFAULT_ALIGNMENT, outer.getStoredMinimumAlignment());
		assertEquals(CompositeInternal.DEFAULT_PACKING, outer.getStoredPackingValue());
		assertEquals(2, outer.getNumComponents());
		assertTrue(new ByteDataType().isEquivalent(outer.getComponent(0).getDataType()));
		assertEquals(inner, outer.getComponent(1).getDataType());
		assertEquals(4, outer.getComponent(1).getLength());
		assertEquals(6, outer.getLength());
		assertEquals(2, outer.getAlignment());
	}

	@Test
    public void testRemoveInnerVsAddOuterContainingInner() throws Exception {

		final CategoryPath rootPath = new CategoryPath("/");

		/*
		 * 	Original  (Create inner structure)
		 * 		inner
		 * 			byte
		 * 			word
		 * 
		 * 	Latest  (Remove inner)
		 * 
		 * 	My  (Create outer containing inner as last component. Don't change inner)
		 * 		outer
		 * 			byte
		 * 			inner
		 * 				byte
		 * 				word
		 */

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				Structure inner = new StructureDataType("inner", 0);
				inner.add(new ByteDataType());
				inner.add(new WordDataType());
				inner.setPackingEnabled(true);

				try {
					Category rootCategory = dtm.getCategory(rootPath);
					rootCategory.addDataType(inner, null);

					inner = (Structure) dtm.getDataType(rootPath, "inner");
					assertNotNull(inner);

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
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				int transactionID = program.startTransaction("delete inner struct");
				try {
					// Remove inner struct
					dtm.remove(inner, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {

				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				Structure outer = new StructureDataType("outer", 0);
				outer.add(new ByteDataType());
				outer.add(inner);
				outer.setPackingEnabled(true);

				int transactionID =
					program.startTransaction("create outer struct, don't modify inner");
				try {
					// Add outer struct
					dtm.addDataType(outer, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNull(inner);
		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		assertEquals(true, outer.isPackingEnabled());
		assertEquals(true, outer.isDefaultAligned());
		assertEquals(CompositeInternal.DEFAULT_ALIGNMENT, outer.getStoredMinimumAlignment());
		assertEquals(CompositeInternal.DEFAULT_PACKING, outer.getStoredPackingValue());
		assertEquals(1, outer.getNumComponents());
		assertTrue(new ByteDataType().isEquivalent(outer.getComponent(0).getDataType()));
		assertEquals(1, outer.getLength());
		assertEquals(1, outer.getAlignment());
	}

	@Test
    public void testRemoveInnerVsAddOuterWithOtherAfterInner() throws Exception {

		final CategoryPath rootPath = new CategoryPath("/");

		/*
		 * 	Original  (Create inner structure)
		 * 		inner
		 * 			byte
		 * 			word
		 * 
		 * 	Latest  (Remove inner)
		 * 
		 * 	My  (Create outer containing inner as 2nd component. Change inner.
		 * 	     Add new structure other so it comes later in struct than inner.)
		 * 		outer
		 * 			byte
		 * 			inner
		 * 				byte
		 * 				word
		 * 			float
		 * 			other
		 * 				byte
		 * 				void *
		 * 			byte
		 */

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				int transactionID = program.startTransaction("test");

				Structure inner = new StructureDataType("inner", 0);
				inner.add(new ByteDataType());
				inner.add(new WordDataType());
				inner.setPackingEnabled(true);

				try {
					Category rootCategory = dtm.getCategory(rootPath);
					rootCategory.addDataType(inner, null);

					inner = (Structure) dtm.getDataType(rootPath, "inner");
					assertNotNull(inner);

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
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				int transactionID = program.startTransaction("delete inner struct");
				try {
					// Remove inner struct
					dtm.remove(inner, TaskMonitorAdapter.DUMMY_MONITOR);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {

				boolean commit = false;
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				Structure other = new StructureDataType("other", 0);
				other.add(new ByteDataType());
				other.add(new PointerDataType(new VoidDataType()));
				other.setPackingEnabled(true);

				Structure outer = new StructureDataType("outer", 0);
				outer.add(new ByteDataType());
				outer.add(inner);
				outer.add(new FloatDataType());
				outer.add(other);
				outer.add(new ByteDataType());
				outer.setPackingEnabled(true);

				int transactionID = program.startTransaction(
					"create outer struct with other structure after inner");
				try {
					// Add outer struct
					dtm.addDataType(outer, DataTypeConflictHandler.DEFAULT_HANDLER);
					commit = true;
				}
				finally {
					program.endTransaction(transactionID, commit);
				}
			}
		});

		executeMerge();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNull(inner);

		StructureInternal other = (StructureInternal) dtm.getDataType(rootPath, "other");
		assertNotNull(other);
		assertEquals(true, other.isPackingEnabled());
		assertEquals(true, other.isDefaultAligned());
		assertEquals(CompositeInternal.DEFAULT_ALIGNMENT, other.getStoredMinimumAlignment());
		assertEquals(CompositeInternal.DEFAULT_PACKING, other.getStoredPackingValue());
		assertEquals(2, other.getNumComponents());
		assertTrue(new ByteDataType().isEquivalent(other.getComponent(0).getDataType()));
		assertTrue(new PointerDataType(new VoidDataType()).isEquivalent(
			other.getComponent(1).getDataType()));
		assertEquals(8, other.getLength());
		assertEquals(4, other.getAlignment());

		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		assertEquals(true, outer.isPackingEnabled());
		assertEquals(true, outer.isDefaultAligned());
		assertEquals(CompositeInternal.DEFAULT_ALIGNMENT, outer.getStoredMinimumAlignment());
		assertEquals(CompositeInternal.DEFAULT_PACKING, outer.getStoredPackingValue());
		assertEquals(4, outer.getNumComponents());
		assertTrue(new ByteDataType().isEquivalent(outer.getComponent(0).getDataType()));
		assertTrue(new FloatDataType().isEquivalent(outer.getComponent(1).getDataType()));
		assertEquals(other, outer.getComponent(2).getDataType());
		assertTrue(new ByteDataType().isEquivalent(outer.getComponent(3).getDataType()));
		assertEquals(4, outer.getComponent(1).getLength());
		assertEquals(20, outer.getLength());
		assertEquals(4, outer.getAlignment());
	}

}
