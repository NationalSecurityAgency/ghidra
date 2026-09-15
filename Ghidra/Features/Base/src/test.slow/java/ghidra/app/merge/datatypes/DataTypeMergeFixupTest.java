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
				DataTypeManager dtm = program.getDataTypeManager();

				Structure inner = new StructureDataType("inner", 0);
				inner.add(new ByteDataType());
				inner.add(new WordDataType());
				inner.setPackingEnabled(true);

				Category rootCategory = dtm.getCategory(rootPath);
				rootCategory.addDataType(inner, null);

				inner = (Structure) dtm.getDataType(rootPath, "inner");
				assertNotNull(inner);
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				// Remove inner struct
				dtm.remove(inner);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				Structure outer = new StructureDataType("outer", 0);
				outer.add(new ByteDataType());
				outer.add(inner);
				outer.setPackingEnabled(true);

				// Add outer struct
				dtm.addDataType(outer, DataTypeConflictHandler.DEFAULT_HANDLER);
				// Modify inner struct
				inner.replace(0, new CharDataType(), 1);
			}
		});
	}

	@Test
	public void testRemoveInnerAddOuterChangeInnerPickLatest() throws Exception {

		final CategoryPath rootPath = new CategoryPath("/");

		setupRemoveInnerVsAddOuterContainingChangedInner();

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_LATEST);

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNull(inner);

		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		//@formatter:off
		assertEquals("/outer\n" + 
			"pack()\n" + 
			"Structure outer {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   -BAD-   4      \"Failed to apply 'inner'\"\n" + 
			"}\n" + 
			"Length: 5 Alignment: 1\n", outer.toString());
		//@formatter:on
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
				DataTypeManager dtm = program.getDataTypeManager();

				Structure inner = new StructureDataType("inner", 0);
				inner.add(new ByteDataType());
				inner.add(new WordDataType());
				inner.setPackingEnabled(true);

				Category rootCategory = dtm.getCategory(rootPath);
				rootCategory.addDataType(inner, null);

				inner = (Structure) dtm.getDataType(rootPath, "inner");
				assertNotNull(inner);
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				// Remove inner struct
				dtm.remove(inner);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				Structure outer = new StructureDataType("outer", 0);
				outer.add(new ByteDataType());
				outer.add(inner);
				outer.setPackingEnabled(true);

				// Add outer struct
				dtm.addDataType(outer, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		});

		executeMerge();

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNull(inner);

		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		//@formatter:off
		assertEquals("/outer\n" + 
			"pack()\n" + 
			"Structure outer {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   -BAD-   4      \"Failed to apply 'inner'\"\n" + 
			"}\n" + 
			"Length: 5 Alignment: 1\n", outer.toString());
		//@formatter:on
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
				DataTypeManager dtm = program.getDataTypeManager();

				Structure inner = new StructureDataType("inner", 0);
				inner.add(new ByteDataType());
				inner.add(new WordDataType());
				inner.setPackingEnabled(true);

				Category rootCategory = dtm.getCategory(rootPath);
				rootCategory.addDataType(inner, null);

				inner = (Structure) dtm.getDataType(rootPath, "inner");
				assertNotNull(inner);
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure inner = (Structure) dtm.getDataType(rootPath, "inner");

				// Remove inner struct
				dtm.remove(inner);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
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

				// Add outer struct
				dtm.addDataType(outer, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		});

		executeMerge();

		dismissUnresolvedDataTypesPopup();

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		StructureInternal inner = (StructureInternal) dtm.getDataType(rootPath, "inner");
		assertNull(inner);

		StructureInternal other = (StructureInternal) dtm.getDataType(rootPath, "other");
		assertNotNull(other);
		//@formatter:off
		assertEquals("/other\n" + 
			"pack()\n" + 
			"Structure other {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   4   void *   4      \"\"\n" + 
			"}\n" + 
			"Length: 8 Alignment: 4\n", other.toString());
		//@formatter:on

		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);
		//@formatter:off
		assertEquals("/outer\n" + 
			"pack()\n" + 
			"Structure outer {\n" + 
			"   0   byte   1      \"\"\n" + 
			"   1   -BAD-   4      \"Failed to apply 'inner'\"\n" + 
			"   8   float   4      \"\"\n" + 
			"   12   other   8      \"\"\n" + 
			"   20   byte   1      \"\"\n" + 
			"}\n" + 
			"Length: 24 Alignment: 4\n", outer.toString());
		//@formatter:on
	}

	@Test
	public void testNonPackedZeroLengthComponentFixup() throws Exception {

		// Goal is to fixup zero-length component at end of structure where its ordinal will 
		// be revised during the merge processing

		final CategoryPath rootPath = new CategoryPath("/");

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union inner = new UnionDataType("inner");
				inner.add(DWordDataType.dataType);
				inner = (Union) dtm.addDataType(inner, null);

				Structure other = new StructureDataType("other", 0);
				other.add(WordDataType.dataType);
				other = (Structure) dtm.addDataType(other, null);

				Structure outer = new StructureDataType("outer", 20, dtm);
				outer.replaceAtOffset(0, other, -1, null, null); // prevent size change
				outer = (Structure) dtm.addDataType(outer, null);
				assertEquals(20, outer.getLength());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				// Increase size of other struct
				Structure other = (Structure) dtm.getDataType(rootPath, "other");
				other.add(DWordDataType.dataType);

				// remove inner to trigger conflict with its modification
				Union inner = (Union) dtm.getDataType(rootPath, "inner");
				dtm.remove(inner);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				Structure outer = (Structure) dtm.getDataType(rootPath, "outer");
				Union inner = (Union) dtm.getDataType(rootPath, "inner");

				// change inner to trigger conflict with its removal
				inner.add(WordDataType.dataType);

				// Add zero-length array at end of struct
				outer.insertAtOffset(20, new ArrayDataType(inner, 0), -1);
				assertEquals(20, outer.getLength());
			}
		});

		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY); // resolve inner conflict

		chooseOption(DataTypeMergeManager.OPTION_MY); // resolve outer conflict

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();

		StructureInternal outer = (StructureInternal) dtm.getDataType(rootPath, "outer");
		assertNotNull(outer);

		//@formatter:off
		assertEquals("/outer\n" + 
			"pack(disabled)\n" + 
			"Structure outer {\n" + 
			"   0   other   6      \"\"\n" + 
			"   20   inner[0]   0      \"\"\n" + 
			"}\n" + 
			"Length: 20 Alignment: 1\n", outer.toString());
		//@formatter:on

	}

}
