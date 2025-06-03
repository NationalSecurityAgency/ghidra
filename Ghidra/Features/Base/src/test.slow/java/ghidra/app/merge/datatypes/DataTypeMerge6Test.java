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

/**
 * Data type merge tests for aligned data types.
 */
public class DataTypeMerge6Test extends AbstractDataTypeMergeTest {

	private void setupStructureMachineAlignedVsValue() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.setToDefaultPacking();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.setToMachineAligned();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(8, s.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.setExplicitMinimumAlignment(4);

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
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
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.isMachineAligned());

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
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.hasExplicitMinimumAlignment());
		assertEquals(4, s.getExplicitMinimumAlignment());

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
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.isDefaultAligned());

		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	private void setupStructurePack1VsPack2() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.setToDefaultPacking();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.pack(1);

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(1, s.getComponent(1).getOffset());
				assertEquals(3, s.getComponent(2).getOffset());
				assertEquals(7, s.getComponent(3).getOffset());
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.pack(2);

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(2, s.getAlignment());
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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasExplicitPackingValue());
		assertEquals(1, s.getExplicitPackingValue());
		assertTrue(s.isDefaultAligned());

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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasExplicitPackingValue());
		assertEquals(2, s.getExplicitPackingValue());
		assertTrue(s.isDefaultAligned());

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
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.isDefaultAligned());

		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	private void setupStructureMinAlignVsPack() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.setToDefaultPacking();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.setToMachineAligned();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(8, s.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.pack(1);

				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(1, s.getComponent(1).getOffset());
				assertEquals(3, s.getComponent(2).getOffset());
				assertEquals(7, s.getComponent(3).getOffset());
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.isMachineAligned());

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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasExplicitPackingValue());
		assertEquals(1, s.getExplicitPackingValue());
		assertTrue(s.isDefaultAligned());

		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	private void setupStructureAddVsAlign() throws Exception {

		mtf.initialize("notepad", new ProgramModifierListener() {

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.add(new IntegerDataType());

				// Offsets change to 0,2,4,8.
				assertFalse(s.isPackingEnabled());
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(1, s.getComponent(1).getOffset());
				assertEquals(3, s.getComponent(2).getOffset());
				assertEquals(7, s.getComponent(3).getOffset());
				assertEquals(15, s.getComponent(4).getOffset());
				assertEquals(19, s.getLength());
				assertEquals(1, s.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.setToDefaultPacking();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertFalse(s.isPackingEnabled());
		assertTrue(s.isDefaultAligned());

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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.isDefaultAligned());

		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(2, s.getComponent(1).getOffset());
		assertEquals(4, s.getComponent(2).getOffset());
		assertEquals(8, s.getComponent(3).getOffset());
		assertEquals(16, s.getLength());
		assertEquals(4, s.getAlignment());
	}

	private void setupStructureFieldNameVsPack() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.setToDefaultPacking();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
				s.getComponent(1).setFieldName("MyComponentOne");

				assertTrue(s.hasDefaultPacking());
				assertTrue(s.isDefaultAligned());

				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals("MyComponentOne", s.getComponent(1).getFieldName());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
				s.pack(1);

				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(1, s.getComponent(1).getOffset());
				assertEquals(3, s.getComponent(2).getOffset());
				assertEquals(7, s.getComponent(3).getOffset());
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasDefaultPacking());
		assertTrue(s.isDefaultAligned());

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
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasExplicitPackingValue());
		assertEquals(1, s.getExplicitPackingValue());
		assertTrue(s.isDefaultAligned());

		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	private void setupStructureRemoveVsPack() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
				s.setToDefaultPacking();

				// Offsets change to 0,2,4,8.
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(2, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(2).getOffset());
				assertEquals(8, s.getComponent(3).getOffset());
				assertEquals(16, s.getLength());
				assertEquals(4, s.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				dtm.remove(s);

				// Offsets change to 0,2,4,8.
				Structure intStruct =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertNull(intStruct);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.pack(1);

				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(1, s.getComponent(1).getOffset());
				assertEquals(3, s.getComponent(2).getOffset());
				assertEquals(7, s.getComponent(3).getOffset());
				assertEquals(15, s.getLength());
				assertEquals(1, s.getAlignment());
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
		Structure intStruct = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertNull(intStruct);
	}

	@Test
	public void testStructureRemoveVsPackPickMy() throws Exception {

		setupStructureRemoveVsPack();
		executeMerge();

		chooseOption(DataTypeMergeManager.OPTION_MY);

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure s = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertTrue(s.hasExplicitPackingValue());
		assertEquals(1, s.getExplicitPackingValue());
		assertTrue(s.isDefaultAligned());

		assertEquals(0, s.getComponent(0).getOffset());
		assertEquals(1, s.getComponent(1).getOffset());
		assertEquals(3, s.getComponent(2).getOffset());
		assertEquals(7, s.getComponent(3).getOffset());
		assertEquals(15, s.getLength());
		assertEquals(1, s.getAlignment());
	}

	private void setupStructureInUnionAndViceVersa() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				s.setPackingEnabled(true);

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				union.setPackingEnabled(true);
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure structure =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(16, structure.getLength());
				assertEquals(4, structure.getAlignment());

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				assertEquals(96, union.getLength());
				assertEquals(4, union.getAlignment());

				structure.add(union);
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Structure structure =
					(Structure) dtm.getDataType(new CategoryPath("/Category1/Category2/Category3"),
						"IntStruct");
				assertEquals(16, structure.getLength());
				assertEquals(4, structure.getAlignment());

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				assertEquals(96, union.getLength());
				assertEquals(4, union.getAlignment());

				union.add(structure);
			}
		});
	}

	@Test
	public void testStructureInUnionAndViceVersa() throws Exception {

		setupStructureInUnionAndViceVersa();
		executeMerge();

		pressButtonByName(waitForWindow("Union Update Failed"), "OK"); // expected dependency error on CoolUnion

		waitForCompletion();

		DataTypeManager dtm = resultProgram.getDataTypeManager();
		Structure intStruct = (Structure) dtm
				.getDataType(new CategoryPath("/Category1/Category2/Category3"), "IntStruct");
		assertNotNull(intStruct);
		//@formatter:off
		assertEquals("/Category1/Category2/Category3/IntStruct\n" + 
			"pack()\n" + 
			"Structure IntStruct {\n" + 
			"   0   byte   1   field0   \"\"\n" + 
			"   2   word   2      \"\"\n" + 
			"   4   dword   4      \"\"\n" + 
			"   8   qword   8      \"\"\n" + 
			"   16   CoolUnion   112      \"\"\n" + 
			"}\n" + 
			"Length: 128 Alignment: 4\n", intStruct.toString());
		//@formatter:on

		Union coolUnion =
			(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
		assertNotNull(coolUnion);
		//@formatter:off
		assertEquals("/Category1/Category2/CoolUnion\n" + 
			"pack()\n" + 
			"Union CoolUnion {\n" + 
			"   0   qword   8      \"\"\n" + 
			"   0   word   2      \"\"\n" + 
			"   0   undefined * * * * *   4      \"\"\n" + 
			"   0   DLL_Table   96      \"\"\n" + 
			"   0   DLL_Table *32   4      \"\"\n" + 
			"   0   -BAD-   112      \"Failed to apply 'IntStruct', Data type IntStruct has CoolUnion within it.\"\n" + 
			"}\n" + 
			"Length: 112 Alignment: 4\n", coolUnion.toString());
		//@formatter:on

	}

	/////////////////////////////////////////////////

	public void setupUnionMachineAlignedVsValue() throws Exception {

		mtf.initialize("notepad", new OriginalProgramModifierListener() {

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				assertEquals(96, union.getLength());
				assertEquals(1, union.getAlignment());
				union.setPackingEnabled(true);

				assertEquals(8, union.getComponent(0).getLength());
				assertEquals(2, union.getComponent(1).getLength());
				assertEquals(4, union.getComponent(2).getLength());
				assertEquals(96, union.getComponent(3).getLength());
				assertEquals(4, union.getComponent(4).getLength());
				assertEquals(96, union.getLength());
				assertEquals(4, union.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				union.setToMachineAligned();

				assertEquals(8, union.getComponent(0).getLength());
				assertEquals(2, union.getComponent(1).getLength());
				assertEquals(4, union.getComponent(2).getLength());
				assertEquals(96, union.getComponent(3).getLength());
				assertEquals(4, union.getComponent(4).getLength());
				assertEquals(96, union.getLength());
				assertEquals(8, union.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				union.setExplicitMinimumAlignment(4);

				assertEquals(8, union.getComponent(0).getLength());
				assertEquals(2, union.getComponent(1).getLength());
				assertEquals(4, union.getComponent(2).getLength());
				assertEquals(96, union.getComponent(3).getLength());
				assertEquals(4, union.getComponent(4).getLength());
				assertEquals(96, union.getLength());
				assertEquals(4, union.getAlignment());
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
		assertTrue(union.hasDefaultPacking());
		assertTrue(union.isMachineAligned());

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
		assertTrue(union.hasDefaultPacking());
		assertTrue(union.hasExplicitMinimumAlignment());
		assertEquals(4, union.getExplicitMinimumAlignment());

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
		assertTrue(union.hasDefaultPacking());
		assertTrue(union.isDefaultAligned());

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

			@Override
			public void modifyOriginal(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				assertEquals(96, union.getLength());
				assertEquals(1, union.getAlignment());
				union.setPackingEnabled(true);

				assertEquals(8, union.getComponent(0).getLength());
				assertEquals(2, union.getComponent(1).getLength());
				assertEquals(4, union.getComponent(2).getLength());
				assertEquals(96, union.getComponent(3).getLength());
				assertEquals(4, union.getComponent(4).getLength());
				assertEquals(96, union.getLength());
				assertEquals(4, union.getAlignment());
			}

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				union.pack(1);

				assertEquals(8, union.getComponent(0).getLength());
				assertEquals(2, union.getComponent(1).getLength());
				assertEquals(4, union.getComponent(2).getLength());
				assertEquals(96, union.getComponent(3).getLength());
				assertEquals(4, union.getComponent(4).getLength());
				assertEquals(96, union.getLength());
				assertEquals(1, union.getAlignment());
			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();

				Union union =
					(Union) dtm.getDataType(new CategoryPath("/Category1/Category2"), "CoolUnion");
				union.pack(2);

				assertEquals(8, union.getComponent(0).getLength());
				assertEquals(2, union.getComponent(1).getLength());
				assertEquals(4, union.getComponent(2).getLength());
				assertEquals(96, union.getComponent(3).getLength());
				assertEquals(4, union.getComponent(4).getLength());
				assertEquals(96, union.getLength());
				assertEquals(2, union.getAlignment());
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
		assertTrue(union.hasExplicitPackingValue());
		assertEquals(1, union.getExplicitPackingValue());
		assertTrue(union.isDefaultAligned());

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
		assertTrue(union.hasExplicitPackingValue());
		assertEquals(2, union.getExplicitPackingValue());
		assertTrue(union.isDefaultAligned());

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
		assertTrue(union.hasDefaultPacking());
		assertTrue(union.isDefaultAligned());

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

			@Override
			public void modifyLatest(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				dtm.addDataType(struct1, null);

				Structure s =
					(Structure) dtm.getDataType(new CategoryPath("/Category1"), "ABCStructure");
				assertEquals(8, s.getLength());
				assertEquals(1, s.getAlignment());
				assertEquals(0, s.getComponent(0).getOffset());
				assertEquals(4, s.getComponent(1).getOffset());
				assertEquals(4, s.getComponent(0).getLength());
				assertEquals(4, s.getComponent(1).getLength());
				assertTrue(new PointerDataType(new FloatDataType())
						.isEquivalent(s.getComponent(0).getDataType()));
				assertTrue(new FloatDataType().isEquivalent(s.getComponent(1).getDataType()));

			}

			@Override
			public void modifyPrivate(ProgramDB program) throws Exception {
				DataTypeManager dtm = program.getDataTypeManager();
				dtm.addDataType(struct2, null);

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
		assertTrue(new PointerDataType(new FloatDataType())
				.isEquivalent(s1.getComponent(0).getDataType()));
		assertTrue(new FloatDataType().isEquivalent(s1.getComponent(1).getDataType()));

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
	}
}
