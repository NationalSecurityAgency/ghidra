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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import javax.swing.*;

import org.junit.Test;

import docking.widgets.OptionDialog;
import ghidra.program.database.DatabaseObject;
import ghidra.program.database.data.StructureDBTest;
import ghidra.program.model.data.*;

public class StructureEditorFlexAlignmentTest extends AbstractStructureEditorTest {

	// NOTE: The trailing flexable array may be assigned an incorrect offset
	// when packing is enabled and the minimum alignment is specified.  In such cases, 
	// the flex array may be less than the overall structure length.  Currently, it is
	// assumed the trailing flex array will have an offset equal to the overall
	// structure length.

	@Test
	public void testUnalignedStructure() {
		init(emptyStructure, pgmRootCat, false);

		assertTrue(structureModel.hasChanges());// initial unsaved empty structure
		assertTrue(structureModel.isValidName());// name should be valid
		assertEquals(structureModel.getTypeName(), "Structure");
		assertEquals(emptyStructure.getName(), structureModel.getCompositeName());
		assertEquals(emptyStructure.getDescription(), structureModel.getDescription());
		assertEquals(pgmRootCat.getCategoryPathName(),
			structureModel.getOriginalCategoryPath().getPath());
		assertEquals(0, structureModel.getNumComponents());// no components
		assertEquals(1, structureModel.getRowCount());// blank row
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertLength(0);
		assertActualAlignment(1);
		assertEquals(0, structureModel.getNumSelectedComponentRows());
		assertEquals(1, structureModel.getNumSelectedRows());
		checkSelection(new int[] { 0 });

		addDataType(ByteDataType.dataType);
		addDataType(FloatDataType.dataType);
		addFlexDataType((Structure) structureModel.viewComposite, DWordDataType.dataType, null,
			null);

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 4, "float", FloatDataType.dataType, "", "");
		checkFlexArrayRow(2, 5, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(5);
		assertActualAlignment(1);
	}

	@Test
	public void testDefaultAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType((Structure) structureModel.viewComposite, DWordDataType.dataType, null,
			null);

		waitForSwing();

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkFlexArrayRow(2, 2, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(2);
		assertActualAlignment(1);

		turnOnPacking();
		assertIsPackingEnabled(true);
		assertDefaultPacked();

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkFlexArrayRow(2, 4, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(4);
		assertActualAlignment(4);
	}

	@Test
	public void testMachineAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType((Structure) structureModel.viewComposite, DWordDataType.dataType, null,
			null);

		waitForSwing();

		turnOnPacking();
		assertIsPackingEnabled(true);
		assertDefaultPacked();

		pressButtonByName(getPanel(), "Machine Alignment");
		assertIsMachineAligned();

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		// It is important to note that a trailing flex array will align the same as any other component and
		// is not guaranteed to fall at the end of the structure.
		checkFlexArrayRow(2, 4, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(8);
		assertActualAlignment(8);
	}

	@Test
	public void testByValueAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType((Structure) structureModel.viewComposite, DWordDataType.dataType, null,
			null);

		waitForSwing();

		turnOnPacking();
		assertIsPackingEnabled(true);
		assertDefaultPacked();

		JTextField minAlignField =
			(JTextField) getInstanceField("explicitAlignTextField", editorPanel);
		assertNotNull(minAlignField);
		JRadioButton explicitAlignButton =
			(JRadioButton) getInstanceField("explicitAlignButton", editorPanel);
		assertNotNull(explicitAlignButton);
		pressButton(explicitAlignButton);
		assertEquals("8", minAlignField.getText()); // toy.cspec machine alignment is default value

		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(8, structureModel.getExplicitMinimumAlignment());

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkFlexArrayRow(2, 4, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(8);
		assertActualAlignment(8);
	}

	@Test
	public void testByValue1AlignedStructure() throws Exception {
		checkByValueAlignedStructure(1, 4, 4, 4);
	}

	@Test
	public void testByValue2AlignedStructure() throws Exception {
		checkByValueAlignedStructure(2, 4, 4, 4);
	}

	@Test
	public void testByValue4AlignedStructure() throws Exception {
		checkByValueAlignedStructure(4, 4, 4, 4);
	}

	@Test
	public void testByValue8AlignedStructure() throws Exception {
		checkByValueAlignedStructure(8, 8, 8, 4);
	}

	@Test
	public void testByValue16AlignedStructure() throws Exception {
		checkByValueAlignedStructure(16, 16, 16, 4);
	}

	public void checkByValueAlignedStructure(int value, int alignment, int length, int flexOffset)
			throws Exception {
		emptyStructure.setPackingEnabled(true);
		emptyStructure.setExplicitMinimumAlignment(value);

		emptyStructure.add(ByteDataType.dataType);
		emptyStructure.add(CharDataType.dataType);
		addFlexDataType(emptyStructure, DWordDataType.dataType, null, null);

		init(emptyStructure, pgmRootCat, false);
		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		JRadioButton explicitAlignButton =
			(JRadioButton) getInstanceField("explicitAlignButton", editorPanel);
		assertNotNull(explicitAlignButton);
		assertEquals(true, explicitAlignButton.isSelected());

		JTextField minAlignField =
			(JTextField) getInstanceField("explicitAlignTextField", editorPanel);
		assertNotNull(minAlignField);
		assertEquals("" + value, minAlignField.getText());

		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(value, structureModel.getExplicitMinimumAlignment());

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");

		checkFlexArrayRow(2, flexOffset, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(length);
		assertActualAlignment(alignment);
	}

	@Test
	public void testDefaultAlignedPacked1Structure() throws Exception {
		int value = 1;
		emptyStructure.setPackingEnabled(true);
		emptyStructure.setExplicitPackingValue(value);

		init(emptyStructure, pgmRootCat, false);
		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType((Structure) structureModel.viewComposite, DWordDataType.dataType, null,
			null);

		JRadioButton byValuePackingButton =
			(JRadioButton) findComponentByName(editorPanel, "Explicit Packing");
		assertNotNull(byValuePackingButton);
		JTextField packingValueField =
			(JTextField) findComponentByName(editorPanel, "Packing Value");
		assertNotNull(packingValueField);
		assertEquals(true, byValuePackingButton.isSelected());
		assertEquals(Integer.toString(value), packingValueField.getText());

		assertEquals(true, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(false, structureModel.viewComposite.hasExplicitMinimumAlignment());

		assertEquals(3, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkFlexArrayRow(2, 2, "ddw", DWordDataType.dataType, "", "");
		checkBlankRow(3);
		assertLength(2);
		assertActualAlignment(1);
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void checkFlexArrayRow(int rowIndex, int offset, String mnemonic, DataType dataType,
			String name, String comment) {
		ArrayDataType a = new ArrayDataType(dataType, 0, -1);
		checkRow(rowIndex, offset, 0, mnemonic + "[0]", a, name, comment);
	}

	private void checkRow(int rowIndex, int offset, int length, String mnemonic, DataType dataType,
			String name, String comment) {
		assertTrue(dataType.isEquivalent(structureModel.getComponent(rowIndex).getDataType()));
		assertEquals("" + offset,
			structureModel.getValueAt(rowIndex, structureModel.getOffsetColumn()));
		assertEquals("" + length,
			structureModel.getValueAt(rowIndex, structureModel.getLengthColumn()));
		assertEquals(mnemonic,
			structureModel.getValueAt(rowIndex, structureModel.getMnemonicColumn()));
		assertEquals(name, structureModel.getValueAt(rowIndex, structureModel.getNameColumn()));
		assertEquals(comment,
			structureModel.getValueAt(rowIndex, structureModel.getCommentColumn()));
	}

	private void checkBlankRow(int rowIndex) {
		assertNull(structureModel.getComponent(rowIndex));
		assertEquals("", structureModel.getValueAt(rowIndex, structureModel.getOffsetColumn()));
		assertEquals("", structureModel.getValueAt(rowIndex, structureModel.getLengthColumn()));
		assertEquals("", structureModel.getValueAt(rowIndex, structureModel.getMnemonicColumn()));
		assertEquals("", structureModel.getValueAt(rowIndex, structureModel.getNameColumn()));
		assertEquals("", structureModel.getValueAt(rowIndex, structureModel.getCommentColumn()));
	}

	private DataTypeComponent addDataType(DataType dataType) {
		return structureModel.viewDTM.withTransaction("Add Test Component",
			() -> structureModel.viewComposite.add(dataType));
	}

	private DataTypeComponent addFlexDataType(Structure struct, DataType dataType, String name,
			String comment) {
		ArrayDataType a = new ArrayDataType(dataType, 0, 1);
		if (struct instanceof DatabaseObject) {
			DataTypeManager dtm = struct.getDataTypeManager();
			return dtm.withTransaction("Add Flex Array", () -> struct.add(a, name, comment));
		}
		return struct.add(a, name, comment);
	}

	private void turnOnPacking() {
		AbstractButton packingButton = findButtonByName(getPanel(), "Packing Enablement");
		if (packingButton.isSelected()) {
			return;
		}
		pressButton(packingButton, true);
	}

}
