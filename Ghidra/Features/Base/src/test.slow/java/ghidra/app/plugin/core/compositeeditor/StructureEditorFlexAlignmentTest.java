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

import javax.swing.JRadioButton;
import javax.swing.JTextField;

import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite.AlignmentType;

public class StructureEditorFlexAlignmentTest extends AbstractStructureEditorTest {

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
		assertIsInternallyAligned(false);
		assertPackingValue(Composite.NOT_PACKING);
		assertMinimumAlignmentType(AlignmentType.DEFAULT_ALIGNED);
		assertMinimumAlignmentValue(Composite.DEFAULT_ALIGNMENT_VALUE);
		assertLength(0);
		assertActualAlignment(1);
		assertEquals(0, structureModel.getNumSelectedComponentRows());
		assertEquals(1, structureModel.getNumSelectedRows());
		checkSelection(new int[] { 0 });

		addDataType(ByteDataType.dataType);
		addDataType(FloatDataType.dataType);
		addFlexDataType(DWordDataType.dataType, null, null);

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 4, "float", FloatDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, 5, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(5);
		assertActualAlignment(1);
	}

	@Test
	public void testDefaultAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType(DWordDataType.dataType, null, null);

		waitForSwing();

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, 2, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(2);
		assertActualAlignment(1);

		pressButtonByName(getPanel(), "Internally Aligned");

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, 4, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(4);
		assertActualAlignment(4);
	}

	@Test
	public void testMachineAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType(DWordDataType.dataType, null, null);

		waitForSwing();

		pressButtonByName(getPanel(), "Internally Aligned");
		pressButtonByName(getPanel(), "Machine Minimum Alignment");

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, 8, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(8);
		assertActualAlignment(8);
	}

	@Test
	public void testByValueAlignedStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType(DWordDataType.dataType, null, null);

		waitForSwing();

		pressButtonByName(editorPanel, "Internally Aligned");
		JTextField minAlignField =
			(JTextField) getInstanceField("minAlignValueTextField", editorPanel);
		assertNotNull(minAlignField);
		JRadioButton byValueMinAlignButton =
			(JRadioButton) getInstanceField("byValueMinAlignButton", editorPanel);
		assertNotNull(byValueMinAlignButton);
		pressButton(byValueMinAlignButton);
		assertEquals("4", minAlignField.getText());

		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(4, structureModel.getMinimumAlignment());

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, 4, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(4);
		assertActualAlignment(4);
	}

	@Test
	public void testByValue1AlignedStructure() throws Exception {
		checkByValueAlignedStructure(1, 4, 4);
	}

	@Test
	public void testByValue2AlignedStructure() throws Exception {
		checkByValueAlignedStructure(2, 4, 4);
	}

	@Test
	public void testByValue4AlignedStructure() throws Exception {
		checkByValueAlignedStructure(4, 4, 4);
	}

	@Test
	public void testByValue8AlignedStructure() throws Exception {
		checkByValueAlignedStructure(8, 8, 8);
	}

	@Test
	public void testByValue16AlignedStructure() throws Exception {
		checkByValueAlignedStructure(16, 16, 16);
	}

	public void checkByValueAlignedStructure(int value, int alignment, int length)
			throws Exception {
		emptyStructure.setInternallyAligned(true);
		emptyStructure.setMinimumAlignment(value);

		emptyStructure.add(ByteDataType.dataType);
		emptyStructure.add(CharDataType.dataType);
		emptyStructure.setFlexibleArrayComponent(DWordDataType.dataType, null, null);

		init(emptyStructure, pgmRootCat, false);
		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		JRadioButton byValueMinAlignButton =
			(JRadioButton) getInstanceField("byValueMinAlignButton", editorPanel);
		assertNotNull(byValueMinAlignButton);
		assertEquals(true, byValueMinAlignButton.isSelected());

		JTextField minAlignField =
			(JTextField) getInstanceField("minAlignValueTextField", editorPanel);
		assertNotNull(minAlignField);
		assertEquals("" + value, minAlignField.getText());

		assertEquals(false, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(value, structureModel.getMinimumAlignment());

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, length, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(length);
		assertActualAlignment(alignment);
	}

	@Test
	public void testDefaultAlignedPacked1Structure() throws Exception {
		int value = 1;
		emptyStructure.setInternallyAligned(true);
		emptyStructure.setPackingValue(value);

		init(emptyStructure, pgmRootCat, false);
		CompEditorPanel editorPanel = (CompEditorPanel) getPanel();

		addDataType(ByteDataType.dataType);
		addDataType(CharDataType.dataType);
		addFlexDataType(DWordDataType.dataType, null, null);

		JRadioButton byValuePackingButton =
			(JRadioButton) findComponentByName(editorPanel, "By Value Packing");
		assertNotNull(byValuePackingButton);
		JTextField packingValueField =
			(JTextField) findComponentByName(editorPanel, "Packing Value");
		assertNotNull(packingValueField);
		assertEquals(true, byValuePackingButton.isSelected());
		assertEquals("" + value, packingValueField.getText());

		assertEquals(true, structureModel.viewComposite.isDefaultAligned());
		assertEquals(false, structureModel.viewComposite.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, structureModel.getMinimumAlignment());

		assertEquals(2, structureModel.getNumComponents());
		assertEquals(4, structureModel.getRowCount());
		checkRow(0, 0, 1, "db", ByteDataType.dataType, "", "");
		checkRow(1, 1, 1, "char", CharDataType.dataType, "", "");
		checkBlankRow(2);
		checkRow(3, 2, 0, "ddw[0]", DWordDataType.dataType, "", "");
		assertLength(2);
		assertActualAlignment(1);
	}

	////////////////////////////

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
		return structureModel.viewComposite.add(dataType);
	}

	private DataTypeComponent addFlexDataType(DataType dataType, String name, String comment) {
		return ((Structure) structureModel.viewComposite).setFlexibleArrayComponent(dataType, name,
			comment);
	}

}
