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

public class UnionEditorAlignmentTest extends AbstractUnionEditorTest {

	@Test
    public void testUnalignedUnion() {
		init(emptyUnion, pgmRootCat, false);

		assertTrue(unionModel.hasChanges());// empty union that hasn't been saved yet.
		assertTrue(unionModel.isValidName());// name should be valid
		assertEquals(unionModel.getTypeName(), "Union");
		assertEquals(emptyUnion.getName(), unionModel.getCompositeName());
		assertEquals(emptyUnion.getDescription(), unionModel.getDescription());
		assertEquals(pgmRootCat.getCategoryPathName(),
			unionModel.getOriginalCategoryPath().getPath());
		assertEquals(0, unionModel.getNumComponents());// no components
		assertEquals(1, unionModel.getRowCount());// blank row
		assertIsInternallyAligned(false);
		assertPackingValue(Composite.NOT_PACKING);
		assertMinimumAlignmentType(AlignmentType.DEFAULT_ALIGNED);
		assertMinimumAlignmentValue(Composite.DEFAULT_ALIGNMENT_VALUE);
		assertLength(0);
		assertActualAlignment(1);
		assertEquals(0, unionModel.getNumSelectedComponentRows());
		assertEquals(1, unionModel.getNumSelectedRows());
		checkSelection(new int[] { 0 });

//		// Check enablement.
//		CompositeEditorAction[] pActions = provider.getActions();
//		for (int i = 0; i < pActions.length; i++) {
//			if ((pActions[i] instanceof FavoritesAction)
//			|| (pActions[i] instanceof CycleGroupAction)
//			|| (pActions[i] instanceof EditFieldAction)
//			|| (pActions[i] instanceof PointerAction)
//			|| (pActions[i] instanceof HexNumbersAction)) {
//				checkEnablement(pActions[i], true);
//			}
//			else {
//				checkEnablement(pActions[i], false);
//			}
//		}

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);
	}

	@Test
    public void testDefaultAlignedUnion() throws Exception {
		init(emptyUnion, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		pressButtonByName(getPanel(), "Internally Aligned");

		assertEquals(true, unionModel.viewComposite.isDefaultAligned());
		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	@Test
    public void testEnablementDefaultAlignedUnion() throws Exception {
		emptyUnion.setInternallyAligned(true);
		init(emptyUnion, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		// Check enablement.
		CompositeEditorTableAction[] pActions = provider.getActions();
		for (int i = 0; i < pActions.length; i++) {
			if ((pActions[i] instanceof FavoritesAction) ||
				(pActions[i] instanceof CycleGroupAction) ||
				(pActions[i] instanceof EditFieldAction) ||
				(pActions[i] instanceof PointerAction) ||
				(pActions[i] instanceof HexNumbersAction) || (pActions[i] instanceof ApplyAction)) {
				checkEnablement(pActions[i], true);
			}
			else {
				checkEnablement(pActions[i], false);
			}
		}

		assertEquals(true, unionModel.viewComposite.isDefaultAligned());
		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	@Test
    public void testMachineAlignedUnion() throws Exception {
		init(emptyUnion, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		pressButtonByName(getPanel(), "Internally Aligned");
		pressButtonByName(getPanel(), "Machine Minimum Alignment");

		assertEquals(true, unionModel.viewComposite.isMachineAligned());
		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(8);
	}

	@Test
    public void testByValueAlignedUnion() throws Exception {
		init(emptyUnion, pgmRootCat, false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		addDataType(new ByteDataType());
		addDataType(new FloatDataType());
		addDataType(arrayDt);

		pressButtonByName(getPanel(), "Internally Aligned");
		pressButtonByName(getPanel(), "By Value Minimum Alignment");

		JTextField minAlignField =
			(JTextField) findComponentByName(getPanel(), "Minimum Alignment Value");
		assertEquals("4", minAlignField.getText());

		assertEquals(false, unionModel.viewComposite.isDefaultAligned());
		assertEquals(false, unionModel.viewComposite.isMachineAligned());
		assertEquals(4, unionModel.getMinimumAlignment());

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	@Test
    public void testByValue1AlignedUnion() throws Exception {
		checkByValueAlignedUnion(1, 4, 8);
	}

	@Test
    public void testByValue2AlignedUnion() throws Exception {
		checkByValueAlignedUnion(2, 4, 8);
	}

	@Test
    public void testByValue4AlignedUnion() throws Exception {
		checkByValueAlignedUnion(4, 4, 8);
	}

	@Test
    public void testByValue8AlignedUnion() throws Exception {
		checkByValueAlignedUnion(8, 8, 8);
	}

	@Test
    public void testByValue16AlignedUnion() throws Exception {
		checkByValueAlignedUnion(16, 16, 16);
	}

	public void checkByValueAlignedUnion(int value, int alignment, int length) throws Exception {
		emptyUnion.setInternallyAligned(true);
		emptyUnion.setMinimumAlignment(value);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		JRadioButton byValueButton =
			(JRadioButton) findComponentByName(getPanel(), "By Value Minimum Alignment");
		assertEquals(true, byValueButton.isSelected());
		JTextField minAlignField =
			(JTextField) findComponentByName(getPanel(), "Minimum Alignment Value");
		assertEquals("" + value, minAlignField.getText());

		assertEquals(false, unionModel.viewComposite.isDefaultAligned());
		assertEquals(false, unionModel.viewComposite.isMachineAligned());
		assertEquals(value, unionModel.getMinimumAlignment());

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(length);
		assertActualAlignment(alignment);
	}

	@Test
    public void testTurnOffAlignmentInUnion() throws Exception {
		emptyUnion.setInternallyAligned(true);
		emptyUnion.setMinimumAlignment(8);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		JRadioButton byValueButton =
			(JRadioButton) findComponentByName(getPanel(), "By Value Minimum Alignment");
		assertEquals(true, byValueButton.isSelected());
		JTextField minAlignField =
			(JTextField) findComponentByName(getPanel(), "Minimum Alignment Value");
		assertEquals("8", minAlignField.getText());

		assertEquals(false, unionModel.viewComposite.isDefaultAligned());
		assertEquals(false, unionModel.viewComposite.isMachineAligned());
		assertEquals(8, unionModel.getMinimumAlignment());

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(8);
		assertEquals(true, unionModel.isAligned());

		pressButtonByName(getPanel(), "Internally Aligned");

		assertEquals(false, unionModel.isAligned());
		assertEquals(true, unionModel.viewComposite.isDefaultAligned());
		assertEquals(false, unionModel.viewComposite.isMachineAligned());
		assertEquals(Composite.DEFAULT_ALIGNMENT_VALUE, unionModel.getMinimumAlignment());

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);
	}

	@Test
    public void testInsertUnaligned1() throws Exception {
		emptyUnion.setInternallyAligned(false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);

		DataType asciiDt = model.getOriginalDataTypeManager().getDataType("/char");
		assertNotNull(asciiDt);
		insertAtPoint(asciiDt, 0, 0);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "char", asciiDt, "", "");
		checkRow(1, 1, "db", new ByteDataType(), "", "");
		checkRow(2, 4, "float", new FloatDataType(), "", "");
		checkRow(3, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);
	}

	@Test
    public void testInsertUnaligned2() throws Exception {
		emptyUnion.setInternallyAligned(false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);

		DataType asciiDt = model.getOriginalDataTypeManager().getDataType("/char");
		assertNotNull(asciiDt);
		insertAtPoint(asciiDt, 2, 3);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 1, "char", asciiDt, "", "");
		checkRow(3, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);
	}

	@Test
    public void testInsertUnaligned3() throws Exception {
		emptyUnion.setInternallyAligned(false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);

		DataType doubleDt = model.getOriginalDataTypeManager().getDataType("/double");
		assertNotNull(doubleDt);
		insertAtPoint(doubleDt, 3, 3);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		checkRow(3, 8, "double", doubleDt, "", "");
		assertLength(8);
		assertActualAlignment(1);
	}

	@Test
    public void testReplaceUnaligned1() throws Exception {
		emptyUnion.setInternallyAligned(false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);

		DataType asciiDt = model.getOriginalDataTypeManager().getDataType("/char");
		assertNotNull(asciiDt);
		addAtPoint(asciiDt, 2, 3);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 1, "char", asciiDt, "", "");
		assertLength(4);
		assertActualAlignment(1);
	}

	@Test
    public void testReplaceUnaligned2() throws Exception {
		emptyUnion.setInternallyAligned(false);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(5);
		assertActualAlignment(1);

		DataType doubleDt = model.getOriginalDataTypeManager().getDataType("/double");
		assertNotNull(doubleDt);
		addAtPoint(doubleDt, 3, 3);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		checkRow(3, 8, "double", doubleDt, "", "");
		assertLength(8);
		assertActualAlignment(1);
	}

	@Test
    public void testInsertAligned1() throws Exception {
		emptyUnion.setInternallyAligned(true);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);

		DataType asciiDt = model.getOriginalDataTypeManager().getDataType("/char");
		assertNotNull(asciiDt);
		insertAtPoint(asciiDt, 0, 0);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "char", asciiDt, "", "");
		checkRow(1, 1, "db", new ByteDataType(), "", "");
		checkRow(2, 4, "float", new FloatDataType(), "", "");
		checkRow(3, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	@Test
    public void testInsertAligned2() throws Exception {
		emptyUnion.setInternallyAligned(true);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);

		DataType asciiDt = model.getOriginalDataTypeManager().getDataType("/char");
		assertNotNull(asciiDt);
		insertAtPoint(asciiDt, 2, 3);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 1, "char", asciiDt, "", "");
		checkRow(3, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	@Test
    public void testInsertAligned3() throws Exception {
		emptyUnion.setInternallyAligned(true);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);

		DataType doubleDt = model.getOriginalDataTypeManager().getDataType("/double");
		assertNotNull(doubleDt);
		insertAtPoint(doubleDt, 3, 3);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		checkRow(3, 8, "double", doubleDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	@Test
    public void testReplaceAligned1() throws Exception {
		emptyUnion.setInternallyAligned(true);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);

		DataType asciiDt = model.getOriginalDataTypeManager().getDataType("/char");
		assertNotNull(asciiDt);
		addAtPoint(asciiDt, 2, 3);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 1, "char", asciiDt, "", "");
		assertLength(4);
		assertActualAlignment(4);
	}

	@Test
    public void testReplaceAligned2() throws Exception {
		emptyUnion.setInternallyAligned(true);

		DataType arrayDt = new ArrayDataType(new CharDataType(), 5, 1);
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new FloatDataType());
		emptyUnion.add(arrayDt);

		init(emptyUnion, pgmRootCat, false);

		assertEquals(3, unionModel.getNumComponents());
		assertEquals(4, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		assertLength(8);
		assertActualAlignment(4);

		DataType doubleDt = model.getOriginalDataTypeManager().getDataType("/double");
		assertNotNull(doubleDt);
		addAtPoint(doubleDt, 3, 3);

		assertEquals(4, unionModel.getNumComponents());
		assertEquals(5, unionModel.getRowCount());
		checkRow(0, 1, "db", new ByteDataType(), "", "");
		checkRow(1, 4, "float", new FloatDataType(), "", "");
		checkRow(2, 5, "char[5]", arrayDt, "", "");
		checkRow(3, 8, "double", doubleDt, "", "");
		assertLength(8);
		assertActualAlignment(4);
	}

	////////////////////////////

	private void checkRow(int rowIndex, int length, String mnemonic, DataType dataType, String name,
			String comment) {
		assertTrue(dataType.isEquivalent(unionModel.getComponent(rowIndex).getDataType()));
		assertEquals("" + length, unionModel.getValueAt(rowIndex, unionModel.getLengthColumn()));
		assertEquals(mnemonic, unionModel.getValueAt(rowIndex, unionModel.getMnemonicColumn()));
		assertEquals(name, unionModel.getValueAt(rowIndex, unionModel.getNameColumn()));
		assertEquals(comment, unionModel.getValueAt(rowIndex, unionModel.getCommentColumn()));
	}

	private DataTypeComponent addDataType(DataType dataType) {
		return unionModel.viewComposite.add(dataType);
	}

}
