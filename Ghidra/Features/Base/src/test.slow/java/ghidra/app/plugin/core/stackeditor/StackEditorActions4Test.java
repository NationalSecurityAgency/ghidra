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
package ghidra.app.plugin.core.stackeditor;

import static org.junit.Assert.*;

import java.awt.Component;

import javax.swing.*;
import javax.swing.text.JTextComponent;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.plugin.core.compositeeditor.CycleGroupAction;
import ghidra.app.plugin.core.compositeeditor.FavoritesAction;
import ghidra.program.model.data.*;

public class StackEditorActions4Test extends AbstractStackEditorTest {

	public StackEditorActions4Test() {
		super(false);
	}

	private JTextComponent getEditedField() {
		JTable table = getTable();
		Component editorComponent = table.getEditorComponent();
		assertNotNull(editorComponent);
		JTextComponent textComponent = (JTextComponent) editorComponent;
		return textComponent;
	}

	private void selectAllText(JTextComponent tc) {
		runSwing(() -> tc.selectAll());
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	@Test
	public void testCycleGroupAsciiLotsOfRoom() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;
		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6 });
		model.clearSelectedComponents();

		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 0 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(0));

		invoke(action);
		dialog = getDialogComponent(NumberInputDialog.class);
		assertNull(dialog);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(0));
	}

	@Test
	public void testCycleGroupAsciiSomeRoom() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;

		DataType dt5 = getDataType(5);
		int dt5Len = getLength(5);
		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(5), dt5Len);
		assertEquals(getDataType(5), dt5);

		invoke(action);
		dialog = getDialogComponent(NumberInputDialog.class);
		assertNull(dialog);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(5), dt5Len);
		assertEquals(getDataType(5), dt5);
	}

	@Test
	public void testDeleteAction() throws Exception {
		init(SIMPLE_STACK);

		DataType dt4 = getDataType(4);
		int offset4 = getOffset(4);
		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 0, 1, 2, 3 });

		assertEquals("", model.getStatus());
		invoke(deleteAction);
		assertEquals("", model.getStatus());
		assertEquals(num - 4, model.getNumComponents());
		assertEquals(len - 7, model.getLength());
		assertEquals(offset4, getOffset(0));
		assertEquals(dt4, getDataType(0));
		assertEquals(0, model.getNumSelectedComponentRows());
	}

	@Test
	public void testEditFieldOnNoVariable() throws Exception {
		init(SIMPLE_STACK);
		setSelection(new int[] { 2 });

		JTable table = provider.getTable();
		final ListSelectionModel selectionModel = table.getColumnModel().getSelectionModel();

		runSwing(() -> selectionModel.setSelectionInterval(0, 0));

		assertTrue(!model.isEditingField());
		triggerActionKey(getTable(), editFieldAction);
		assertTrue(model.isEditingField());
		assertEquals(2, model.getRow());
		assertEquals(model.getDataTypeColumn(), ((StackEditorModel) model).getColumn());

		escape();

		assertEquals("", model.getStatus());
	}

	@Test
	public void testEditFieldOnVariable() throws Exception {
		init(SIMPLE_STACK);

		int row = 1;
		setSelection(new int[] { row });

		JTable table = provider.getTable();
		final ListSelectionModel selectionModel = table.getColumnModel().getSelectionModel();
		final int offsetColumn = model.getOffsetColumn();

		runSwing(() -> selectionModel.setSelectionInterval(offsetColumn, offsetColumn));

		assertTrue(!model.isEditingField());
		invoke(editFieldAction);
		assertTrue("The edit action did not start an edit", model.isEditingField());
		assertEquals("Not editing the expected row", row, model.getRow());
		assertEquals(
			"Not editing the expected column - expected: " + offsetColumn + " but found: " +
				((StackEditorModel) model).getColumn(),
			offsetColumn, ((StackEditorModel) model).getColumn());

		Object initialValue = model.getValueAt(row, model.getOffsetColumn());

		assertEquals("", model.getStatus());

		JTextComponent field = getEditedField();
		selectAllText(field);
		typeInCellEditor("Ab\b\b\t");

		assertEquals("\"\" is not a valid offset.", model.getStatus());
		assertTrue("Not editing after entering invalid data and pressing the tab key",
			model.isEditingField());
		assertEquals("Not editing the expected row", row, model.getRow());

		// make sure we didn't leave the current column, as an empty string is not a valid offset
		assertEquals(
			"Changed column under edit when we should not have left the column being " +
				"edited due to an invalid value - expected: " + offsetColumn + " but found: " +
				((StackEditorModel) model).getColumn(),
			offsetColumn, ((StackEditorModel) model).getColumn());
		typeInCellEditor(initialValue.toString() + "\t");
		assertEquals("", model.getStatus());

		// with valid text, after pressing tab, we should have moved to the next editable cell
		assertEquals(
			"Tabbing with a valid value did not trigger an edit of the next logical " +
				"cell - expected: " + model.getDataTypeColumn() + " but found: " +
				((StackEditorModel) model).getColumn(),
			model.getDataTypeColumn(), ((StackEditorModel) model).getColumn());

		escape();
		waitForSwing();

		assertEquals("", model.getStatus());
	}

	@Test
	public void testFavoritesFixedOnDefined() throws Exception {
		init(SIMPLE_STACK);

		FavoritesAction fav = getFavorite("byte");

		setSelection(new int[] { 0 });
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		assertEquals("", model.getStatus());
		invoke(fav);
		assertEquals("", model.getStatus());
		assertEquals(0x1e, model.getLength());
		assertEquals(23, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		assertTrue(getDataType(0).isEquivalent(fav.getDataType()));
	}

	@Test
	public void testFavoritesFixedOnMultiple() throws Exception {
		init(SIMPLE_STACK);

		FavoritesAction fav = getFavorite("float");

		setSelection(new int[] { 1, 2, 3, 4, 5 });
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		checkEnablement(fav, false);
	}

	@Test
	public void testFavoritesFixedOnNonContiguous() throws Exception {
		init(SIMPLE_STACK);

		FavoritesAction fav = getFavorite("float");

		setSelection(new int[] { 1, 2, 4, 5 });
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		checkEnablement(fav, false);
	}

	@Test
	public void testFavoritesFixedOnUndefined() throws Exception {
		init(SIMPLE_STACK);

		FavoritesAction fav = getFavorite("byte");

		setSelection(new int[] { 3 });
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		assertEquals("", model.getStatus());
		invoke(fav);
		assertEquals("", model.getStatus());
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		assertTrue(getDataType(3).isEquivalent(fav.getDataType()));
	}

	@Test
	public void testFavoritesOnPointer() throws Exception {
		init(SIMPLE_STACK);

		setSelection(new int[] { 5 });
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x10, getOffset(0));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));

		FavoritesAction fav = getFavorite("word");
		assertTrue(fav.isEnabledForContext(null)); // context not utilized
		assertEquals("", model.getStatus());
		invoke(fav);
		assertEquals("", model.getStatus());
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertTrue(((Pointer) getDataType(5)).getDataType().isEquivalent(fav.getDataType()));
		assertEquals("word *32", getDataType(5).getName());
		assertEquals(4, getLength(5));
	}

	@Test
	public void testNoFitPointerOnFixedDt() throws Exception {
		init(SIMPLE_STACK);
		int ordinal = 2;
		setSelection(new int[] { ordinal });
		invoke(getCycleGroup(new ByteDataType()));
		assertCellString("byte", ordinal, model.getDataTypeColumn());
		assertEquals(20, model.getNumComponents());

		DataType dt = getDataType(ordinal);
		setSelection(new int[] { ordinal });
		assertEquals("", model.getStatus());
		invoke(pointerAction);
		assertEquals("pointer doesn't fit within 3 bytes, need 4 bytes", model.getStatus());
		assertEquals(20, model.getNumComponents());
		assertCellString("byte", ordinal, model.getDataTypeColumn());
		assertEquals("byte", getDataType(ordinal).getName());
		assertEquals(getDataType(ordinal), dt);
		assertEquals(1, getDataType(ordinal).getLength());
		assertEquals(1, model.getComponent(ordinal).getLength());
		assertEquals(0x1e, model.getLength());
	}

	@Test
	public void testShowComponentPathAction() throws Exception {
		init(SIMPLE_STACK);

		assertEquals("", model.getStatus());

		setSelection(new int[] { 19 });
		invoke(showComponentPathAction);
		String pathMessage = "float is in category \"" + pgmRootCat.getCategoryPathName() + "\".";
		assertTrue(pathMessage.equals(model.getStatus()));
	}

	@Test
	public void testShowNumbersInHex() throws Exception {

		editStack(function.getEntryPoint().toString());
		StackEditorPanel panel = (StackEditorPanel) provider.getComponent();

		assertEquals("", model.getStatus());

		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("-0x10", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("0x4", model.getValueAt(0, model.getLengthColumn()));
		assertEquals("0x20", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("0x14", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("0xc", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("0x4",
			((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0x0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());

		invoke(hexNumbersAction);
		assertEquals("", model.getStatus());
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("-16", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("4", model.getValueAt(0, model.getLengthColumn()));
		assertEquals("32", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("20", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("12", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("4", ((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());

		invoke(hexNumbersAction);
		assertEquals("", model.getStatus());
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("-0x10", model.getValueAt(0, model.getOffsetColumn()));
		assertEquals("0x4", model.getValueAt(0, model.getLengthColumn()));
		assertEquals("0x20", ((JTextField) findComponentByName(panel, "Frame Size")).getText());
		assertEquals("0x14", ((JTextField) findComponentByName(panel, "Local Size")).getText());
		assertEquals("0xc", ((JTextField) findComponentByName(panel, "Parameter Size")).getText());
		assertEquals("0x4",
			((JTextField) findComponentByName(panel, "Parameter Offset")).getText());
		assertEquals("0x0",
			((JTextField) findComponentByName(panel, "Return Address Offset")).getText());
	}
}
