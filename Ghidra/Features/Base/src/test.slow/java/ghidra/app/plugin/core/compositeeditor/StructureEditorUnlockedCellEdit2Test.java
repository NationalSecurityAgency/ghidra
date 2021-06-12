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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.JTextField;

import org.junit.Test;

import generic.test.ConcurrentTestExceptionHandler;
import ghidra.program.model.data.*;

public class StructureEditorUnlockedCellEdit2Test
		extends AbstractStructureEditorUnlockedCellEditTest {

	@Test
	public void testF2EditKey() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getDataTypeColumn();

		setSelection(new int[] { 0 });
		checkSelection(new int[] { 0 });
		assertTrue(editFieldAction.isEnabled());
		triggerActionKey(getTable(), editFieldAction);

		assertIsEditingField(0, colNum);
		escape();

		assertNotEditingField();
	}

	@Test
	public void testEditFieldOnOffsetColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getOffsetColumn();

		// TODO these should not rely on mouse clicking; we should also get an error when 
		//      we call edit cell
		clickTableCell(getTable(), 1, colNum, 2);
		assertStatus("Offset field is not editable");
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnLengthColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getLengthColumn();

		// TODO these should not rely on mouse clicking; we should also get an error when 
		//      we call edit cell
		clickTableCell(getTable(), 1, colNum, 2);
		assertStatus("Length field is not editable");
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnMnemonicColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getMnemonicColumn();

		// TODO these should not rely on mouse clicking; we should also get an error when 
		//      we call edit cell
		// editCell(getTable(), 1, colNum);
		clickTableCell(getTable(), 1, colNum, 2);
		assertStatus("Mnemonic field is not editable");
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnDataTypeColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getDataTypeColumn();

		editCell(getTable(), 0, colNum);
		assertIsEditingField(0, colNum);

		runSwing(() -> getTable().getCellEditor().stopCellEditing());// close the editor

		editCell(getTable(), 1, colNum);
		assertIsEditingField(1, colNum);

		escape();// Remove the choose data type dialog.

		assertNotEditingField();
	}

	@Test
	public void testEditFieldOnNameColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getNameColumn();

		editCell(getTable(), 0, colNum);
		assertNotEditingField();

		editCell(getTable(), 1, colNum);
		assertIsEditingField(1, colNum);
	}

	@Test
	public void testEditFieldOnCommentColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getCommentColumn();

		editCell(getTable(), 0, colNum);
		assertNotEditingField();

		editCell(getTable(), 1, colNum);
		assertIsEditingField(1, colNum);
	}

	@Test
	public void testEditFieldOnBlankRow() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = model.getNumComponents();

		for (int colNum = 0; colNum < model.getNumFields(); colNum++) {
			editCell(getTable(), rowNum, colNum);
			assertEquals(rowNum, model.getRow());
			if (model.isCellEditable(rowNum, colNum)) {
				assertIsEditingField(rowNum, colNum);
				runSwing(() -> getTable().getCellEditor().stopCellEditing());// close the editor
			}
		}
	}

	@Test
	public void testUpOnEditField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = model.getNumComponents() - 1;
		int colNum = model.getDataTypeColumn() + 1;

		waitForSwing();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		for (int count = 0; count < 6; count++) {
			triggerActionInCellEditor(KeyEvent.VK_UP);
			rowNum--;
			assertIsEditingField(rowNum, colNum);
		}
		triggerActionInCellEditor(KeyEvent.VK_UP);
		assertNotEditingField();
		assertEquals(0, model.getRow());
	}

	@Test
	public void testDownOnEditField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = 1;
		int colNum = model.getDataTypeColumn() + 1;

		waitForSwing();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		for (int count = 0; count < 6; count++) {
			triggerActionInCellEditor(KeyEvent.VK_DOWN);
			rowNum++;
			assertIsEditingField(rowNum, colNum);
		}
		triggerActionInCellEditor(KeyEvent.VK_DOWN);
		assertNotEditingField();
		assertEquals(model.getNumComponents(), model.getRow());
	}

	@Test
	public void testCantLeaveEditField() throws Exception {
		init(simpleStructure, pgmBbCat);

		assertTrue(!model.isEditingField());
		DataType dt = getDataType(2);
		editCell(getTable(), 2, model.getDataTypeColumn());
		waitForSwing();
		assertTrue(model.isEditingField());
		assertEquals(2, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		endKey();
		type("Ab\bm");

		// Bad value prevents action performed.
		triggerActionInCellEditor(KeyEvent.VK_ENTER);
		waitForSwing();
		assertTrue(model.isEditingField());
		assertEquals(2, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		// Bad value allows escape.
		escape();
		escape();
		waitForSwing();
		assertTrue(!model.isEditingField());
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertEquals(getDataType(2), dt);
	}

	@Test
	public void testEditDefaultField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int dtColNum = model.getDataTypeColumn();

		assertNotEditingField();
		DataType dt = getDataType(2);
		editCell(getTable(), 2, dtColNum);
		waitForSwing();
		assertIsEditingField(2, dtColNum);

		endKey();
		type("Ab\bm");
		assertIsEditingField(2, dtColNum);

		// Bad value prevents action performed.
		triggerActionInCellEditor(KeyEvent.VK_ENTER);
		assertIsEditingField(2, dtColNum);
		waitForSwing();

		// Bad value allows escape.
		triggerActionInCellEditor(KeyEvent.VK_ESCAPE);// close the dialog
		waitForSwing();
		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertEquals(getDataType(2), dt);
	}

	@Test
	public void testEditComponentDataTypeNoFit() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "char[3][2][4]";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 2, column);
		assertIsEditingField(2, column);

		setText(str);
		pressEnterToSelectChoice();

		assertEquals("char[3][2][4] doesn't fit within 2 bytes, need 24 bytes", model.getStatus());

		assertEquals(true, model.isEditingField());
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("word", 2, column);
		assertEquals(29, model.getLength());
		assertEquals(2, getDataType(2).getLength());
	}

	@Test
	public void testEditComponentDataTypeAtEnd() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "char[3][2][4]";
		DataType dt = getDataType(7);

		assertEquals(29, model.getLength());
		assertEquals(1, dt.getLength());
		editCell(getTable(), 7, column);
		assertIsEditingField(7, column);

		setText(str);
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(7, model.getMinIndexSelected());
		assertCellString(str, 7, column);
		assertEquals(52, model.getLength());
		assertEquals(24, getDataType(7).getLength());
	}

	@Test
	public void testEditComponentDataTypeInvalid() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String invalidString = "AbCdEfG_12345.,/\\";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 2, column);
		assertIsEditingField(2, column);

		setText(invalidString);

		enter();
		ConcurrentTestExceptionHandler.clear();// prevent this from failing the test after tearDown()

		assertIsEditingField(2, column);
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("word", 2, column);
		assertEquals(29, model.getLength());
		assertEquals(dt, getDataType(2));

		escape();
		assertNotEditingField();
		assertEquals(dt, getDataType(2));
	}

	@Test
	public void testEditToBasicPointer() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 3, column);
		assertIsEditingField(3, column);

		setText("pointer");

		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertCellString("pointer", 3, column);
		assertEquals(29, model.getLength());
		assertEquals(4, getDataType(3).getLength());
		assertEquals(4, model.getComponent(3).getLength());
	}

	@Test
	public void testEditToSizedPointer() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 3, column);
		assertIsEditingField(3, column);

		setText("pointer32");

		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertCellString("pointer32", 3, column);
		assertEquals(29, model.getLength());
		assertEquals(4, getDataType(3).getLength());
		assertEquals(4, model.getComponent(3).getLength());
	}

	@Test
	public void testEditToComplexPointerArray() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(7);

		assertEquals(29, model.getLength());
		assertEquals(1, dt.getLength());
		editCell(getTable(), 7, column);
		assertIsEditingField(7, column);

		setText("unicode**[5][2]");// only unicode
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(7, model.getMinIndexSelected());
		assertCellString("unicode * *[5][2]", 7, column);
		assertEquals(68, model.getLength());
		dt = getDataType(7);
		assertEquals(40, dt.getLength());
		assertEquals("unicode * *[5][2]", dt.getDisplayName());
		assertEquals(40, model.getComponent(7).getLength());
	}

	@Test
	public void testEditPointerToPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(6);
		int len = model.getLength();
		int num = model.getNumComponents();

		assertEquals(4, dt.getLength());
		assertEquals(4, model.getComponent(6).getLength());
		editCell(getTable(), 6, column);
		assertIsEditingField(6, column);

		endKey();
		type("*");// have simpleStructure *32, but not simpleStructure *32*
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(6, model.getMinIndexSelected());
		assertCellString("simpleStructure * *", 6, column);
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
		dt = getDataType(6);
		assertEquals(4, dt.getLength());
		assertEquals("simpleStructure * *", dt.getDisplayName());
		assertEquals(4, model.getComponent(6).getLength());
	}

	@Test
	public void testEditComponentDataTypeBigger() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();

		assertEquals(29, model.getLength());
		assertEquals(1, getDataType(7).getLength());
		editCell(getTable(), 7, column);
		assertIsEditingField(7, column);

		endKey();
		type("[5]\n");// char, but no char[5]

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(7, model.getMinIndexSelected());
		assertCellString("char[5]", 7, column);
		assertEquals(33, model.getLength());
		assertEquals(5, getDataType(7).getLength());
	}

	@Test
	public void testEditComponentDataTypeSmaller() throws Exception {
		init(complexStructure, pgmTestCat);
		int column = model.getDataTypeColumn();

		assertEquals(325, model.getLength());
		assertEquals(87, getDataType(16).getLength());
		editCell(getTable(), 16, column);
		assertIsEditingField(16, column);

		endKey();
		type("\b\b2]\n");// simpleStructure[3], but not simpleStructure[2]

		assertNotEditingField();
		assertEquals(30, model.getNumSelectedRows());
		assertEquals(16, model.getMinIndexSelected());
		assertCellString("simpleStructure[2]", 16, column);
		assertEquals(325, model.getLength());
		assertEquals(58, getDataType(16).getLength());
	}

	@Test
	public void testEditComponentDataTypeComplex() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(7);

		assertEquals(29, model.getLength());
		assertEquals(1, dt.getLength());
		editCell(getTable(), 7, column);
		assertIsEditingField(7, column);

		setText("complexUnion***[3][3]");// complexUnion, but not complexUnion***[3][3]
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(7, model.getMinIndexSelected());
		assertCellString("complexUnion * * *[3][3]", 7, column);
		assertEquals(64, model.getLength());
		dt = getDataType(7);
		assertEquals(36, dt.getLength());
		assertEquals("complexUnion * * *[3][3]", dt.getDisplayName());
		assertEquals(36, model.getComponent(7).getLength());
	}

	@Test
	public void testEditDataTypeNotSelf() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "simpleStructure";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 2, column);
		assertIsEditingField(2, column);

		setText(str);
		enter();

		assertIsEditingField(2, column);
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("word", 2, column);
		assertEquals(29, model.getLength());
		assertEquals(dt, getDataType(2));

		escape();// Remove the choose data type dialog.

		assertNotEditingField();
	}

	@Test
	public void testEditDataTypeSelfPointer() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(3);

		assertEquals(29, model.getLength());
		assertEquals(4, dt.getLength());
		editCell(getTable(), 3, column);
		assertIsEditingField(3, column);

		setText("simpleStructure*");// no basic simpleStructure*, but there are others like simpleStructure *32
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertCellString("simpleStructure *", 3, column);
		assertEquals(29, model.getLength());
		dt = getDataType(3);
		assertEquals(4, dt.getLength());
		assertEquals("simpleStructure *", dt.getDisplayName());
		assertEquals(4, model.getComponent(3).getLength());
	}

	@Test
	public void testEditDataTypeWithFactory() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "PE";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 2, column);
		assertIsEditingField(2, column);

		setText(str);
		enter();

		assertEquals("Factory data-type not allowed", model.getStatus());
		escape();

		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("word", 2, column);
		assertEquals(29, model.getLength());
		assertEquals(dt, getDataType(2));
	}

	@Test
	public void testEditDataTypeWithDynamic() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "GIF-Image";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		editCell(getTable(), 2, column);
		assertIsEditingField(2, column);

		setText(str);
		enter();
		assertIsEditingField(2, column);

		assertEquals("non-sizable data-type not allowed", model.getStatus());

		escape();

		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("word", 2, column);
		assertEquals(29, model.getLength());
		assertEquals(dt, getDataType(2));
	}

	@Test
	public void testEditComponentName() throws Exception {
		init(simpleStructure, pgmBbCat);

		int column = model.getNameColumn();
		int num = model.getNumComponents();
		int len = model.getLength();
		assertNull(getComment(3));
		editCell(getTable(), 3, column);
		assertIsEditingField(3, column);

		setText("Wow");
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertEquals("Wow", getFieldName(3));
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
	}

	@Test
	public void testEditComponentComment() throws Exception {
		init(simpleStructure, pgmBbCat);

		int column = model.getCommentColumn();
		int num = model.getNumComponents();
		int len = model.getLength();
		assertNull(getComment(3));
		editCell(getTable(), 3, column);
		assertIsEditingField(3, column);

		setText("My comment.");
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertEquals("My comment.", getComment(3));
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
	}

	@Test
	public void testEditNextField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		setText("Component_3");

		triggerActionInCellEditor(KeyEvent.VK_TAB);

		assertIsEditingField(rowNum, colNum + 1);
		assertEquals(rowNum, model.getRow());
		assertEquals(colNum + 1, model.getColumn());
		assertEquals("Component_3", getFieldName(rowNum));

		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditPreviousField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		setText("Component_3");
		triggerActionInCellEditor(InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);

		assertIsEditingField(rowNum, colNum - 1);
		assertEquals("Component_3", getFieldName(rowNum));

		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditUpField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		setText("Component_3");

		triggerActionInCellEditor(KeyEvent.VK_UP);

		assertIsEditingField(rowNum - 1, colNum);
		assertEquals("Component_3", getFieldName(rowNum));

		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditDownField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		setText("Component_3");
		triggerActionInCellEditor(KeyEvent.VK_DOWN);

		assertIsEditingField(rowNum + 1, colNum);
		assertEquals("Component_3", getFieldName(rowNum));

		escape();
		assertNotEditingField();
	}

	@Test
	public void testManyWithSameDtName() throws Exception {
		Structure simpleStructure2 = new StructureDataType("simpleStructure", 0);
		simpleStructure2.add(new FloatDataType());// component 0
		simpleStructure2.add(new DoubleDataType());// component 1
		simpleStructure2.setDescription("My simple structure.");
		startTransaction("Add second simpleStructure.");
		simpleStructure2 = (Structure) pgmRootCat.addDataType(simpleStructure2, null);
		endTransaction(true);

		init(complexStructure, pgmTestCat);
		int rowNum = 3;
		int colNum = model.getDataTypeColumn();

		editCell(getTable(), rowNum, colNum);
		assertIsEditingField(rowNum, colNum);

		// this test has to use the slower 'type()' method to ensure that the drop-down
		// window appears, which allows the correct type to be selected
		type("simpleStructure");
		enter();
		assertIsEditingField(rowNum, colNum);

		assertEquals("simpleStructure doesn't fit within 4 bytes, need 29 bytes",
			model.getStatus());

		escape();

		editCell(getTable(), 22, colNum);
		assertIsEditingField(22, colNum);
		// this test has to use the slower 'type()' method to ensure that the drop-down
		// window appears, which allows the correct type to be selected
		type("simpleStructure");
		enter();

		DataType newDt = getDataType(22);
		assertEquals("simpleStructure", newDt.getDisplayName());
		assertEquals(29, newDt.getLength());
		assertEquals(29, getLength(22));
		assertEquals(350, model.getLength());
	}

	@Override
	protected void setText(String s) {
		JTextField tf = getActiveEditorTextField();
		setText(tf, s);
	}
}
