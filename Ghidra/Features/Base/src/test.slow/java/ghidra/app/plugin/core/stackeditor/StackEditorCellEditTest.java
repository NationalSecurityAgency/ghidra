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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.JTable;
import javax.swing.ListSelectionModel;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.listing.Variable;

public class StackEditorCellEditTest extends AbstractStackEditorTest {

	public StackEditorCellEditTest() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	@Test
	public void testF2EditKey() throws Exception {
		init(SIMPLE_STACK);

		setSelection(new int[] { 0 });

		JTable table = provider.getTable();
		final ListSelectionModel selectionModel = table.getColumnModel().getSelectionModel();

		runSwing(() -> selectionModel.setSelectionInterval(0, 0));

		triggerActionKey(getTable(), editFieldAction);
		assertIsEditingField(0, 0);
		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditFieldOnOffsetColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getOffsetColumn();

		// Can't edit offset where there isn't a stack variable defined.
		clickTableCell(getTable(), 2, colNum, 2);
		assertNotEditingField();
		assertEquals(2, model.getRow());

		// Can edit stack variable where there is a stack variable defined.
		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);

		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditOffsetBadMove() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getOffsetColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("-0x10\n");
		assertIsEditingField(1, colNum);
		assertTrue(stackModel.hasVariableAtOrdinal(1));
		assertStatus("There is already a stack variable at offset -0x10.");

		cleanup();
	}

	@Test
	public void testEditOffsetGoodMove() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getOffsetColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
		assertEquals(1, model.getRow());
		deleteAllInCellEditor();
		typeInCellEditor("-0xb\n");
		assertNotEditingField();
		assertTrue(!stackModel.hasVariableAtOrdinal(1));
		assertTrue(stackModel.hasVariableAtOrdinal(2));
		assertStatus("");
		assertTrue(applyAction.isEnabled());
	}

	@Test
	public void testEditLocalVarOffset() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getOffsetColumn();
		assertTrue(!stackModel.hasVariableAtOrdinal(3));
		assertTrue(stackModel.hasVariableAtOrdinal(5));

		// Move & overlap start
		clickTableCell(getTable(), 5, colNum, 2);
		assertIsEditingField(5, colNum);
		assertEquals(5, model.getRow());
		deleteAllInCellEditor();
		typeInCellEditor("-0xa\n");
		assertNotEditingField();
		assertTrue(stackModel.hasVariableAtOrdinal(3));
		assertTrue(!stackModel.hasVariableAtOrdinal(5));
		assertStatus("");
		assertTrue(applyAction.isEnabled());

		// Move & overlap end
		clickTableCell(getTable(), 3, colNum, 2);
		assertIsEditingField(3, colNum);
		assertEquals(3, model.getRow());
		deleteAllInCellEditor();
		typeInCellEditor("-0x7\n");
		assertNotEditingField();
		assertTrue(!stackModel.hasVariableAtOrdinal(3));
		assertTrue(stackModel.hasVariableAtOrdinal(6));
		assertStatus("");
		assertTrue(applyAction.isEnabled());

		// Move before
		clickTableCell(getTable(), 6, colNum, 2);
		assertIsEditingField(6, colNum);
		assertEquals(6, model.getRow());
		deleteAllInCellEditor();
		typeInCellEditor("-0xb\n");
		assertNotEditingField();
		assertTrue(stackModel.hasVariableAtOrdinal(2));
		assertTrue(!stackModel.hasVariableAtOrdinal(6));
		assertStatus("");
		assertTrue(applyAction.isEnabled());

		// Move after
		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		assertEquals(2, model.getRow());
		deleteAllInCellEditor();
		typeInCellEditor("-0x7\n");
		assertNotEditingField();
		assertTrue(!stackModel.hasVariableAtOrdinal(2));
		assertTrue(stackModel.hasVariableAtOrdinal(6));
		assertStatus("");
		assertTrue(applyAction.isEnabled());
	}

	@Test
	public void testEditOffsetMoveNoFit() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getOffsetColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("-0xa\n");
		assertIsEditingField(0, colNum);
		assertTrue(stackModel.hasVariableAtOrdinal(0));
		assertTrue(stackModel.hasVariableAtOrdinal(1));
		assertTrue(!stackModel.hasVariableAtOffset(-0xa));
		assertTrue(stackModel.hasVariableAtOffset(-0x8));
		assertTrue(model.getStatus().startsWith("undefined4 doesn't fit at offset -0xa."));

		cleanup();
	}

	@Test
	public void testEditOffsetMoveCrossesBounds() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getOffsetColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("-0x2\n");
		assertIsEditingField(0, colNum);
		assertTrue(stackModel.hasVariableAtOrdinal(0));
		assertTrue(stackModel.hasVariableAtOrdinal(1));
		assertTrue(!stackModel.hasVariableAtOffset(-0x2));
		assertTrue(model.getStatus().startsWith("undefined4 doesn't fit at offset -0x2."));

		cleanup();
	}

//	public void testEditOffsetNoMoveLocalToParam() throws Exception {
//		init(SIMPLE_STACK);
//		int colNum = model.getOffsetColumn();
//			
//		clickTableCell(getTable(), 0, colNum, 2);
//		assertIsEditingField(0, colNum);
//		deleteAllInCellEditor();
//		typeInCellEditor("0x2\n");
//		assertNotEditingField();
//		assertTrue(stackModel.hasVariableAtOrdinal(0));
//		assertTrue(stackModel.hasVariableAtOrdinal(1));
//		assertTrue(!stackModel.hasVariableAtOffset(0x2));
//		assertStatus("Component doesn't fit at offset 0x2.");
//	}

	@Test
	public void testEditFieldOnLengthColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getLengthColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		waitForPostedSwingRunnables();
		assertNotEditingField();
		assertEquals(1, model.getRow());
		assertStatus("Length field is not editable");
	}

	@Test
	public void testEditFieldOnDataTypeColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 3, colNum, 2);
		assertIsEditingField(3, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("byte\n");
		enter();
		assertNotEditingField();
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0xa);
		assertEquals("byte", sv.getDataType().getName());
		assertEquals(1, sv.getDataType().getLength());
		assertEquals("local_a", sv.getName());
	}

	@Test
	public void testChangeDataTypeSameSize() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("pointer32");
		waitForSwing();

		pressEnterToSelectChoice();
		enter();
		assertNotEditingField();
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0x10);
		assertEquals("pointer32", sv.getDataType().getName());
		assertEquals(4, sv.getDataType().getLength());
		assertEquals("local_10", sv.getName());
	}

	@Test
	public void testChangeDataTypeSmaller() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("word\n");
		assertNotEditingField();
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0x10);
		assertEquals("word", sv.getDataType().getName());
		assertEquals(2, sv.getDataType().getLength());
		assertEquals("local_10", sv.getName());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xe, getOffset(1));
		assertEquals(-0xd, getOffset(2));
		assertEquals(-0xc, getOffset(3));
	}

	@Test
	public void testChangeDataTypeBigger() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("dword\n");
		enter();
		assertNotEditingField();
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0xc);
		assertEquals("dword", sv.getDataType().getName());
		assertEquals(4, sv.getDataType().getLength());
		assertEquals("local_c", sv.getName());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xc, getOffset(1));
		assertEquals(-0x8, getOffset(2));
	}

	@Test
	public void testChangeDataTypeBiggerNoFit() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getDataTypeColumn();

		int ordinal = getOrdinalAtOffset(-0x4);
		clickTableCell(getTable(), ordinal, colNum, 2);
		assertIsEditingField(ordinal, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("qword\n");
		enter();

		assertEquals("qword doesn't fit within 4 bytes, need 8 bytes", model.getStatus());
		assertTrue(!applyAction.isEnabled());
		escape();
	}

	@Test
	public void testChangeDataTypeToCrossBoundary() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
		deleteAllInCellEditor();
		typeInCellEditor("qword\n");
		enter();

		assertEquals("qword doesn't fit within 4 bytes, need 8 bytes", model.getStatus());
		assertTrue(!applyAction.isEnabled());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xc, getOffset(1));
		assertEquals(-0xb, getOffset(2));
	}

	@Test
	public void testEditFieldOnDefinedNameColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
		selectAllInCellEditor();
		typeInCellEditor("testName1\n");
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0xc);
		assertEquals("undefined", sv.getDataType().getName());
		assertEquals(1, sv.getDataType().getLength());
		assertEquals("testName1", sv.getName());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xc, getOffset(1));
		assertEquals(-0xb, getOffset(2));
	}

	@Test
	public void testApplyOnDefinedNameEdit() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getNameColumn();
		assertEquals(null, getFieldName(0));

		// Change name and apply enables
		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		selectAllInCellEditor();
		typeInCellEditor("testName1\n");
		assertTrue(applyAction.isEnabled());

		// Change name back and apply disables
		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		selectAllInCellEditor();
		typeInCellEditor("local_10\n");
		assertTrue(!applyAction.isEnabled());
	}

	@Test
	public void testEditFieldOnUndefinedNameColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		selectAllInCellEditor();
		typeInCellEditor("testNameTwo\n");
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0xb);
		assertEquals("undefined", sv.getDataType().getName());
		assertEquals(1, sv.getDataType().getLength());
		assertEquals("testNameTwo", sv.getName());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xc, getOffset(1));
		assertEquals(-0xb, getOffset(2));
	}

	@Test
	public void testApplyOnUndefinedNameEdit() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getNameColumn();
		assertNull(getFieldName(2));

		// Change name and apply enables
		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		selectAllInCellEditor();
		typeInCellEditor("testName1\n");
		assertTrue(applyAction.isEnabled());

		// Change name back and apply disables
		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		selectAllInCellEditor();
		typeInCellEditor("\b\n");
		assertTrue(!applyAction.isEnabled());
	}

	@Test
	public void testEditFieldOnDefinedCommentColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getCommentColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
		selectAllInCellEditor();
		typeInCellEditor("test comment one\n");
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0xc);
		assertEquals("undefined", sv.getDataType().getName());
		assertEquals(1, sv.getDataType().getLength());
		assertEquals("test comment one", sv.getComment());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xc, getOffset(1));
		assertEquals(-0xb, getOffset(2));
	}

	@Test
	public void testApplyOnDefinedCommentEdit() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getCommentColumn();
		assertNull(getComment(0));

		// Change name and apply enables
		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		selectAllInCellEditor();
		typeInCellEditor("test comment one\n");
		assertEquals("test comment one", getComment(0));
		assertTrue(applyAction.isEnabled());

		// Change name back and apply disables
		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
		selectAllInCellEditor();
		typeInCellEditor("\b\n");
		assertNull(getComment(0));
		assertTrue(!applyAction.isEnabled());
	}

	@Test
	public void testEditFieldOnUndefinedCommentColumn() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getCommentColumn();

		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		selectAllInCellEditor();
		typeInCellEditor("test comment two\n");
		assertTrue(applyAction.isEnabled());
		invoke(applyAction);
		Variable sv = stackFrame.getVariableContaining(-0xb);
		assertEquals("undefined", sv.getDataType().getName());
		assertEquals(1, sv.getDataType().getLength());
		assertEquals("test comment two", sv.getComment());
		assertEquals(-0x10, getOffset(0));
		assertEquals(-0xc, getOffset(1));
		assertEquals(-0xb, getOffset(2));
	}

	@Test
	public void testApplyOnUndefinedCommentEdit() throws Exception {
		init(SIMPLE_STACK);
		int colNum = model.getCommentColumn();
		assertNull(getFieldName(2));

		// Change name and apply enables
		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		selectAllInCellEditor();
		typeInCellEditor("test comment 1\n");
		assertTrue(applyAction.isEnabled());

		// Change name back and apply disables
		clickTableCell(getTable(), 2, colNum, 2);
		assertIsEditingField(2, colNum);
		selectAllInCellEditor();
		typeInCellEditor("\b\n");
		assertTrue(!applyAction.isEnabled());
	}

	@Test
	public void testUpOnEditField() throws Exception {
		init(SIMPLE_STACK);
		int rowNum = model.getNumComponents() - 1;
		int colNum = model.getDataTypeColumn() + 1;

		waitForPostedSwingRunnables();

		clickTableCell(getTable(), rowNum, colNum, 2);
		assertIsEditingField(rowNum, colNum);

		while (rowNum > 0) {
			triggerActionInCellEditor(KeyEvent.VK_UP);
			waitForPostedSwingRunnables();
			rowNum--;
//			DataTypeComponent dtc = model.getComponent(rowNum);
//			if (dtc.getOffset() < ((StackEditorModel) model).getParameterOffset()) {
//				assertNotEditingField();
//				break;
//			}
			assertIsEditingField(rowNum, colNum);
		}
		while (rowNum > 0) {
			triggerActionInCellEditor(KeyEvent.VK_UP);
			waitForPostedSwingRunnables();
			rowNum--;
			clickTableCell(getTable(), rowNum, colNum, 2);
			DataTypeComponent dtc = model.getComponent(rowNum);
			if (dtc.getOffset() < 0) {
				System.out.println("E " + rowNum + ": " + dtc.getOffset());
				assertIsEditingField(rowNum, colNum);
				break;
			}
			System.out.println(rowNum + ": " + dtc.getOffset());
			assertNotEditingField();
		}
		while (rowNum > 0) {
			triggerActionInCellEditor(KeyEvent.VK_UP);
			waitForPostedSwingRunnables();
			rowNum--;
			assertIsEditingField(rowNum, colNum);
		}
		triggerActionInCellEditor(KeyEvent.VK_UP);
		waitForPostedSwingRunnables();
		assertNotEditingField();
		assertEquals(0, model.getRow());
	}

	@Test
	public void testDownOnEditField() throws Exception {
		init(SIMPLE_STACK);
		int rowNum = 0;
		int colNum = model.getNameColumn();

		waitForPostedSwingRunnables();

		clickTableCell(getTable(), rowNum, colNum, 2);
		assertIsEditingField(rowNum, colNum);

		while (rowNum < model.getNumComponents() - 1) {
			triggerActionInCellEditor(KeyEvent.VK_DOWN);
			waitForPostedSwingRunnables();
			rowNum++;
//			DataTypeComponent dtc = model.getComponent(rowNum);
//			if (dtc.getOffset() == 0) {
//				assertNotEditingField();
//				break;
//			}
			assertIsEditingField(rowNum, colNum);
		}
		while (rowNum < model.getNumComponents() - 1) {
			triggerActionInCellEditor(KeyEvent.VK_DOWN);
			waitForPostedSwingRunnables();
			rowNum++;
			clickTableCell(getTable(), rowNum, colNum, 2);
//			DataTypeComponent dtc = model.getComponent(rowNum);
//			if (dtc.getOffset() == ((StackEditorModel) model).getParameterOffset()) {
//				assertIsEditingField(rowNum, colNum);
//				break;
//			}
			assertNotEditingField();
		}
		while (rowNum < model.getNumComponents() - 1) {
			triggerActionInCellEditor(KeyEvent.VK_DOWN);
			waitForPostedSwingRunnables();
			rowNum++;
			assertIsEditingField(rowNum, colNum);
		}
		triggerActionInCellEditor(KeyEvent.VK_DOWN);
		waitForPostedSwingRunnables();
		assertNotEditingField();
		assertEquals(model.getNumComponents() - 1, model.getRow());
	}

	@Test
	public void testCantLeaveEditField() throws Exception {
		init(SIMPLE_STACK);
		int dtColNum = model.getDataTypeColumn();

		assertNotEditingField();
		DataType dt = getDataType(2);
		clickTableCell(getTable(), 2, dtColNum, 2);
		assertIsEditingField(2, dtColNum);

		deleteAllInCellEditor();
		typeInCellEditor("dwordAm");

		// Bad value prevents move to next.
		triggerActionInCellEditor(KeyEvent.VK_TAB);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents move to previous.
		triggerActionInCellEditor(InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents move to next.
		triggerActionInCellEditor(0, KeyEvent.VK_UP);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents move to next.
		triggerActionInCellEditor(0, KeyEvent.VK_DOWN);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents action performed.
		enter();
		assertIsEditingField(2, dtColNum);

		// Bad value allows escape.
		escape();
		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertEquals(getDataType(2), dt);
	}

//	public void testEditComponentDataType() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "Char[3][2][4]";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		clickTableCell(getTable(), 1, column, 2);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals(str, model.getValueAt(1, column));
//		assertEquals(24, model.getLength());
//		assertEquals(24, getDataType(1).getLength());
//	}

//	public void testEditComponentDataTypeInvalid() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String invalidString = "AbCdEfG_12345.,/\\";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		clickTableCell(getTable(), 1, column, 2);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(invalidString);
//		enter();
//			
//		assertIsEditingField();
//		assertStatus("Unrecognized data type of \""+invalidString+"\" entered.");
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals("Word", model.getValueAt(1, column));
//		assertEquals(8, model.getLength());
//		assertEquals(dt, getDataType(1));
//			
//		escape();
//		assertNotEditingField();
//		assertEquals(dt, getDataType(1));
//	}

//	public void testEditDtDoesntFit() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "char[3][2][4]";
//		DataType dt = getDataType(2);
//			
//		assertEquals(29, model.getLength());
//		assertEquals(2, dt.getLength());
//		clickTableCell(getTable(), 2, column, 2);
//		assertIsEditingField();
//		assertEquals(2, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//			
//		assertIsEditingField();
//		escape();
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(2, model.getMinIndexSelected());
//		assertEquals(dt.getDisplayName(), model.getValueAt(2, column));
//		assertEquals(29, model.getLength());
//		assertEquals(dt.getLength(), getDataType(2).getLength());
//	}

//	public void testEditDtSameSize() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "float";
//		DataType dt = getDataType(3);
//		assertEquals(29, model.getLength());
//		assertEquals(4, dt.getLength());
//		assertEquals("dword", getDataType(3).getDisplayName());
//			
//		clickTableCell(getTable(), 3, column, 2);
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(3, model.getMinIndexSelected());
//		assertEquals(str, model.getValueAt(3, column));
//		assertEquals(29, model.getLength());
//		assertEquals(4, getDataType(3).getLength());
//	}

//	public void testEditToBasicPointer() throws Exception {
//		NumberInputDialog dialog;
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "Pointer";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		Point pt = getPoint(1, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//		assertIsEditingField();
//			
//		dialog = (NumberInputDialog)env.waitForWindow(NumberInputDialog.class, 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 6);
//		dialog.dispose();
//		dialog = null;
//
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals(str, model.getValueAt(1, column));
//		assertEquals(8, model.getLength());
//		assertEquals(-1, getDataType(1).getLength());
//		assertEquals(6, model.getComponent(1).getLength());
//	}

//	public void testEditToVariableDataType() throws Exception {
//		NumberInputDialog dialog;
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "String[3]";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		Point pt = getPoint(1, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//		assertIsEditingField();
//			
//		dialog = (NumberInputDialog)env.waitForWindow(NumberInputDialog.class, 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 15);
//		dialog.dispose();
//		dialog = null;
//
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals(str, model.getValueAt(1, column));
//		assertEquals(45, model.getLength());
//		assertEquals(45, getDataType(1).getLength());
//		assertEquals(45, model.getComponent(1).getLength());
//	}

//	public void testEditToComplexPointerArray() throws Exception {
//		NumberInputDialog dialog;
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "Unicode**[5][2]";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		Point pt = getPoint(1, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//		assertIsEditingField();
//			
//		dialog = (NumberInputDialog)env.waitForWindow("Specify number of Unicode * * bytes", 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 4);
//		dialog.dispose();
//		dialog = null;
//
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals("Unicode * *[5][2]", model.getValueAt(1, column));
//		assertEquals(40, model.getLength());
//		assertEquals(40, getDataType(1).getLength());
//		assertEquals(40, model.getComponent(1).getLength());
//	}

//	public void testEditPointerToPointer() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "simpleStructure * *";
//		DataType dt = getDataType(5);
//		int len = model.getLength();
//		int num = model.getNumComponents();
//			
//		assertEquals(-1, dt.getLength());
//		assertEquals(4, model.getComponent(5).getLength());
//		Point pt = getPoint(5, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(5, model.getRow());
//		assertEquals(column, model.getColumn());
//		
//		endKey();	
//		type("*");
//		enter();
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(5, model.getMinIndexSelected());
//		assertEquals(str, model.getValueAt(5, column));
//		assertEquals(len, model.getLength());
//		assertEquals(num, model.getNumComponents());
//		assertEquals(-1, dt.getLength());
//		assertEquals(4, model.getComponent(5).getLength());
//	}

//	public void testEditComponentDataTypeSmaller() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, getDataType(1).getLength());
//		Point pt = getPoint(1, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		endKey();
//		typeKey(0, KeyEvent.VK_OPEN_BRACKET, '[');
//		typeKey(0, KeyEvent.VK_5, '5');
//		typeKey(0, KeyEvent.VK_CLOSE_BRACKET, ']');
//		typeKey(0, KeyEvent.VK_ENTER);
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals("Word[5]", model.getValueAt(1, column));
//		assertEquals(10, model.getLength());
//		assertEquals(10, getDataType(1).getLength());
//	}

//	public void testEditComponentDataTypeBigger() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//			
//		assertEquals(87, model.getLength());
//		assertEquals(87, getDataType(12).getLength());
//		Point pt = getPoint(12, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(12, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		endKey();
//		typeKey(0, KeyEvent.VK_BACK_SPACE, '\b');
//		typeKey(0, KeyEvent.VK_BACK_SPACE, '\b');
//		typeKey(0, KeyEvent.VK_2, '2');
//		typeKey(0, KeyEvent.VK_CLOSE_BRACKET, ']');
//		typeKey(0, KeyEvent.VK_ENTER);
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(12, model.getMinIndexSelected());
//		assertEquals("simpleStructure[2]", model.getValueAt(12, column));
//		assertEquals(58, model.getLength());
//		assertEquals(58, getDataType(12).getLength());
//	}

//	public void testEditComponentDataTypeComplex() throws Exception {
//		NumberInputDialog dialog;
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "complexUnion***[3][3]";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		Point pt = getPoint(1, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//		assertIsEditingField();
//			
//		dialog = (NumberInputDialog)env.waitForWindow("Specify number of complexUnion * * * bytes", 1000);
//		assertNotNull(dialog);
//		okInput(dialog, 4);
//		dialog.dispose();
//		dialog = null;
//
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals("complexUnion * * *[3][3]", model.getValueAt(1, column));
//		assertEquals(36, model.getLength());
//		assertEquals(36, getDataType(1).getLength());
//		assertEquals(36, model.getComponent(1).getLength());
//	}

//	public void testEditDataTypeWithPE() throws Exception {
//		init(SIMPLE_STACK);
//		int column = model.getDataTypeColumn();
//		String str = "PE";
//		DataType dt = getDataType(1);
//			
//		assertEquals(8, model.getLength());
//		assertEquals(2, dt.getLength());
//		Point pt = getPoint(1, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(1, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		deleteAllInCellEditor();
//		type(str);
//		enter();
//			
//		assertIsEditingField();
//		assertStatus("Dynamic data types are not allowed in a composite data type.");
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(1, model.getMinIndexSelected());
//		assertEquals("Word", model.getValueAt(1, column));
//		assertEquals(8, model.getLength());
//		assertEquals(dt, getDataType(1));
//	}

//	public void testEditComponentName() throws Exception {
//		init(SIMPLE_STACK);
//			
//		int column = model.getNameColumn();
//		int num = model.getNumComponents();
//		int len = model.getLength();
//		assertNull(getComment(3));
//		Point pt = getPoint(3, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		endKey();
//		type("Wow");
//		enter();
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(3, model.getMinIndexSelected());
//		assertEquals("Wow", getFieldName(3));
//		assertEquals(len, model.getLength());
//		assertEquals(num, model.getNumComponents());
//	}

//	public void testEditComponentComment() throws Exception {
//		init(SIMPLE_STACK);
//			
//		int column = model.getCommentColumn();
//		int num = model.getNumComponents();
//		int len = model.getLength();
//		assertNull(getComment(3));
//		Point pt = getPoint(3, column);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(column, model.getColumn());
//			
//		endKey();
//		type("My comment.");
//		enter();
//			
//		assertNotEditingField();
//		assertEquals(1, model.getNumSelectedRows());
//		assertEquals(3, model.getMinIndexSelected());
//		assertEquals("My comment.", getComment(3));
//		assertEquals(len, model.getLength());
//		assertEquals(num, model.getNumComponents());
//	}

//	public void testEditNextField() throws Exception {
//		init(SIMPLE_STACK);
//		int rowNum = 3;
//		int colNum = model.getNameColumn();
//		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_TAB, 0);
//			
//		Point pt = getPoint(rowNum, colNum);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//			
//		deleteAllInCellEditor();
//		type("Component_3");
//		typeKey(ks);
//			
//		assertIsEditingField();
//		assertEquals(rowNum, model.getRow());
//		assertEquals(colNum+1, model.getColumn());
//		assertEquals("Component_3", getFieldName(rowNum));
//			
//		escape();
//		assertNotEditingField();
//	}

//	public void testEditPreviousField() throws Exception {
//		init(SIMPLE_STACK);
//		int rowNum = 3;
//		int colNum = model.getNameColumn();
//		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_TAB, KeyEvent.SHIFT_DOWN_MASK);
//			
//		Point pt = getPoint(rowNum, colNum);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//			
//		deleteAllInCellEditor();
//		type("Component_3");
//		typeKey(ks);
//			
//		assertIsEditingField();
//		assertEquals(rowNum, model.getRow());
//		assertEquals(colNum-1, model.getColumn());
//		assertEquals("Component_3", getFieldName(rowNum));
//			
//		escape();
//		assertNotEditingField();
//	}

//	public void testEditUpField() throws Exception {
//		init(SIMPLE_STACK);
//		int rowNum = 3;
//		int colNum = model.getNameColumn();
//		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_UP, 0);
//			
//		Point pt = getPoint(rowNum, colNum);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//			
//		deleteAllInCellEditor();
//		type("Component_3");
//		typeKey(ks);
//			
//		assertIsEditingField();
//		assertEquals(rowNum-1, model.getRow());
//		assertEquals(colNum, model.getColumn());
//		assertEquals("Component_3", getFieldName(rowNum));
//			
//		escape();
//		assertNotEditingField();
//	}

//	public void testEditDownField() throws Exception {
//		init(SIMPLE_STACK);
//		int rowNum = 3;
//		int colNum = model.getNameColumn();
//		KeyStroke ks = KeyStroke.getKeyStroke(KeyEvent.VK_DOWN, 0);
//			
//		Point pt = getPoint(rowNum, colNum);
//		clickMouse(getTable(), 1, pt.x, pt.y, 2, 0);
//		assertIsEditingField();
//			
//		deleteAllInCellEditor();
//		type("Component_3");
//		typeKey(ks);
//			
//		assertIsEditingField();
//		assertEquals(rowNum+1, model.getRow());
//		assertEquals(colNum, model.getColumn());
//		assertEquals("Component_3", getFieldName(rowNum));
//			
//		escape();
//		assertNotEditingField();
//	}

//	public void testEditReorderedColumns() throws Exception {
//		init(simpleStructure, pgmBbCat);
//		final JTable table = getTable();
//		runSwing(new Runnable() {
//			public void run() {
//				table.moveColumn(4, 1); // moves Name after Offset before Length
//				table.moveColumn(5, 3); // moves Comment after Length before Mnemonic
//			}
//		});
//		// Order is now Offset Name Length Comment Mnemonic DataType
//			
//		clickTableCell(getTable(), 3, 1, 2); // Edit name of dword
//			
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(model.getNameColumn(), model.getColumn());
//
//		type("Component_3");
//		type("\t");
//			
//		assertEquals("Component_3", getFieldName(3));
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(model.getCommentColumn(), model.getColumn());
//
//		type("My new comment.");
//		type("\t");
//			
//		assertEquals("My new comment.", getComment(3));
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(model.getDataTypeColumn(), model.getColumn());
//
//		deleteAllInCellEditor();
//		type("float");
//		type("\t");
//			
//		assertEquals("float", getDataType(3).getDisplayName());
//		assertIsEditingField();
//		assertEquals(4, model.getRow());
//		assertEquals(model.getNameColumn(), model.getColumn());
//
//		typeActionKey(0, KeyEvent.VK_DOWN);
//		waitForPostedSwingRunnables();
//
//		assertIsEditingField();
//		assertEquals(5, model.getRow());
//		assertEquals(model.getNameColumn(), model.getColumn());
//		assertNull(getFieldName(5));
//
//		typeActionKey(0, KeyEvent.VK_UP);
//		waitForPostedSwingRunnables();
//
//		assertIsEditingField();
//		assertEquals(4, model.getRow());
//		assertEquals(model.getNameColumn(), model.getColumn());
//		assertNull(getFieldName(4));
//			
//		typeActionKey(KeyEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
//		waitForPostedSwingRunnables();
//
//		assertIsEditingField();
//		assertEquals(3, model.getRow());
//		assertEquals(model.getDataTypeColumn(), model.getColumn());
//
//		escape();
//		assertNotEditingField();
//	}

}
