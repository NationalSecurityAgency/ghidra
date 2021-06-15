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

import javax.swing.JTable;
import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import generic.test.ConcurrentTestExceptionHandler;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;

public class UnionEditorCellEditTest extends AbstractUnionEditorTest {

	@Test
	public void testF2EditKey() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int colNum = model.getDataTypeColumn();

		setSelection(new int[] { 0 });
		checkSelection(new int[] { 0 });
		assertTrue(editFieldAction.isEnabled());
		triggerActionKey(getTable(), editFieldAction);
		assertIsEditingField(0, colNum);

		escape();// Remove the choose data type dialog.
		assertNotEditingField();
	}

	@Test
	public void testEditFieldOnLengthColumn() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int colNum = model.getLengthColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnMnemonicColumn() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int colNum = model.getMnemonicColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnDataTypeColumn() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);

		escape();// Remove the choose data type dialog.
		Thread.sleep(500);
		assertNotEditingField();
	}

	@Test
	public void testEditFieldOnNameColumn() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
	}

	@Test
	public void testEditFieldOnCommentColumn() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int colNum = model.getCommentColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);
	}

	@Test
	public void testEditFieldOnBlankRow() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int rowNum = model.getNumComponents();
		int dtColNum = model.getDataTypeColumn();

		for (int colNum = 0; colNum < model.getNumFields(); colNum++) {
			clickTableCell(getTable(), rowNum, colNum, 2);
			assertEquals(rowNum, model.getRow());
			if (colNum == dtColNum) {
				assertIsEditingField(rowNum, colNum);
				escape();
			}
			else {
				assertNotEditingField();
			}
		}
	}

	@Test
	public void testCantLeaveEditField() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int dtColNum = model.getDataTypeColumn();

		assertNotEditingField();
		DataType dt = getDataType(2);
		clickTableCell(getTable(), 2, dtColNum, 2);
		assertIsEditingField(2, dtColNum);

		endKey();
		typeInCellEditor("Ab\bm");

		// Bad value prevents move to next.
		triggerActionInCellEditor(KeyEvent.VK_TAB);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents move to previous.
		triggerActionInCellEditor(InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents move to next.
		triggerActionInCellEditor(KeyEvent.VK_UP);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents move to next.
		triggerActionInCellEditor(KeyEvent.VK_DOWN);
		assertIsEditingField(2, dtColNum);

		// Bad value prevents action performed.
		triggerActionInCellEditor(KeyEvent.VK_ENTER);
		assertIsEditingField(2, dtColNum);

		// Bad value allows escape.
		triggerActionInCellEditor(KeyEvent.VK_ESCAPE);
		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertEquals(getDataType(2), dt);
	}

	@Test
	public void testEditComponentDataType() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		String str = "char[3][2][4]";
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText(str);
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString(str, 1, column);
		assertEquals(24, model.getLength());
		assertEquals(24, getDataType(1).getLength());
	}

	@Test
	public void testEditComponentDataTypeInvalid() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		String invalidString = "AbCdEfG_12345.,/\\";
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText(invalidString);

		enter();
		ConcurrentTestExceptionHandler.clear();// prevent this from failing the test after tearDown()

		waitForSwing();

		assertIsEditingField(1, column);
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("word", 1, column);
		assertEquals(8, model.getLength());
		assertEquals(dt, getDataType(1));

		escape();
		assertNotEditingField();
		assertEquals(dt, getDataType(1));
	}

	@Test
	public void testEditToBasicPointer() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText("pointer");

		pressEnterToSelectChoice();
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("pointer", 1, column);
		assertEquals(8, model.getLength());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testEditToSizedPointer() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText("pointer32");

		pressEnterToSelectChoice();
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("pointer32", 1, column);
		assertEquals(8, model.getLength());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testEditToVariableDataType() throws Exception {

		init(simpleUnion, pgmBbCat, false);

		NumberInputDialog dialog;
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText("string");
		enter();

		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 15);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("string", 1, column);
		assertEquals(15, model.getLength());
		dt = getDataType(1);
		assertEquals("string", dt.getDisplayName());
		assertEquals(15, model.getComponent(1).getLength());
	}

	@Test
	public void testEditToFunctionDefinitionDataType() throws Exception {

		init(simpleUnion, pgmBbCat, false);

		startTransaction("addExternal");
		ExternalLocation extLoc = program.getExternalManager().addExtFunction(Library.UNKNOWN,
			"extLabel", null, SourceType.USER_DEFINED);
		Function function = extLoc.createFunction();
		endTransaction(true);

		String name = function.getName();
		FunctionDefinitionDataType functionDefinitionDataType =
			new FunctionDefinitionDataType(function, true);
		FunctionDefinition functionDefinition = null;
		boolean commit = false;
		txId = program.startTransaction("Modify Program");
		try {
			programDTM = program.getListing().getDataTypeManager();
			functionDefinition =
				(FunctionDefinition) programDTM.resolve(functionDefinitionDataType, null);
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}
		assertNotNull(functionDefinition);

		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText(name);
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString(name + " *", 1, column);
		assertEquals(8, model.getLength());
		dt = getDataType(1);
		assertEquals(name + " *", dt.getDisplayName());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testEditToComplexPointerArray() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText("unicode**[5][2]");
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("unicode * *[5][2]", 1, column);
		assertEquals(40, model.getLength());
		dt = getDataType(1);
		assertEquals(40, dt.getLength());
		assertEquals("unicode * *[5][2]", dt.getDisplayName());
		assertEquals(40, model.getComponent(1).getLength());
	}

	@Test
	public void testEditPointerToPointer() throws Exception {
		init(complexUnion, pgmTestCat, false);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(5);
		assertEquals("simpleStructure *", dt.getDisplayName());
		int len = model.getLength();
		int num = model.getNumComponents();

		assertEquals(4, dt.getLength());
		assertEquals(4, model.getComponent(5).getLength());
		clickTableCell(getTable(), 5, column, 2);
		assertIsEditingField(5, column);

		endKey();
		type("*");
		enter();
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(5, model.getMinIndexSelected());
		assertCellString("simpleStructure * *", 5, column);
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
		dt = getDataType(5);
		assertEquals(4, dt.getLength());
		assertEquals("simpleStructure * *", dt.getDisplayName());
		assertEquals(4, model.getComponent(5).getLength());
	}

	@Test
	public void testEditComponentDataTypeSmaller() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();

		assertEquals(8, model.getLength());
		assertEquals(2, getDataType(1).getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		endKey();
		typeInCellEditor("[5]\n");

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("word[5]", 1, column);
		assertEquals(10, model.getLength());
		assertEquals(10, getDataType(1).getLength());
	}

	@Test
	public void testEditComponentDataTypeBigger() throws Exception {
		init(complexUnion, pgmTestCat, false);
		int column = model.getDataTypeColumn();

		assertEquals(87, model.getLength());
		assertEquals(87, getDataType(12).getLength());
		clickTableCell(getTable(), 12, column, 2);
		assertIsEditingField(12, column);

		endKey();
		typeInCellEditor("\b\b2]\n");

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(12, model.getMinIndexSelected());
		assertCellString("simpleStructure[2]", 12, column);
		assertEquals(58, model.getLength());
		assertEquals(58, getDataType(12).getLength());
	}

	@Test
	public void testEditComponentDataTypeComplex() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText("complexUnion***[3][3]");
		enter();
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("complexUnion * * *[3][3]", 1, column);
		assertEquals(36, model.getLength());
		dt = getDataType(1);
		assertEquals(36, dt.getLength());
		assertEquals("complexUnion * * *[3][3]", dt.getDisplayName());
		assertEquals(36, model.getComponent(1).getLength());
	}

	@Test
	public void testEditDataTypeNotSelf() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		String str = "simpleUnion";
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText(str);
		enter();// pick the DT

		assertEquals("Data type \"" + str + "\" can't contain itself.", model.getStatus());
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("word", 1, column);
		assertEquals(8, model.getLength());
		assertEquals(dt, getDataType(1));
	}

	@Test
	public void testEditDataTypeSelfPointer() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText("simpleUnion**");// double pointer to avoid conflict with the existing 'simpleUnion *'
		enter();// accept our typed text as the value we want to use
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("simpleUnion * *", 1, column);
		assertEquals(8, model.getLength());
		dt = getDataType(1);
		assertEquals(4, dt.getLength());
		assertEquals("simpleUnion * *", dt.getDisplayName());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testEditDataTypeWithFactory() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		String str = "PE";
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText(str);
		enter();
		waitForSwing();

		assertIsEditingField(1, column);
		assertEquals("Factory data-type not allowed", model.getStatus());
		escape();

		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("word", 1, column);
		assertEquals(8, model.getLength());
		assertEquals(dt, getDataType(1));
	}

	@Test
	public void testEditDataTypeWithDynamic() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int column = model.getDataTypeColumn();
		String str = "GIF-Image";
		DataType dt = getDataType(1);

		assertEquals(8, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 1, column, 2);
		assertIsEditingField(1, column);

		setText(str);
		enter();
		waitForSwing();

		assertIsEditingField(1, column);
		assertEquals("non-sizable data-type not allowed", model.getStatus());
		escape();

		assertEquals(1, model.getNumSelectedRows());
		assertEquals(1, model.getMinIndexSelected());
		assertCellString("word", 1, column);
		assertEquals(8, model.getLength());
		assertEquals(dt, getDataType(1));
	}

	@Test
	public void testEditComponentName() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		int column = model.getNameColumn();
		int num = model.getNumComponents();
		int len = model.getLength();
		assertNull(getComment(3));
		clickTableCell(getTable(), 3, column, 2);
		assertIsEditingField(3, column);

		setText("Wow");
		enter();
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertEquals("Wow", getFieldName(3));
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
	}

	@Test
	public void testEditComponentComment() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		int column = model.getCommentColumn();
		int num = model.getNumComponents();
		int len = model.getLength();
		assertNull(getComment(3));
		clickTableCell(getTable(), 3, column, 2);
		assertIsEditingField(3, column);

		String comment = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "abcdefghijklmnopqrstuvwxyz" +
			"`1234567890-=[]\\;',./" + "~!@#$%^&*()_+{}|:\"<>?";
		setText(comment);
		enter();
		waitForSwing();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertEquals(comment, getComment(3));
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
	}

	@Test
	public void testEditNextField() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), rowNum, colNum, 2);
		assertIsEditingField(rowNum, colNum);

		setText("Component_3");

		triggerActionInCellEditor(KeyEvent.VK_TAB);

		assertIsEditingField(rowNum, colNum + 1);
		assertEquals("Component_3", getFieldName(rowNum));

		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditPreviousField() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), rowNum, colNum, 2);
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
		init(simpleUnion, pgmBbCat, false);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), rowNum, colNum, 2);
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
		init(simpleUnion, pgmBbCat, false);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), rowNum, colNum, 2);
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

		init(simpleUnion, pgmBbCat, false);
		int rowNum = 3;
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), rowNum, colNum, 2);
		assertIsEditingField(rowNum, colNum);

		// this test has to use the slower 'type()' method to ensure that the drop-down
		// window appears, which allows the correct type to be selected
		deleteAllInCellEditor();
		type("simpleStructure");
		enter();
		waitForSwing();

		assertNotEditingField();
		DataType newDt = getDataType(rowNum);
		assertEquals("simpleStructure", newDt.getName());
		assertEquals(29, newDt.getLength());
		assertEquals(29, getLength(rowNum));
		assertEquals(29, model.getLength());
	}

	@Test
	public void testEditReorderedColumns() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		final JTable table = getTable();
		runSwing(() -> {
			table.moveColumn(3, 0);// moves Name before Length
			table.moveColumn(4, 2);// moves Comment after Length before Mnemonic
		});
		// Order is now Name Length Comment Mnemonic DataType

		doubleClickTableCell(2, 0);// Edit name of dword

		assertIsEditingField(2, model.getNameColumn());

		setText("Component_2");
		type("\t");

		assertEquals("Component_2", getFieldName(2));
		assertIsEditingField(2, model.getCommentColumn());

		setText("My new comment.");
		type("\t");

		assertEquals("My new comment.", getComment(2));
		assertIsEditingField(2, model.getDataTypeColumn());

		setText("float");
		enter();

		assertEquals("float", getDataType(2).getDisplayName());
		clickTableCell(getTable(), 3, 0, 2);
		assertIsEditingField(3, model.getNameColumn());

		triggerActionInCellEditor(KeyEvent.VK_DOWN);
		waitForSwing();

		assertIsEditingField(4, model.getNameColumn());
		assertNull(getFieldName(4));

		triggerActionInCellEditor(KeyEvent.VK_UP);
		waitForSwing();

		assertIsEditingField(3, model.getNameColumn());
		assertNull(getFieldName(3));

		triggerActionInCellEditor(InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
		waitForSwing();

		assertIsEditingField(2, model.getDataTypeColumn());

		escape();
		assertNotEditingField();
	}

	protected void setText(String s) {
		JTextField tf = getActiveEditorTextField();
		setText(tf, s);
	}
}
