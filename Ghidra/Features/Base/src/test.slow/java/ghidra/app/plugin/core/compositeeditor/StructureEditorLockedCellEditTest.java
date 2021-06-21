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
import java.io.File;

import javax.swing.JTable;

import org.junit.*;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;

public class StructureEditorLockedCellEditTest extends AbstractStructureEditorTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		File dir = getDebugFileDirectory();
		dir.mkdirs();
	}

	protected void init(Structure dt, final Category cat) {

		boolean commit = true;
		startTransaction("Structure Editor Test Initialization");

		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = (Structure) dt.clone(dataTypeManager);
			}

			CategoryPath categoryPath = cat.getCategoryPath();
			if (!dt.getCategoryPath().equals(categoryPath)) {
				try {
					dt.setCategoryPath(categoryPath);
				}
				catch (DuplicateNameException e) {
					commit = false;
					Assert.fail(e.getMessage());
				}
			}
		}
		finally {
			endTransaction(commit);
		}

		final Structure structDt = dt;
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, structDt, false));
			model = provider.getModel();
		});
		waitForSwing();

		getActions();
	}

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

		clickTableCell(getTable(), 1, colNum, 2);
		assertStatus("Offset field is not editable");
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnLengthColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getLengthColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertStatus("Length field is not editable");
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnMnemonicColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getMnemonicColumn();

		clickTableCell(getTable(), 1, colNum, 2);
		assertStatus("Mnemonic field is not editable");
		assertNotEditingField();
		assertEquals(1, model.getRow());
	}

	@Test
	public void testEditFieldOnDataTypeColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getDataTypeColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertIsEditingField(0, colNum);

		runSwing(() -> getTable().getCellEditor().stopCellEditing());// close the editor

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);

		escape();// Remove the choose data type dialog.

		assertNotEditingField();
	}

	@Test
	public void testEditFieldOnNameColumn() throws Exception {
		init(simpleStructure, pgmBbCat);
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertNotEditingField();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
	}

	@Test
	public void testEditFieldOnCommentColumn() throws Exception {
		init(simpleStructure, pgmBbCat);

		int colNum = model.getCommentColumn();

		clickTableCell(getTable(), 0, colNum, 2);
		assertNotEditingField();

		clickTableCell(getTable(), 1, colNum, 2);
		assertIsEditingField(1, colNum);
	}

	@Test
	public void testUpOnEditField() throws Exception {
		init(simpleStructure, pgmBbCat);
		int rowNum = model.getNumComponents() - 1;
		int colNum = model.getDataTypeColumn() + 1;

		clickTableCell(getTable(), rowNum, colNum, 2);
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

		clickTableCell(getTable(), rowNum, colNum, 2);
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

		assertNotEditingField();
		DataType dt = getDataType(2);
		clickTableCell(getTable(), 2, model.getDataTypeColumn(), 2);
		assertIsEditingField(2, model.getDataTypeColumn());

		endKey();
		typeInCellEditor("Ab\bm");

		// Bad value prevents action performed.
		triggerActionKey(getTable(), 0, KeyEvent.VK_ENTER);
		assertIsEditingField(2, model.getDataTypeColumn());

		// Bad value allows escape.
		triggerActionKey(getTable(), 0, KeyEvent.VK_ESCAPE);
		triggerActionKey(getTable(), 0, KeyEvent.VK_ESCAPE);
		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertEquals(getDataType(2), dt);
	}

	@Test
	public void testEditComponentDataTypeInvalid() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String invalidString = "AbCdEfG_12345.,/\\";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		setText(invalidString);
		enter();

		assertIsEditingField(2, column);

		escape();

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
	public void testEditDtDoesntFit() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "char[3][2][4]";
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		setText(str);
		enter();

		assertIsEditingField(2, column);
		escape();
		escape();
		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString(dt.getDisplayName(), 2, column);
		assertEquals(29, model.getLength());
		assertEquals(dt.getLength(), getDataType(2).getLength());
	}

	@Test
	public void testEditDtSameSize() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "float";
		DataType dt = getDataType(3);
		assertEquals(29, model.getLength());
		assertEquals(4, dt.getLength());
		assertEquals("dword", getDataType(3).getDisplayName());

		clickTableCell(getTable(), 3, column, 2);
		assertIsEditingField(3, column);

		setText(str);
		enter();// pick the DT

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertCellString(str, 3, column);
		assertEquals(29, model.getLength());
		assertEquals(4, getDataType(3).getLength());
	}

	@Test
	public void testEditComponentDataTypeSmaller() throws Exception {
		init(complexStructure, pgmTestCat);
		int column = model.getDataTypeColumn();

		assertEquals(325, model.getLength());
		assertEquals(87, getDataType(16).getLength());
		clickTableCell(getTable(), 16, column, 2);
		assertIsEditingField(16, column);

		endKey();
		typeInCellEditor("\b\b2]\n");

		assertNotEditingField();
		assertEquals(30, model.getNumSelectedRows());
		assertEquals(16, model.getMinIndexSelected());
		assertCellString("simpleStructure[2]", 16, column);
		assertEquals(325, model.getLength());
		assertEquals(58, getDataType(16).getLength());
	}

	@Test
	public void testEditComponentDataTypeBigger() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		model.clearComponents(new int[] { 3, 4, 5 });

		assertEquals(29, model.getLength());
		assertEquals(2, getDataType(2).getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		endKey();
		type("[5]");
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("word[5]", 2, column);
		assertEquals(29, model.getLength());
		assertEquals(10, getDataType(2).getLength());
	}

	@Test
	public void testEditToBasicPointer() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "undefined *";
		int row = 3;
		int dtLength = 4;
		DataType dt = getDataType(row);

		assertEquals(29, model.getLength());
		assertEquals(dtLength, dt.getLength());
		clickTableCell(getTable(), row, column, 2);
		assertIsEditingField(row, column);

		setText(str);
		enter();// Selects dt and removes data type list and closes the editor dialog
		assertNotEditingField();

		assertEquals(1, model.getNumSelectedRows());
		assertEquals(row, model.getMinIndexSelected());
		assertCellString("undefined *", row, column);
		assertEquals(29, model.getLength());
		assertEquals(dtLength, getDataType(row).getLength());
		assertEquals(dtLength, model.getComponent(row).getLength());
	}

	@Test
	public void testEditToVariableDataType() throws Exception {
		NumberInputDialog dialog;
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "string";
		DataType dt = getDataType(2);
		model.clearComponents(new int[] { 3, 4 });

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		setText(str);
		enter();

		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		okInput(dialog, 14);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString(str, 2, column);
		assertEquals(29, model.getLength());
		assertEquals(-1, getDataType(2).getLength());
		assertEquals(14, model.getComponent(2).getLength());
	}

	@Test
	public void testEditToFunctionDefinitionDataType() throws Exception {
		init(simpleStructure, pgmBbCat);

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
		DataType dt = functionDefinition;
		model.clearComponents(new int[] { 3 });

		assertEquals(29, model.getLength());
		assertEquals(-1, dt.getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		setText(name);
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString(name + " *", 2, column);// Was function definition converted to a pointer?
		assertEquals(29, model.getLength());
		assertEquals(4, getDataType(2).getLength());
		assertEquals(4, model.getComponent(2).getLength());
	}

	@Test
	public void testEditToComplexPointerArray() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "unicode**[3][2]";
		DataType dt = getDataType(2);
		model.clearComponents(new int[] { 3, 4, 5, 6 });

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		setText(str);
		pressEnterToSelectChoice();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(2, model.getMinIndexSelected());
		assertCellString("unicode * *[3][2]", 2, column);
		assertEquals(6, model.getNumComponents());
		assertEquals(29, model.getLength());
		assertEquals(24, getDataType(2).getLength());
		assertEquals(24, model.getComponent(2).getLength());
	}

	@Test
	public void testEditPointerToPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		int column = model.getDataTypeColumn();
		String mnemonicStr = "simpleStructure * *";
		DataType dt = getDataType(6);
		int len = model.getLength();
		int num = model.getNumComponents();

		assertEquals(4, dt.getLength());
		assertEquals(4, model.getComponent(6).getLength());
		clickTableCell(getTable(), 6, column, 2);
		assertIsEditingField(6, column);

		endKey();
		type("*");
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(6, model.getMinIndexSelected());
		assertCellString(mnemonicStr, 6, column);
		assertEquals(len, model.getLength());
		assertEquals(num, model.getNumComponents());
		assertEquals(4, dt.getLength());
		assertEquals(4, model.getComponent(6).getLength());
	}

	@Test
	public void testEditDataTypeNotSelf() throws Exception {

		Structure testStruct = new StructureDataType("testStruct", 20);
		testStruct.setPackingEnabled(false);

		DataTypeManager dtm = program.getDataTypeManager();
		txId = program.startTransaction("Add testStruct");
		try {
			testStruct = (Structure) dtm.resolve(testStruct, null);
		}
		finally {
			program.endTransaction(txId, true);
		}

		init(testStruct, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "testStruct";
		DataType dt = getDataType(0);

		assertEquals(20, model.getLength());
		assertEquals(DataType.DEFAULT, dt);
		clickTableCell(getTable(), 0, column, 2);
		assertIsEditingField(0, column);

		setText(str);
		enter();// pick the DT

		assertStatus("Data type \"" + str + "\" can't contain itself.");
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(0, model.getMinIndexSelected());
		assertCellString("undefined", 0, column);
		assertEquals(20, model.getLength());
		assertEquals(dt, getDataType(0));
	}

	@Test
	public void testEditDataTypeSelfPointer() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "simpleStructure *32";
		DataType dt = getDataType(3);

		assertEquals(29, model.getLength());
		assertEquals(4, dt.getLength());
		clickTableCell(getTable(), 3, column, 2);
		assertIsEditingField(3, column);

		setText(str);
		enter();// pick the DT 

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertCellString("simpleStructure *", 3, column);
		assertEquals(29, model.getLength());
		assertEquals(4, getDataType(3).getLength());
		assertEquals(4, model.getComponent(3).getLength());
	}

	@Test
	public void testEditDataTypeWithPE() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		DataType dt = getDataType(2);

		assertEquals(29, model.getLength());
		assertEquals(2, dt.getLength());
		clickTableCell(getTable(), 2, column, 2);
		assertIsEditingField(2, column);

		setText("PE");// factory data-type
		enter();// pick the DT

		// DataTypeSelectionDialog should prevent Factory data-type
		assertIsEditingField(2, column);

		setText("GIF-Image");// dynamic data-type
		enter();// pick the DT

		// DataTypeSelectionDialog should prevent Non-sizable Dynamic data-type
		assertIsEditingField(2, column);

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
		clickTableCell(getTable(), 3, column, 2);
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
		clickTableCell(getTable(), 3, column, 2);
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
		init(simpleStructure, pgmBbCat);
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
		init(simpleStructure, pgmBbCat);
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
		init(simpleStructure, pgmBbCat);
		int rowNum = 3;
		int colNum = model.getNameColumn();

		clickTableCell(getTable(), rowNum, colNum, 2);
		assertIsEditingField(rowNum, colNum);

		setText("Component_3");
		triggerActionInCellEditor(KeyEvent.VK_DOWN);

		assertIsEditingField(rowNum + 1, colNum);
		assertEquals(rowNum + 1, model.getRow());
		assertEquals(colNum, model.getColumn());
		assertEquals("Component_3", getFieldName(rowNum));

		escape();
		assertNotEditingField();
	}

	@Test
	public void testEditReorderedColumns() throws Exception {
		init(simpleStructure, pgmBbCat);
		final JTable table = getTable();
		runSwing(() -> {
			table.moveColumn(4, 1);// moves Name after Offset before Length
			table.moveColumn(5, 3);// moves Comment after Length before Mnemonic
		});
		// Order is now Offset Name Length Comment Mnemonic DataType

		doubleClickTableCell(3, 1);// Edit name of dword

		assertIsEditingField(3, model.getNameColumn());

		setText("Component_3");
		type("\t");

		assertEquals("Component_3", getFieldName(3));
		assertIsEditingField(3, model.getCommentColumn());

		setText("My new comment.");
		type("\t");

		assertEquals("My new comment.", getComment(3));
		assertIsEditingField(3, model.getDataTypeColumn());

		setText("float");
		enter();// pick the DT

		assertEquals("float", getDataType(3).getDisplayName());
		clickTableCell(getTable(), 4, 1, 2);
		assertIsEditingField(4, model.getNameColumn());

		triggerActionInCellEditor(KeyEvent.VK_DOWN);
		assertIsEditingField(5, model.getNameColumn());
		assertNull(getFieldName(5));

		triggerActionInCellEditor(KeyEvent.VK_UP);
		assertIsEditingField(4, model.getNameColumn());
		assertNull(getFieldName(4));

		triggerActionInCellEditor(InputEvent.SHIFT_DOWN_MASK, KeyEvent.VK_TAB);
		assertIsEditingField(3, model.getDataTypeColumn());

		escape();
		assertNotEditingField();
	}
}
