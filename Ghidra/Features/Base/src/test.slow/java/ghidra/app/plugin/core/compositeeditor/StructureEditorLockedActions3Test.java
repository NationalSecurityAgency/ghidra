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

import java.awt.Component;

import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.dialogs.InputDialog;
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class StructureEditorLockedActions3Test extends AbstractStructureEditorLockedActionsTest {

	/**
	 * Edit an existing structure and create a structure from a selection. Use the conflicting 
	 * names followed by a good non-default name.
	 * @throws Exception if the test throws an exception
	 */
	@Test
	public void testExistingDtEditInternalStructureOnSelectionVariousNames() throws Exception {
		init(simpleStructure, pgmBbCat);

		assertEquals(8, getModel().getNumComponents());

		setSelection(new int[] { 1, 2, 3 });
		DataType originalDt1 = getDataType(1);
		DataType originalDt2 = getDataType(2);
		DataType originalDt3 = getDataType(3);
		DataType originalDt4 = getDataType(4);

		// Make selected components into internal structure.
		invoke(createInternalStructureAction, false);

		// Specify name for structure.
		InputDialog inputDialog = waitForDialogComponent(InputDialog.class);
		assertNotNull(inputDialog);

		JTextField[] textFields = (JTextField[]) getInstanceField("textFields", inputDialog);
		JTextField textField = textFields[0];
		triggerText(textField, "simpleStructure");
		pressButtonByText(inputDialog, "OK");
		waitForSwing();

		assertEquals("The name cannot match the external structure name.",
			getStatusText(inputDialog));
		assertTrue(inputDialog.isShowing());

		setText(textField, "simpleUnion");
		pressButtonByText(inputDialog, "OK");
		assertEquals("A data type named \"simpleUnion\" already exists.",
			getStatusText(inputDialog));
		assertTrue(inputDialog.isShowing());

		setText(textField, "Foo");
		pressButtonByText(inputDialog, "OK");
		assertEquals(" ", getStatusText(inputDialog));
		assertFalse(inputDialog.isShowing());
		waitForTasks();

		assertEquals(6, getModel().getNumComponents());
		Structure internalStruct = (Structure) getDataType(1);
		assertEquals("Foo", internalStruct.getName());
		assertEquals(3, internalStruct.getNumComponents());
		DataType internalDt0 = internalStruct.getComponent(0).getDataType();
		DataType internalDt1 = internalStruct.getComponent(1).getDataType();
		DataType internalDt2 = internalStruct.getComponent(2).getDataType();
		assertTrue(internalDt0.isEquivalent(originalDt1));
		assertTrue(internalDt1.isEquivalent(originalDt2));
		assertTrue(internalDt2.isEquivalent(originalDt3));
		assertEquals(7, getDataType(1).getLength());
		assertEquals(7, getModel().getComponent(1).getLength());
		assertEquals(originalDt4, getDataType(2));
		assertEquals(29, getModel().getLength());
	}

	@Test
	public void testFavoritesFixedOnComponent() {
		init(simpleStructure, pgmBbCat);

		DataType dt = getModel().getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		setSelection(new int[] { 3 });
		assertTrue(!getDataType(3).isEquivalent(dt));
		invoke(fav);
		assertEquals(11, getModel().getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt));
		checkSelection(new int[] { 3, 4, 5, 6 });
	}

	@Test
	public void testFavoritesFixedOnMultiple() {
		init(simpleStructure, pgmBbCat);

		DataType dt = getModel().getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = getModel().getNumComponents();
		setSelection(new int[] { 2, 3 });
		DataType dt4 = getDataType(4);
		invoke(fav);
		assertTrue(getDataType(3).isEquivalent(dt));
		assertTrue(getDataType(8).isEquivalent(dt4));
		checkSelection(new int[] { 2, 3, 4, 5, 6, 7 });
		assertEquals(num + 4, getModel().getNumComponents());
	}

	@Test
	public void testFavoritesFixedOnUndefined() {
		init(simpleStructure, pgmBbCat);

		DataType dt = getModel().getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = getModel().getNumComponents();
		setSelection(new int[] { 0 });
		assertTrue(!getDataType(0).isEquivalent(dt));
		invoke(fav);
		assertEquals(num, getModel().getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		checkSelection(new int[] { 0 });
	}

	@Test
	public void testFavoritesOnPointer() throws Exception {
		init(complexStructure, pgmBbCat);

		DataType dt = getModel().getOriginalDataTypeManager().getDataType("/word");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		assertEquals(325, getModel().getLength());
		assertEquals(23, getModel().getNumComponents());
		setSelection(new int[] { 3 });
		invoke(fav);
		assertEquals(325, getModel().getLength());
		assertEquals(23, getModel().getNumComponents());
		assertTrue(((Pointer) getDataType(3)).getDataType().isEquivalent(dt));
		assertEquals("word *32", getDataType(3).getName());
		assertEquals(4, getLength(3));
	}

	@Test
	public void testFavoritesVariableOnBlank() throws Exception {
		NumberInputDialog dialog;
		init(simpleStructure, pgmBbCat);

		DataType dt = getModel().getOriginalDataTypeManager().getDataType("/string");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		assertEquals(29, getModel().getLength());
		assertEquals(8, getModel().getNumComponents());
		setSelection(new int[] { 4 });
		invoke(fav, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 8);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(29, getModel().getLength());
		assertEquals(8, getModel().getNumComponents());
		assertTrue(getDataType(4).isEquivalent(dt));
		assertEquals(8, getLength(4));
	}

	@Test
	public void testNoFitPointerOnFixedDt() throws Exception {
		init(simpleStructure, pgmBbCat);
		model.clearComponents(new int[] { 2 });

		DataType dt1 = getDataType(1);
		setSelection(new int[] { 1 });
		invoke(pointerAction);
		assertEquals(9, getModel().getNumComponents());
		assertEquals("byte", getDataType(1).getName());
		assertEquals(getDataType(1), dt1);
		assertEquals("pointer doesn't fit.", getModel().getStatus());
		assertEquals(1, getDataType(1).getLength());
		assertEquals(1, getModel().getComponent(1).getLength());
		assertEquals(DataType.DEFAULT, getDataType(2));
		assertEquals(29, model.getLength());
	}

	//	public void testCancelPointerOnFixedDt() throws Exception {
	//		provider = new StructureEditorProvider(plugin, program, complexStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//		NumberInputDialog dialog;
	//		int num = getModel().getNumComponents();
	//		
	//		setSelection(new int[] {1});
	//		DataType dt1 = getDataType(1);
	//		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
	//		invoke(pointerAction, false);
	//		dialog = (NumberInputDialog)env.waitForDialogComponent(NumberInputDialog.class, 1000);
	//		assertNotNull(dialog);
	//		cancelInput(dialog, 2);
	//		dialog.dispose();
	//		dialog = null;
	//		assertEquals(num, getModel().getNumComponents());
	//		assertEquals("word", getDataType(1).getName());
	//		assertTrue(getDataType(1).isEquivalent(dt1));
	//		assertEquals(2, getModel().getComponent(1).getLength());
	//	}

	//	public void testCreatePointerOnPointer() throws Exception {
	//		provider = new StructureEditorProvider(plugin, program, complexStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//		NumberInputDialog dialog;
	//		int num = getModel().getNumComponents();
	//		
	//		setSelection(new int[] {2});
	//		DataType dt2 = getDataType(2);
	//		assertTrue(getDataType(2).isEquivalent(new PointerDataType()));
	//		assertEquals(4, getModel().getComponent(2).getLength());
	//		invoke(pointerAction);
	//		assertEquals(num, getModel().getNumComponents());
	//		assertEquals("pointer *", getDataType(2).getName());
	//		assertTrue(((Pointer)getDataType(2)).getDataType().isEquivalent(dt2));
	//		assertEquals(-1, getDataType(2).getLength());
	//		assertEquals(4, getModel().getComponent(2).getLength());
	//	}

	//	public void testCreatePointerOnVariableDataType() throws Exception {
	//		emptyStructure.add(new ByteDataType());
	//		emptyStructure.add(new StringDataType(), 5);
	//		emptyStructure.add(new WordDataType());
	//		
	//		provider = new StructureEditorProvider(plugin, program, emptyStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//		NumberInputDialog dialog;
	//		int num = getModel().getNumComponents();
	//		
	//		setSelection(new int[] {1});
	//		DataType dt1 = getDataType(1);
	//		assertTrue(getDataType(1).isEquivalent(new StringDataType()));
	//		assertEquals(5, getModel().getComponent(1).getLength());
	//		invoke(pointerAction, false);
	//		dialog = (NumberInputDialog)env.waitForDialogComponent(NumberInputDialog.class, 1000);
	//		assertNotNull(dialog);
	//		okInput(dialog, 8);
	//		dialog.dispose();
	//		dialog = null;
	//		assertEquals(num, getModel().getNumComponents());
	//		assertEquals("String *", getDataType(1).getName());
	//		assertTrue(((Pointer)getDataType(1)).getDataType().isEquivalent(dt1));
	//		assertEquals(-1, getDataType(1).getLength());
	//		assertEquals(8, getModel().getComponent(1).getLength());
	//	}

	//	public void testCreatePointerOnStructPointer() {
	//		provider = new StructureEditorProvider(plugin, program, complexStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//		NumberInputDialog dialog;
	//		int num = getModel().getNumComponents();
	//		
	//		setSelection(new int[] {5});
	//		DataType dt5 = getDataType(5);
	//		assertEquals(4, getModel().getComponent(5).getLength());
	//		invoke(pointerAction);
	//		assertEquals(num, getModel().getNumComponents());
	//		assertEquals("simpleStructure * *", getDataType(5).getName());
	//		assertTrue(((Pointer)getDataType(5)).getDataType().isEquivalent(dt5));
	//		assertEquals(-1, getDataType(5).getLength());
	//		assertEquals(4, getModel().getComponent(5).getLength());
	//	}

	//	public void testCreatePointerOnArray() throws Exception {
	//		provider = new StructureEditorProvider(plugin, program, complexStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//		NumberInputDialog dialog;
	//		int num = getModel().getNumComponents();
	//		
	//		setSelection(new int[] {10});
	//		DataType dt10 = getDataType(10);
	//		invoke(pointerAction, false);
	//		dialog = (NumberInputDialog)env.waitForDialogComponent(NumberInputDialog.class, 1000);
	//		assertNotNull(dialog);
	//		okInput(dialog, 2);
	//		dialog.dispose();
	//		dialog = null;
	//		assertEquals(num, getModel().getNumComponents());
	//		assertEquals("byte[7] *", getDataType(10).getName());
	//		assertTrue(((Pointer)getDataType(10)).getDataType().isEquivalent(dt10));
	//		assertEquals(-1, getDataType(10).getLength());
	//		assertEquals(2, getModel().getComponent(10).getLength());
	//	}

	//	public void testCreatePointerOnTypedef() throws Exception {
	//		provider = new StructureEditorProvider(plugin, program, complexStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//		NumberInputDialog dialog;
	//		int num = getModel().getNumComponents();
	//		
	//		setSelection(new int[] {15});
	//		DataType dt15 = getDataType(15);
	//		invoke(pointerAction, false);
	//		dialog = (NumberInputDialog)env.waitForDialogComponent(NumberInputDialog.class, 1000);
	//		assertNotNull(dialog);
	//		okInput(dialog, 4);
	//		dialog.dispose();
	//		dialog = null;
	//		assertEquals(num, getModel().getNumComponents());
	//		assertEquals("simpleStructureTypedef *", getDataType(15).getName());
	//		assertTrue(((Pointer)getDataType(15)).getDataType().isEquivalent(dt15));
	//		assertEquals(4, getModel().getComponent(15).getLength());
	//	}

	//	public void testApplyComponentChange() throws Exception {
	//		provider = new StructureEditorProvider(plugin, program, complexStructure,  pgmTestCat, dtmService);
	//		model = (StructureEditorModel)provider.getModel();
	//		getActions();
	//
	//		setSelection(new int[] {3,4});
	//		getModel().deleteSelectedComponents();
	//		DataType viewCopy = getModel().viewComposite.copy();
	//		
	//		assertTrue(!complexStructure.isEquivalent(getModel().viewComposite));
	//		assertTrue(viewCopy.isEquivalent(getModel().viewComposite));
	//		invoke(applyAction);
	//		assertTrue(viewCopy.isEquivalent(complexStructure));
	//		assertTrue(viewCopy.isEquivalent(getModel().viewComposite));
	//		assertTrue(complexStructure.isEquivalent(getModel().viewComposite));
	//	}

	@Test
	public void testShowNumbersInHex() {
		init(complexStructure, pgmTestCat);
		CompEditorPanel panel = (CompEditorPanel) provider.getComponent();

		assertEquals("", model.getStatus());

		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("47", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("45", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("325", ((JTextField) findComponentByName(panel, "Total Length")).getText());

		invoke(hexNumbersAction);
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x2f", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("0x2d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x145", ((JTextField) findComponentByName(panel, "Total Length")).getText());

		invoke(hexNumbersAction);
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("47", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("45", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("325", ((JTextField) findComponentByName(panel, "Total Length")).getText());
	}

	@Test
	public void testSizeEnablement() throws Exception {
		init(complexStructure, pgmTestCat);
		Component component = findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(component);
		assertEquals(true, component.isEnabled());
	}
}
