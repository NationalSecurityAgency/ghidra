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

import java.awt.event.KeyEvent;
import java.util.Arrays;

import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class UnionEditorActions1Test extends AbstractUnionEditorTest {

	@Test
	public void testEmptyUnionEditorState() {
		init(emptyUnion, pgmRootCat, false);

		assertEquals(0, model.getNumComponents());// no components
		assertEquals(1, model.getRowCount());// blank row
		assertEquals(0, model.getLength());// size is 0
		assertTrue(model.hasChanges());// new empty union that hasn't been saved yet.
		assertTrue(model.isValidName());// name should be valid
		assertEquals(emptyUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(emptyUnion.getName(), model.getCompositeName());
		assertEquals(pgmRootCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");

		// Check enablement.
		CompositeEditorTableAction[] pActions = provider.getActions();
		for (int i = 0; i < pActions.length; i++) {
			if ((pActions[i] instanceof FavoritesAction) ||
				(pActions[i] instanceof CycleGroupAction) ||
				(pActions[i] instanceof EditFieldAction) ||
				(pActions[i] instanceof PointerAction) ||
				(pActions[i] instanceof HexNumbersAction) || (actions[i] instanceof ApplyAction)) {
				checkEnablement(pActions[i], true);
			}
			else {
				checkEnablement(pActions[i], false);
			}
		}
	}

	@Test
	public void testNonEmptyUnionEditorState() {
		init(simpleUnion, pgmBbCat, false);

		assertEquals(simpleUnion.getNumComponents(), model.getNumComponents());
		assertEquals(simpleUnion.getNumComponents() + 1, model.getRowCount());
		assertEquals(simpleUnion.getLength(), model.getLength());
		assertFalse(model.hasChanges());// no Changes yet
		assertTrue(model.isValidName());// name should be valid
		assertEquals(simpleUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { model.getNumComponents() });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(8);
		assertEquals(simpleUnion.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());

		// Check enablement on blank line selected.
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testFirstComponentSelectedEnablement() {
		init(simpleUnion, pgmBbCat, false);
		getActions();

		// Check enablement on first component selected.
		setSelection(new int[] { 0 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) ||
				(action instanceof ShowComponentPathAction) || (action instanceof MoveDownAction) ||
				(action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof DeleteAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testCentralComponentSelectedEnablement() {
		init(simpleUnion, pgmBbCat, false);
		getActions();

		// Check enablement on central component selected.
		setSelection(new int[] { 1 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) ||
				(action instanceof ShowComponentPathAction) || (action instanceof MoveUpAction) ||
				(action instanceof MoveDownAction) || (action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof DeleteAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testLastComponentSelectedEnablement() {
		init(simpleUnion, pgmBbCat, false);
		getActions();

		// Check enablement on last component selected.
		setSelection(new int[] { model.getNumComponents() - 1 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) ||
				(action instanceof ShowComponentPathAction) || (action instanceof MoveUpAction) ||
				(action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof DeleteAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testContiguousSelectionEnablement() {
		init(complexUnion, pgmTestCat, false);
		getActions();

		// Check enablement on a contiguous multi-component selection.
		setSelection(new int[] { 2, 3, 4 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction)// enabled to show message
				|| (action instanceof MoveDownAction) || (action instanceof MoveUpAction) ||
				(action instanceof DeleteAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNonContiguousSelectionEnablement() {
		init(complexUnion, pgmTestCat, false);

		getActions();

		// Check enablement on a non-contiguous multi-component selection.
		setSelection(new int[] { 2, 3, 6, 7 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof DeleteAction) || (action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testFavoritesFixedOnBlankLine() {
		init(emptyUnion, pgmRootCat, false);

		getActions();

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		assertEquals(0, model.getLength());
		assertEquals(0, model.getNumComponents());
		invoke(fav);
		assertEquals(1, model.getLength());
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
	}

	@Test
	public void testFavoritesFixedOnComponent() {
		init(simpleUnion, pgmBbCat, false);

		getActions();

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = model.getNumComponents();
		setSelection(new int[] { 3 });
		assertFalse(getDataType(3).isEquivalent(dt));
		invoke(fav);
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt));
		checkSelection(new int[] { 3 });
	}

	@Test
	public void testFavoritesFixedOnMultiple() {
		init(simpleUnion, pgmBbCat, false);

		getActions();

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = model.getNumComponents();
		setSelection(new int[] { 3, 4, 5 });
		DataType dt6 = getDataType(6);
		invoke(fav);
		assertTrue(getDataType(3).isEquivalent(dt));
		assertTrue(getDataType(4).isEquivalent(dt6));
		checkSelection(new int[] { 3 });
		assertEquals(num - 2, model.getNumComponents());
	}

	@Test
	public void testFavoritesVariableOnBlank() throws Exception {
		init(emptyUnion, pgmRootCat, false);

		getActions();
		NumberInputDialog dialog;

		DataType dt = model.getOriginalDataTypeManager().getDataType("/string");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		assertEquals(0, model.getLength());
		assertEquals(0, model.getNumComponents());
		invoke(fav, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 7);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(7, model.getLength());
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(7, getLength(0));
	}

	@Test
	public void testCycleGroupOnBlankLine() {
		init(emptyUnion, pgmRootCat, false);

		getActions();

		assertEquals(0, model.getNumComponents());
		checkSelection(new int[] { 0 });

		CycleGroupAction action = getCycleGroup(new ByteDataType());
		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		assertEquals(1, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new WordDataType()));
		assertEquals(2, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new DWordDataType()));
		assertEquals(4, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new QWordDataType()));
		assertEquals(8, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		assertEquals(1, getLength(0));
		checkSelection(new int[] { 0 });

		CycleGroupAction floatAction = getCycleGroup(new FloatDataType());
		invoke(floatAction);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new FloatDataType()));
		assertEquals(4, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(floatAction);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new DoubleDataType()));
		assertEquals(8, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(floatAction);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new FloatDataType()));
		assertEquals(4, getLength(0));
		checkSelection(new int[] { 0 });
	}

	@Test
	public void testCancelCycleGroupOnComponent() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		getActions();
		NumberInputDialog dialog;

		DataType dt1 = getDataType(1);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);
		assertEquals(num, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), dt3);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		cancelInput(dialog);
		dialog = null;
		assertEquals(num, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), dt3);
	}

	@Test
	public void testCycleGroupOnMultiLine() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		getActions();

		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 1, 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals(num, model.getNumComponents());
		checkSelection(new int[] { 1, 2 });
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt3);
		assertFalse("".equals(model.getStatus()));
	}

	@Test
	public void testEditComponentAction() throws Exception {
		init(complexUnion, pgmTestCat, false);

		assertEquals("", model.getStatus());

		setSelection(new int[] { 20 });
		String complexTitle = getProviderSubTitle(complexUnion);
		String simpleTitle = getProviderSubTitle(simpleStructure);
		assertTrue("Couldn't find editor = " + complexTitle,
			isProviderShown(tool.getToolFrame(), "Union Editor", complexTitle));
		assertFalse(isProviderShown(tool.getToolFrame(), "Structure Editor", simpleTitle));
		invoke(editComponentAction);
		assertEquals("", model.getStatus());
		assertTrue("Couldn't find editor = " + complexTitle,
			isProviderShown(tool.getToolFrame(), "Union Editor", complexTitle));
		assertTrue("Couldn't find editor = " + simpleTitle,
			isProviderShown(tool.getToolFrame(), "Structure Editor", simpleTitle));
	}

	@Test
	public void testEditFieldOnBlankLine() throws Exception {
		init(emptyUnion, pgmRootCat, false);
		assertFalse(model.isEditingField());

		triggerActionKey(getTable(), editFieldAction);
		assertTrue(model.isEditingField());
		assertEquals(0, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		triggerActionKey(getTable(), 0, KeyEvent.VK_ESCAPE);
	}

	@Test
	public void testEditFieldOnComponent() throws Exception {
		init(complexUnion, pgmTestCat, false);

		setSelection(new int[] { 3 });
		assertFalse(model.isEditingField());
		invoke(editFieldAction);
		assertTrue(model.isEditingField());
		assertEquals(3, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		JTextField tf = getActiveEditorTextField();
		triggerText(tf, "Ab\b\b\t");
		assertTrue(model.isEditingField());
		assertEquals(3, model.getRow());

		escape();// Remove the choose data type dialog.
		Thread.sleep(500);
		assertNotEditingField();
	}

	@Test
	public void testShowComponentPathAction() {
		init(complexUnion, pgmTestCat, false);

		assertEquals("", model.getStatus());

		setSelection(new int[] { 0 });
		invoke(showComponentPathAction);
		String pathMessage = "byte is in category \"" + pgmRootCat.getCategoryPathName() + "\".";
		assertTrue(pathMessage.equals(model.getStatus()));

		setSelection(new int[] { 20 });
		invoke(showComponentPathAction);
		assertEquals("simpleStructure is in category \"" + pgmBbCat.getCategoryPathName() + "\".",
			model.getStatus());
		assertFalse(listener.getBeep());
	}

	@Test
	public void testMoveDownAction() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		setSelection(new int[] { 2, 3, 4, 5 });
		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt6 = getDataType(6);
		assertTrue(model.isMoveDownAllowed());

		invoke(moveDownAction);
		checkSelection(new int[] { 3, 4, 5, 6 });
		assertEquals(7, model.getNumComponents());
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt6);
		assertEquals(getDataType(3), dt2);
		assertEquals(getDataType(4), dt3);
		assertEquals(getDataType(5), dt4);
		assertEquals(getDataType(6), dt5);
		assertFalse(model.isMoveDownAllowed());
	}

	@Test
	public void testMoveUpAction() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		setSelection(new int[] { 2, 3, 4 });
		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt6 = getDataType(6);
		assertTrue(model.isMoveUpAllowed());

		invoke(moveUpAction);
		checkSelection(new int[] { 1, 2, 3 });
		assertEquals(7, model.getNumComponents());
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt2);
		assertEquals(getDataType(2), dt3);
		assertEquals(getDataType(3), dt4);
		assertEquals(getDataType(4), dt1);
		assertEquals(getDataType(5), dt5);
		assertEquals(getDataType(6), dt6);
		assertTrue(model.isMoveUpAllowed());

		invoke(moveUpAction);
		checkSelection(new int[] { 0, 1, 2 });
		assertEquals(7, model.getNumComponents());
		assertEquals(getDataType(0), dt2);
		assertEquals(getDataType(1), dt3);
		assertEquals(getDataType(2), dt4);
		assertEquals(getDataType(3), dt0);
		assertEquals(getDataType(4), dt1);
		assertEquals(getDataType(5), dt5);
		assertEquals(getDataType(6), dt6);
		assertFalse(model.isMoveUpAllowed());
	}

	@Test
	public void testDuplicateAction() {
		init(complexUnion, pgmTestCat, false);

		int num = model.getNumComponents();
		int len = model.getLength();

		// Duplicate Byte
		setSelection(new int[] { 0 });
		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		invoke(duplicateAction);
		num++;
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		checkSelection(new int[] { 0 });
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt0);
		assertEquals(getDataType(2), dt1);

		// Duplicate simpleStructure*  (pointer of size 4)
		setSelection(new int[] { 6 });
		dt0 = getDataType(6);
		dt1 = getDataType(7);
		invoke(duplicateAction);
		num++;
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		checkSelection(new int[] { 6 });
		assertEquals(getDataType(6), dt0);
		assertEquals(getDataType(7), dt0);
		assertEquals(getDataType(8), dt1);

		// Can't duplicate blank line
		listener.clearStatus();
		setSelection(new int[] { model.getNumComponents() });
		assertFalse(runSwing(() -> duplicateAction.isEnabled()));
	}

	@Test
	public void testDeleteOneCompNoSizeChange() {
		init(complexUnion, pgmTestCat, false);

		int len = model.getLength();
		setSelection(new int[] { 3 });// simpleUnion == 8 bytes
		invoke(deleteAction);
		waitForTasks();
		assertEquals(model.getLength(), len);
		assertEquals(1, model.getNumSelectedComponentRows());
		assertTrue(Arrays.equals(new int[] { 3 }, model.getSelectedComponentRows()));
	}

	@Test
	public void testDeleteOneCompWithSizeChange() {
		init(complexUnion, pgmTestCat, false);

		setSelection(new int[] { 12 });// simpleStructure[3] == 87 bytes
		invoke(deleteAction);
		waitForTasks();
		assertEquals(56, model.getLength());// simpleStructure*[7] == 56 bytes
		assertEquals(1, model.getNumSelectedComponentRows());
		assertTrue(Arrays.equals(new int[] { 12 }, model.getSelectedComponentRows()));
	}

	@Test
	public void testDeleteContiguousAction() {
		init(complexUnion, pgmTestCat, false);

		DataType dt3 = getDataType(3);
		DataType dt10 = getDataType(10);
		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 4, 5, 6, 7, 8, 9 });
		invoke(deleteAction);
		waitForTasks();
		assertEquals(num - 6, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals(getDataType(3), dt3);
		assertEquals(getDataType(4), dt10);
		assertEquals(1, model.getNumSelectedComponentRows());
		assertTrue(Arrays.equals(new int[] { 4 }, model.getSelectedComponentRows()));
	}

	@Test
	public void testDeleteNonContiguousAction() {
		init(complexUnion, pgmTestCat, false);

		DataType dt3 = getDataType(3);
		DataType dt10 = getDataType(10);
		DataType dt18 = getDataType(18);
		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 4, 5, 6, 7, 8, 9, 19, 20 });
		invoke(deleteAction);
		waitForTasks();
		assertEquals(num - 8, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertEquals(getDataType(3), dt3);
		assertEquals(getDataType(4), dt10);
		assertEquals(getDataType(12), dt18);
		assertEquals(1, model.getNumSelectedComponentRows());
		assertTrue(Arrays.equals(new int[] { 4 }, model.getSelectedComponentRows()));
	}

	@Test
	public void testCancelArrayOnFixedDt() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		NumberInputDialog dialog;
		int num = model.getNumComponents();

		setSelection(new int[] { 3 });
		DataType dt3 = getDataType(3);

		// Cancel the array dialog
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		cancelInput(dialog);
		dialog = null;
		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt3));
		assertEquals(dt3.getLength(), model.getComponent(3).getLength());
	}

	@Test
	public void testCreatePointerOnFixedDt() throws Exception {
		init(complexUnion, pgmTestCat, false);
		int num = model.getNumComponents();

		setSelection(new int[] { 1 });
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		invoke(pointerAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer", getDataType(1).getDisplayName());
		assertNull(((Pointer) getDataType(1)).getDataType());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testCreatePointerOnPointer() throws Exception {
		init(complexUnion, pgmTestCat, false);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		DataType dt2 = getDataType(2);
		assertTrue(getDataType(2) instanceof Pointer);
		assertEquals(4, model.getComponent(2).getLength());
		invoke(pointerAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("undefined * *", getDataType(2).getDisplayName());
		assertTrue(((Pointer) getDataType(2)).getDataType().isEquivalent(dt2));
		assertEquals(4, getDataType(2).getLength());
		assertEquals(4, model.getComponent(2).getLength());
	}

	@Test
	public void testCreatePointerOnVariableDataType() throws Exception {
		emptyUnion.add(new ByteDataType());
		emptyUnion.add(new StringDataType(), 5);
		emptyUnion.add(new WordDataType());
		init(emptyUnion, pgmRootCat, false);
		int num = model.getNumComponents();

		setSelection(new int[] { 1 });
		assertTrue(getDataType(1).isEquivalent(new StringDataType()));
		assertEquals(5, model.getComponent(1).getLength());
		invoke(pointerAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("pointer", getDataType(1).getDisplayName());
		assertNull(((Pointer) getDataType(1)).getDataType());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());

		setSelection(new int[] { 1 });
		CycleGroupAction charCycleAction = getCycleGroup(CharDataType.dataType);
		invoke(charCycleAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("char *", getDataType(1).getDisplayName());
		assertTrue(((Pointer) getDataType(1)).getDataType().isEquivalent(CharDataType.dataType));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());

		invoke(charCycleAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("string *", getDataType(1).getDisplayName());
		assertTrue(((Pointer) getDataType(1)).getDataType().isEquivalent(StringDataType.dataType));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
	}

	@Test
	public void testCreatePointerOnStructPointer() {
		init(complexUnion, pgmTestCat, false);
		int num = model.getNumComponents();

		setSelection(new int[] { 5 });
		DataType dt5 = getDataType(5);
		assertEquals(4, model.getComponent(5).getLength());
		invoke(pointerAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("simpleStructure * *", getDataType(5).getDisplayName());
		assertTrue(((Pointer) getDataType(5)).getDataType().isEquivalent(dt5));
		assertEquals(4, getDataType(5).getLength());
		assertEquals(4, model.getComponent(5).getLength());
	}

	@Test
	public void testApplyComponentChange() throws Exception {
		init(complexUnion, pgmTestCat, false);

		setSelection(new int[] { 3, 4 });
		model.deleteSelectedComponents();
		DataType viewCopy = model.viewComposite.clone(null);

		assertFalse(complexUnion.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		invoke(applyAction);
		assertTrue(viewCopy.isEquivalent(complexUnion));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertTrue(complexUnion.isEquivalent(model.viewComposite));
	}

	@Test
	public void testApplyNameChange() throws Exception {
		init(complexUnion, pgmTestCat, false);

		model.setName("FooBarUnion");
		DataType viewCopy = model.viewComposite.clone(null);

		assertTrue(complexUnion.isEquivalent(model.viewComposite));
		assertEquals("FooBarUnion", model.getCompositeName());
		assertEquals("complexUnion", complexUnion.getName());
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		invoke(applyAction);
		assertTrue(viewCopy.isEquivalent(complexUnion));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertTrue(complexUnion.isEquivalent(model.viewComposite));
		assertEquals(complexUnion.getName(), model.getCompositeName());
		assertEquals("FooBarUnion", model.getCompositeName());
		assertEquals("FooBarUnion", complexUnion.getName());
	}

	// hard to create dataType with invalid name
	public void testApplyWithInvalidName() throws Exception {
		init(complexUnion, pgmTestCat, false);

		CompEditorPanel panel = (CompEditorPanel) getPanel();
		JTextField nameField = panel.nameTextField;
		assertTrue(model.isValidName());

		triggerActionKey(nameField, 0, KeyEvent.VK_END);
		triggerText(nameField, "#/$");
		DataType viewCopy = model.viewComposite.clone(null);

		assertFalse(model.isValidName());
		assertEquals("complexUnion#/$", nameField.getText());
		assertEquals("complexUnion#/$", model.getCompositeName());
		assertEquals("complexUnion", complexUnion.getName());
		assertTrue(complexUnion.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertEquals(model.getStatus(), "complexUnion#/$ is not a valid name.");
		invoke(applyAction);
		assertEquals(model.getStatus(), "Name is not valid.");
		assertTrue(complexUnion.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertTrue(model.getStatus().length() > 0);
		assertEquals("complexUnion#/$", model.getCompositeName());
		assertEquals("complexUnion", complexUnion.getName());
	}

	@Test
	public void testApplyDescriptionChange() throws Exception {
		init(complexUnion, pgmTestCat, false);

		String desc = "This is a sample description.";
		model.setDescription(desc);
		DataType viewCopy = model.viewComposite.clone(null);

		assertEquals(desc, model.getDescription());
		assertEquals("A complex union.", complexUnion.getDescription());
		assertTrue(complexUnion.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		invoke(applyAction);
		assertTrue(viewCopy.isEquivalent(complexUnion));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertEquals(desc, model.getDescription());
		assertEquals(desc, complexUnion.getDescription());
	}

	@Test
	public void testApplyOfEmptyUnion() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6 });
		invoke(deleteAction);
		waitForTasks();
		DataType viewCopy = model.viewComposite.clone(null);

		assertFalse(simpleUnion.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertEquals(0, model.getNumComponents());
		assertEquals(model.getStatus(), "");
		invoke(applyAction);
		assertTrue(simpleUnion.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
	}

	@Test
	public void testShowNumbersInHex() {
		init(complexUnion, pgmTestCat, false);
		assertEquals("", model.getStatus());
		CompEditorPanel panel = (CompEditorPanel) provider.getComponent();

		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("45", model.getValueAt(11, model.getLengthColumn()));
		assertEquals("87", ((JTextField) findComponentByName(panel, "Total Length")).getText());

		invoke(hexNumbersAction);
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x2d", model.getValueAt(11, model.getLengthColumn()));
		assertEquals("0x57", ((JTextField) findComponentByName(panel, "Total Length")).getText());

		invoke(hexNumbersAction);
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("45", model.getValueAt(11, model.getLengthColumn()));
		assertEquals("87", ((JTextField) findComponentByName(panel, "Total Length")).getText());
	}
}
