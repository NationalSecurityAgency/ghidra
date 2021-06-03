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
import java.awt.Window;
import java.awt.event.KeyEvent;

import javax.swing.JTextField;

import org.junit.Assert;
import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UsrException;

public class StructureEditorUnlockedActions5Test
		extends AbstractStructureEditorUnlockedActionsTest {

	@Test
	public void testApplyDuplicateName() throws Exception {
		init(complexStructure, pgmTestCat);

		try {
			model.setName("complexUnion");
			Assert.fail("Should have gotten Duplicate name exception");
		}
		catch (DuplicateNameException e) {
			// good
		}
	}

	@Test
	public void testApplyNameChange() throws Exception {
		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			try {
				model.setName("FooBarStructure");
			}
			catch (UsrException e) {
				failWithException("Unexpected error", e);
			}
		});
		DataType viewCopy = model.viewComposite.clone(null);

		assertEquals("FooBarStructure", model.getCompositeName());
		assertEquals("complexStructure", complexStructure.getName());
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		invoke(applyAction);
		assertTrue(viewCopy.isEquivalent(complexStructure));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertEquals(complexStructure.getName(), model.getCompositeName());
		assertEquals("FooBarStructure", model.getCompositeName());
		assertEquals("FooBarStructure", complexStructure.getName());
	}

	@Test
	public void testApplyOfEmptyStructure() throws Exception {
		init(simpleStructure, pgmBbCat);

		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6, 7 });
		invoke(deleteAction);
		DataType viewCopy = model.viewComposite.clone(null);

		assertTrue(!simpleStructure.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertEquals(0, model.getNumComponents());
		assertEquals(model.getStatus(), "");
		invoke(applyAction);
		assertTrue(simpleStructure.isEquivalent(model.viewComposite));
		assertTrue(simpleStructure.isNotYetDefined());
		assertTrue(simpleStructure.isZeroLength());
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		// Is now allowed
		//		assertEquals(
		//			"/aa/bb/simpleStructure is contained in /aa/bb/simpleStructure[3] and can't be changed to a zero size data type.",
		//			model.getStatus());
	}

	//  Ignoring test for now.  Don't know how to make the name invalid
	public void testApplyWithInvalidName() throws Exception {
		init(complexStructure, pgmTestCat);

		CompEditorPanel panel = (CompEditorPanel) getPanel();
		JTextField nameField = panel.nameTextField;
		assertTrue(model.isValidName());
		triggerActionKey(nameField, 0, KeyEvent.VK_END);
		triggerText(nameField, "#$/");
		DataType viewCopy = model.viewComposite.clone(null);

		assertTrue(!model.isValidName());
		assertEquals("complexStructure#$/", nameField.getText());
		assertEquals("complexStructure#$/", model.getCompositeName());
		assertEquals("complexStructure", complexStructure.getName());
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertEquals(model.getStatus(), "complexStructure#$/ is not a valid name.");
		invoke(applyAction);
		assertEquals(model.getStatus(), "Name is not valid.");
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertTrue(model.getStatus().length() > 0);
		assertEquals("complexStructure#$/", model.getCompositeName());
		assertEquals("complexStructure", complexStructure.getName());
	}

	@Test
	public void testCancelArrayOnFixedDt() throws Exception {
		init(simpleStructure, pgmBbCat);
		NumberInputDialog dialog;
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		DataType dt2 = getDataType(2);
		assertTrue(dt2 instanceof WordDataType);

		// Cancel the array dialog
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		cancelInput(dialog);

		assertEquals(num, model.getNumComponents());
		assertTrue(getDataType(2).isEquivalent(dt2));
		assertEquals(dt2.getLength(), model.getComponent(2).getLength());
	}

	@Test
	public void testCancelCycleGroupOnComponent() throws Exception {
		init(simpleStructure, pgmBbCat);
		NumberInputDialog dialog;

		DataType dt1 = getDataType(1);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);// CHange word to char followed by 1 undefined
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), DataType.DEFAULT);
		assertEquals(getDataType(4), dt3);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		cancelInput(dialog);

		assertEquals(num + 1, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), DataType.DEFAULT);
		assertEquals(getDataType(4), dt3);
	}

	@Test
	public void testCannotDeleteDefinedComp() {
		init(complexStructure, pgmTestCat);

		int len = model.getLength();
		int num = model.getNumComponents();
		setSelection(new int[] { 3 });
		assertEquals("", model.getStatus());
		invoke(deleteAction);// Delete the 4 byte pointer
		assertEquals("", model.getStatus());
		assertEquals(len - 4, model.getLength());
		assertEquals(1, model.getNumSelectedComponentRows());
		assertEquals(num - 1, model.getNumComponents());
	}

	@Test
	public void testChangeSizeBigger() throws Exception {
		init(complexStructure, pgmTestCat);
		int originalLength = complexStructure.getLength();
		int newLength = originalLength + 5;

		assertEquals(originalLength, model.getLength());

		Component component = findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(component);
		assertTrue(component instanceof JTextField);
		((JTextField) component).setText(Integer.toString(newLength));
		triggerActionKey(component, 0, KeyEvent.VK_ENTER);

		waitForSwing();
		assertEquals(newLength, model.getLength());
		invoke(applyAction);
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertEquals(newLength, complexStructure.getLength());
	}

	@Test
	public void testChangeSizeInvalid() throws Exception {
		init(complexStructure, pgmTestCat);
		int originalLength = complexStructure.getLength();
		int newLength = -9;

		assertEquals(originalLength, model.getLength());

		JTextField textField =
			(JTextField) findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(textField);

		setText(textField, Integer.toString(newLength));
		triggerEnter(textField);

		assertEquals(originalLength, model.getLength());
		invoke(applyAction);
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertEquals(originalLength, complexStructure.getLength());
	}

	@Test
	public void testChangeSizeSmaller() throws Exception {
		init(complexStructure, pgmTestCat);
		int originalLength = complexStructure.getLength();
		int newLength = originalLength - 5;

		assertEquals(originalLength, model.getLength());

		waitForSwing();
		JTextField textField =
			(JTextField) findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(textField);

		setText(textField, Integer.toString(newLength));
		triggerEnter(textField);

		Window truncateDialog = waitForWindow("Truncate Structure In Editor?");
		assertNotNull(truncateDialog);
		pressButtonByText(truncateDialog, "No");

		assertEquals(originalLength, model.getLength());

		setText(textField, Integer.toString(newLength));
		setText(textField, Integer.toString(newLength));
		triggerEnter(textField);

		truncateDialog = waitForWindow("Truncate Structure In Editor?");
		assertNotNull(truncateDialog);
		pressButtonByText(truncateDialog, "Yes");
		waitForSwing();

		assertEquals(newLength, model.getLength());
		invoke(applyAction);
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertEquals(newLength, complexStructure.getLength());
	}

	@Test
	public void testClearContiguousAction() {
		init(complexStructure, pgmTestCat);

		DataType dt3 = getDataType(3);
		DataType dt10 = getDataType(10);
		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 4, 5, 6, 7, 8, 9 });// = 25 bytes
		invoke(clearAction);
		assertEquals(num + 19, model.getNumComponents());
		assertEquals(getDataType(3), dt3);
		assertEquals(getDataType(29), dt10);
		checkSelection(new int[] { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
			22, 23, 24, 25, 26, 27, 28 });
		assertEquals(len, model.getLength());
	}

	@Test
	public void testClearNonContiguousAction() {
		init(complexStructure, pgmTestCat);

		DataType dt3 = getDataType(3);
		DataType dt7 = getDataType(7);
		DataType dt21 = getDataType(21);
		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 5, 6, 22 });// = 6+4 bytes
		invoke(clearAction);
		assertEquals(num + 7, model.getNumComponents());
		assertEquals(getDataType(3), dt3);
		assertEquals(getDataType(11), dt7);
		assertEquals(getDataType(25), dt21);
		checkSelection(new int[] { 5, 6, 7, 8, 9, 10, 26, 27, 28, 29 });
		assertEquals(len, model.getLength());
	}

	@Test
	public void testClearOneComp() {
		init(simpleStructure, pgmTestCat);

		int len = model.getLength();
		int num = model.getNumComponents();
		setSelection(new int[] { 3 });// the DWord
		invoke(clearAction);
		assertEquals(len, model.getLength());
		assertEquals(4, model.getNumSelectedComponentRows());
		assertEquals(num + 3, model.getNumComponents());
	}

	@Test
	public void testClearOneComp2() {
		init(complexStructure, pgmTestCat);

		int len = model.getLength();
		int num = model.getNumComponents();
		setSelection(new int[] { 16 });// simpleStructure[3] == 87 bytes
		invoke(clearAction);
		assertEquals(len, model.getLength());
		assertEquals(87, model.getNumSelectedComponentRows());
		assertEquals(num + 86, model.getNumComponents());
	}

	@Test
	public void testCreatePointerOnBlankLine() throws Exception {
		init(simpleStructure, pgmBbCat);

		setSelection(new int[] { 8 });
		invoke(pointerAction);
		assertEquals("pointer", getDataType(8).getDisplayName());
		assertNull(((Pointer) getDataType(8)).getDataType());
		assertEquals(4, getDataType(8).getLength());
		assertEquals(4, getModel().getComponent(8).getLength());
		assertEquals(33, model.getLength());
	}

	@Test
	public void testCreatePointerOnFixedDt() throws Exception {
		init(complexStructure, pgmTestCat);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		assertTrue(getDataType(2).isEquivalent(new WordDataType()));
		invoke(pointerAction);

		assertEquals("pointer doesn't fit.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals("word", getDataType(2).getDisplayName());
		assertTrue(getDataType(2).isEquivalent(new WordDataType()));
		assertEquals(2, getDataType(2).getLength());
		assertEquals(2, model.getComponent(2).getLength());

		setSelection(new int[] { 4 });
		invoke(pointerAction);

		assertEquals(num + 4, model.getNumComponents());// field changed to pointer and 4 undefineds
		assertEquals("pointer", getDataType(4).getDisplayName());
		assertNull(((Pointer) getDataType(4)).getDataType());
		assertEquals(4, getDataType(4).getLength());
		assertEquals(4, model.getComponent(4).getLength());
	}

	//	public void testCancelPointerOnFixedDt() throws Exception {
	//      // FUTURE
	//		init(complexStructure,  pgmTestCat);
	//		NumberInputDialog dialog;
	//		int num = model.getNumComponents();
	//
	//		setSelection(new int[] {2});
	//		DataType dt2 = getDataType(2);
	//		assertTrue(getDataType(2).isEquivalent(new WordDataType()));
	//		invoke(pointerAction);
	//		dialog = (NumberInputDialog)env.waitForDialog(NumberInputDialog.class, 1000);
	//		assertNotNull(dialog);
	//		cancelInput(dialog);
	//		dialog.dispose();
	//		dialog = null;
	//		assertEquals(num, model.getNumComponents());
	//		assertEquals("word", getDataType(2).getDisplayName());
	//		assertTrue(getDataType(2).isEquivalent(dt2));
	//		assertEquals(4, model.getComponent(2).getLength());
	//	}

	@Test
	public void testCreatePointerOnPointer() throws Exception {
		init(complexStructure, pgmTestCat);
		int num = model.getNumComponents();

		setSelection(new int[] { 3 });
		DataType dt3 = getDataType(3);
		assertTrue(getDataType(3) instanceof Pointer);
		assertEquals(4, model.getComponent(3).getLength());
		invoke(pointerAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("undefined * *", getDataType(3).getDisplayName());
		assertTrue(((Pointer) getDataType(3)).getDataType().isEquivalent(dt3));
		assertEquals(4, getDataType(3).getLength());
		assertEquals(4, model.getComponent(3).getLength());
	}

	@Test
	public void testInsertUndefinedByteEnd() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { num - 1 });
		invoke(insertUndefinedAction);
		assertEquals(len + 1, model.getLength());
		assertEquals(num + 1, model.getNumComponents());
		assertTrue(getDataType(num - 1).isEquivalent(DataType.DEFAULT));
	}

	@Test
	public void testInsertUndefinedByteMiddle() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		runSwing(() -> model.setValueAt("Comment for Component_4", 4, model.getCommentColumn()));
		setSelection(new int[] { 4 });
		invoke(insertUndefinedAction);
		assertEquals(len + 1, model.getLength());
		assertEquals(num + 1, model.getNumComponents());
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		assertCellString("Comment for Component_4", 5, model.getCommentColumn());
	}

	@Test
	public void testInsertUndefinedByteOnBlankLine() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { num });
		invoke(insertUndefinedAction);
		assertEquals(len + 1, model.getLength());
		assertEquals(num + 1, model.getNumComponents());
		assertTrue(getDataType(num).isEquivalent(DataType.DEFAULT));
	}

	@Test
	public void testInsertUndefinedByteStart() throws Exception {
		init(simpleStructure, pgmBbCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 0 });
		invoke(insertUndefinedAction);
		assertEquals(len + 1, model.getLength());
		assertEquals(num + 1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(DataType.DEFAULT));
	}

	@Test
	public void testMoveDownAction() throws Exception {
		init(simpleStructure, pgmTestCat);

		setSelection(new int[] { 2, 3, 4, 5 });
		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt6 = getDataType(6);
		DataType dt7 = getDataType(7);
		assertTrue(model.isMoveDownAllowed());

		performAction(moveDownAction);
		checkSelection(new int[] { 3, 4, 5, 6 });
		assertEquals(8, model.getNumComponents());
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt6);
		assertEquals(getDataType(3), dt2);
		assertEquals(getDataType(4), dt3);
		assertEquals(getDataType(5), dt4);
		assertEquals(getDataType(6), dt5);
		assertEquals(getDataType(7), dt7);
		assertTrue(model.isMoveDownAllowed());

		performAction(moveDownAction);
		checkSelection(new int[] { 4, 5, 6, 7 });
		assertEquals(8, model.getNumComponents());
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt6);
		assertEquals(getDataType(3), dt7);
		assertEquals(getDataType(4), dt2);
		assertEquals(getDataType(5), dt3);
		assertEquals(getDataType(6), dt4);
		assertEquals(getDataType(7), dt5);
		assertTrue(!model.isMoveDownAllowed());
	}

	@Test
	public void testMoveUpAction() throws Exception {
		init(simpleStructure, pgmTestCat);

		setSelection(new int[] { 2, 3, 4 });
		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		DataType dt4 = getDataType(4);
		DataType dt5 = getDataType(5);
		DataType dt6 = getDataType(6);
		DataType dt7 = getDataType(7);
		assertTrue(model.isMoveUpAllowed());

		invoke(moveUpAction);
		checkSelection(new int[] { 1, 2, 3 });
		assertEquals(8, model.getNumComponents());
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt2);
		assertEquals(getDataType(2), dt3);
		assertEquals(getDataType(3), dt4);
		assertEquals(getDataType(4), dt1);
		assertEquals(getDataType(5), dt5);
		assertEquals(getDataType(6), dt6);
		assertEquals(getDataType(7), dt7);
		assertTrue(model.isMoveUpAllowed());

		invoke(moveUpAction);
		checkSelection(new int[] { 0, 1, 2 });
		assertEquals(8, model.getNumComponents());
		assertEquals(getDataType(0), dt2);
		assertEquals(getDataType(1), dt3);
		assertEquals(getDataType(2), dt4);
		assertEquals(getDataType(3), dt0);
		assertEquals(getDataType(4), dt1);
		assertEquals(getDataType(5), dt5);
		assertEquals(getDataType(6), dt6);
		assertEquals(getDataType(7), dt7);
		assertTrue(!model.isMoveUpAllowed());
	}

	@Test
	public void testShowComponentPathAction() {
		init(complexStructure, pgmTestCat);

		assertEquals("", model.getStatus());

		setSelection(new int[] { 1 });
		invoke(showComponentPathAction);
		String pathMessage = "byte is in category \"" + pgmRootCat.getCategoryPathName() + "\".";
		assertTrue(pathMessage.equals(model.getStatus()));

		setSelection(new int[] { 21 });
		invoke(showComponentPathAction);
		assertEquals("simpleStructure is in category \"" + pgmBbCat.getCategoryPathName() + "\".",
			model.getStatus());
		assertTrue(!listener.getBeep());
	}

	@Test
	public void testSizeEnablement() throws Exception {
		init(complexStructure, pgmTestCat);
		Component component = findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(component);
		assertEquals(true, component.isEnabled());
	}

	@Test
	public void testSizeNoChange() throws Exception {
		init(complexStructure, pgmTestCat);
		int originalLength = complexStructure.getLength();
		int newLength = originalLength;

		assertEquals(originalLength, model.getLength());

		Component component = findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(component);
		((JTextField) component).setText(Integer.toString(newLength));
		triggerActionKey(component, 0, KeyEvent.VK_ENTER);

		assertEquals(newLength, model.getLength());
		invoke(applyAction);
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertEquals(newLength, complexStructure.getLength());
	}

	@Test
	public void testUndoRename() throws Exception {
		init(complexStructure, pgmTestCat);

		CompEditorPanel panel = (CompEditorPanel) getPanel();
		JTextField nameField = panel.nameTextField;
		runSwing(() -> nameField.setText("myStruct"));
		invoke(applyAction);
		runSwing(() -> nameField.setText("myStruct2"));
		invoke(applyAction);
		undo(program, false);
		program.flushEvents();
		waitForSwing();
		runSwing(() -> provider.domainObjectRestored(program), true);
		waitForSwing();

		assertEquals("myStruct", model.getCompositeName());
		redo(program, false);
		program.flushEvents();
		waitForSwing();
		runSwing(() -> provider.domainObjectRestored(program), true);
		waitForSwing();
		assertEquals("myStruct2", model.getCompositeName());

	}

	@Test
	public void testUnpackageComponentArray() throws Exception {
		init(complexStructure, pgmTestCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		DataType dt15 = getDataType(15);
		assertTrue(dt15 instanceof Array);
		DataType element = ((Array) dt15).getDataType();
		int elementLen = ((Array) dt15).getElementLength();
		setSelection(new int[] { 15 });
		assertEquals("string[5]", getDataType(15).getDisplayName());
		invoke(unpackageAction);
		assertEquals(len, model.getLength());
		assertEquals(num + 4, model.getNumComponents());
		assertTrue(!getDataType(15).isEquivalent(simpleStructure));
		for (int i = 0; i < 5; i++) {
			DataTypeComponent dtc = model.getComponent(15 + i);
			DataType sdt = dtc.getDataType();
			assertTrue(sdt.isEquivalent(element));
			assertEquals("string", sdt.getDisplayName());
			assertEquals(elementLen, dtc.getLength());
		}
	}

	@Test
	public void testUnpackageComponentStructure() throws Exception {
		init(complexStructure, pgmTestCat);

		int num = model.getNumComponents();
		int len = model.getLength();
		int numComps = simpleStructure.getNumComponents();
		setSelection(new int[] { 21 });
		assertEquals("simpleStructure", getDataType(21).getDisplayName());
		invoke(unpackageAction);
		assertEquals(len, model.getLength());
		assertEquals(num + numComps - 1, model.getNumComponents());
		assertTrue(!getDataType(21).isEquivalent(simpleStructure));
		for (int i = 0; i < numComps; i++) {
			DataType sdt = simpleStructure.getComponent(i).getDataType();
			assertTrue(getDataType(21 + i).isEquivalent(sdt));
			assertEquals(sdt.getDisplayName(), getDataType(21 + i).getDisplayName());
		}
	}
}
