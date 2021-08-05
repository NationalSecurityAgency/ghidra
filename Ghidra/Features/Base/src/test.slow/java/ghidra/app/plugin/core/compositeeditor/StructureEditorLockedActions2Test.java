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

import javax.swing.JDialog;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class StructureEditorLockedActions2Test extends AbstractStructureEditorLockedActionsTest {

	@Test
	public void testCycleGroupByteSomeRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			getModel().clearComponents(new int[] { 2, 3 });// clear 6 bytes
		});
		DataType dt8 = getDataType(8);
		int dt8Len = getLength(8);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new ByteDataType());

		invoke(action);
		assertEquals(num - 1, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(6).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(2, getLength(1));
		assertEquals(getLength(7), dt8Len);
		assertEquals(getDataType(7), dt8);

		invoke(action);
		assertEquals(num - 3, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new DWordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(5), dt8Len);
		assertEquals(getDataType(5), dt8);

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new ByteDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(8), dt8Len);
		assertEquals(getDataType(8), dt8);

		invoke(action);
		assertEquals(num - 1, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(6).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(2, getLength(1));
		assertEquals(getLength(7), dt8Len);
		assertEquals(getDataType(7), dt8);
	}

	@Test
	public void testCycleGroupFloatLotsOfRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			getModel().clearComponents(new int[] { 2, 3, 4 });// clear 14 bytes
		});
		DataType dt16 = getDataType(16);
		int dt16Len = getLength(16);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new FloatDataType());

		invoke(action);
		assertEquals(num - 3, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new FloatDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(13), dt16Len);
		assertEquals(getDataType(13), dt16);

		invoke(action);
		assertEquals(num - 7, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new DoubleDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(8, getLength(1));
		assertEquals(getLength(9), dt16Len);
		assertEquals(getDataType(9), dt16);
	}

	@Test
	public void testCycleGroupFloatNoRoom() throws Exception {
		init(complexStructure, pgmTestCat);

		DataType dt1 = getDataType(1);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 0 });
		CycleGroupAction action = getCycleGroup(new FloatDataType());

		invoke(action);
		assertTrue(!"".equals(getModel().getStatus()));
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);
	}

	@Test
	public void testCycleGroupFloatSomeRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		getModel().clearComponents(new int[] { 2, 3 });// clear 6 bytes

		DataType dt8 = getDataType(8);
		int dt8Len = getLength(8);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new FloatDataType());

		invoke(action);
		assertEquals(num - 3, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new FloatDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(5), dt8Len);
		assertEquals(getDataType(5), dt8);

		invoke(action);
		assertEquals(num - 3, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new FloatDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(5), dt8Len);
		assertEquals(getDataType(5), dt8);
	}

	@Test
	public void testCycleGroupOnMultiLine() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		int num = getModel().getNumComponents();

		setSelection(new int[] { 1, 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", getModel().getStatus());
		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		checkSelection(new int[] { 1, 2 });
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt3);
		assertTrue(!"".equals(getModel().getStatus()));
	}

	@Test
	public void testDuplicateAction() throws Exception {
		init(complexStructure, pgmTestCat);
		model.clearComponent(3);
		model.setComponentName(2, "comp2");
		model.setComponentComment(2, "comment 2");

		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		// Duplicate Word
		setSelection(new int[] { 2 });
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		invoke(duplicateAction);
		assertEquals(num - 1, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt2);
		assertEquals(getDataType(4), dt3);
		assertEquals("comp2", getFieldName(2));
		assertEquals("comment 2", getComment(2));
	}

	@Test
	public void testDuplicateMultipleAction() throws Exception {
		NumberInputDialog dialog;
		init(complexStructure, pgmTestCat);
		model.clearComponent(3);
		model.setComponentName(2, "comp2");
		model.setComponentComment(2, "comment 2");

		int num = getModel().getNumComponents();

		// Duplicate Word
		setSelection(new int[] { 2 });
		DataType dt2 = getDataType(2);
		DataType dt7 = getDataType(7);

		invoke(duplicateMultipleAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		badInput(dialog, 3);
		dialog = getDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		waitForBusyTool(tool); // the 'Duplicate Multiple' action uses a task

		assertEquals(num - 2, getModel().getNumComponents());
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt2);
		assertEquals(getDataType(4), dt2);
		assertEquals(getDataType(5), dt7);
		assertEquals("comp2", getFieldName(2));
		assertEquals("comment 2", getComment(2));
	}

	@Test
	public void testExistingAlignedDtEditInternalStructureOnSelectionDefaultName()
			throws Exception {
		boolean commit = false;
		txId = program.startTransaction("Modify Program");
		try {
			simpleStructure.setPackingEnabled(true);
			commit = true;
		}
		finally {
			program.endTransaction(txId, commit);
		}

		init(simpleStructure, pgmBbCat);

		assertEquals(7, getModel().getNumComponents());

		setSelection(new int[] { 1, 2, 3 });
		DataType originalDt1 = getDataType(1);
		DataType originalDt2 = getDataType(2);
		DataType originalDt3 = getDataType(3);
		DataType originalDt4 = getDataType(4);

		// Make selected components into internal structure.
		invoke(createInternalStructureAction, false);

		// Specify name for structure.
		JDialog inputDialog = waitForJDialog("Specify the Structure's Name");
		assertNotNull(inputDialog);
		pressButtonByText(inputDialog, "OK");

		waitForTasks();

		assertEquals(5, getModel().getNumComponents());
		Structure internalStruct = (Structure) getDataType(1);
		assertEquals("struct", internalStruct.getName());
		assertEquals(3, internalStruct.getNumComponents());
		DataType internalDt0 = internalStruct.getComponent(0).getDataType();
		DataType internalDt1 = internalStruct.getComponent(1).getDataType();
		DataType internalDt2 = internalStruct.getComponent(2).getDataType();
		assertTrue(internalDt0.isEquivalent(originalDt1));
		assertTrue(internalDt1.isEquivalent(originalDt2));
		assertTrue(internalDt2.isEquivalent(originalDt3));
		assertEquals(16, getDataType(1).getLength());
		assertEquals(16, getModel().getComponent(1).getLength());
		assertEquals(originalDt4, getDataType(2));
		assertEquals(36, getModel().getLength());
	}

	/**
	 * Edit an existing structure and create a structure from a selection, 
	 * but cancel out of name dialog.
	 * @throws Exception it the test throws an exception
	 */
	@Test
	public void testExistingDtEditInternalStructureOnSelectionCancelOnName() throws Exception {
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
		JDialog inputDialog = waitForJDialog("Specify the Structure's Name");
		assertNotNull(inputDialog);
		pressButtonByText(inputDialog, "Cancel");
		waitForSwing();

		// Verify the structure wasn't changed.
		assertEquals(8, getModel().getNumComponents());
		assertEquals(29, getModel().getLength());
		assertEquals(originalDt1, getDataType(1));
		assertEquals(originalDt2, getDataType(2));
		assertEquals(originalDt3, getDataType(3));
		assertEquals(originalDt4, getDataType(4));
	}

	/**
	 * Edit an existing structure and create a structure from a selection. Use the default name.
	 * @throws Exception if the test throws an exception
	 */
	@Test
	public void testExistingDtEditInternalStructureOnSelectionDefaultName() throws Exception {
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
		JDialog inputDialog = waitForJDialog("Specify the Structure's Name");
		assertNotNull(inputDialog);
		pressButtonByText(inputDialog, "OK");

		waitForTasks();

		assertEquals(6, getModel().getNumComponents());
		Structure internalStruct = (Structure) getDataType(1);
		assertEquals("struct", internalStruct.getName());
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
}
