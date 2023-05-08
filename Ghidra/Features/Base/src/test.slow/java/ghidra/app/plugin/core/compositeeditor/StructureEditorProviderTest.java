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

import java.awt.Window;

import org.junit.Assert;
import org.junit.Test;

import docking.DefaultActionContext;
import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.UsrException;

public class StructureEditorProviderTest extends AbstractStructureEditorTest {
	private static final String HEX_OPTION_NAME =
		"Structure Editor" + Options.DELIMITER + "Show Numbers In Hex";

	@Override
	protected void init(Structure dt, final Category cat, final boolean showInHex) {
		boolean commit = true;
		startTransaction("Structure Editor Test Initialization");
		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = dt.clone(dataTypeManager);
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
			installProvider(new StructureEditorProvider(plugin, structDt, showInHex));
			model = provider.getModel();
//				model.setLocked(false);
		});
//		assertFalse(model.isLocked());
		getActions();
	}

	@Test
	public void testDataTypeChanged() throws Exception {
		try {
			txId = program.startTransaction("Grow DataType");
			complexStructure.insert(22, DataType.DEFAULT);
			complexStructure.insert(22, DataType.DEFAULT);
			complexStructure.insert(22, DataType.DEFAULT);
			complexStructure.insert(22, DataType.DEFAULT);
			complexStructure.insert(22, DataType.DEFAULT);
			complexStructure.insert(22, DataType.DEFAULT);
			assertEquals(87, complexStructure.getComponent(16).getDataType().getLength());
			assertEquals(29, complexStructure.getComponent(19).getDataType().getLength());
			assertEquals(29, complexStructure.getComponent(21).getDataType().getLength());
			assertEquals(87, complexStructure.getComponent(16).getLength());
			assertEquals(29, complexStructure.getComponent(19).getLength());
			assertEquals(29, complexStructure.getComponent(21).getLength());
			assertEquals(1, complexStructure.getComponent(22).getLength());
			assertEquals(4, complexStructure.getComponent(28).getLength());
			assertEquals(331, complexStructure.getLength());
			assertEquals(29, complexStructure.getNumComponents());
			// Change the struct.  simpleStructure was 29 bytes.
			simpleStructure.add(new DWordDataType());
			assertEquals(331, complexStructure.getLength());
			assertEquals(25, complexStructure.getNumComponents());
			assertEquals(99, complexStructure.getComponent(16).getDataType().getLength());
			assertEquals(33, complexStructure.getComponent(19).getDataType().getLength());
			assertEquals(33, complexStructure.getComponent(21).getDataType().getLength());
			assertEquals(87, complexStructure.getComponent(16).getLength());
			assertEquals(29, complexStructure.getComponent(19).getLength());
			assertEquals(33, complexStructure.getComponent(21).getLength());
			assertEquals(1, complexStructure.getComponent(22).getLength());
			assertEquals(4, complexStructure.getComponent(24).getLength());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	// Test Undo / Redo of program.
	@Test
	public void testModifiedDtAndProgramRestored() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		Window dialog;
		try {
			init(complexStructure, pgmTestCat, false);
			program.addListener(restoreListener);

			// Change the structure
			runSwingLater(() -> {
				getTable().requestFocus();
				setSelection(new int[] { 4, 5 });
				deleteAction.actionPerformed(new DefaultActionContext());
				try {
					model.add(new WordDataType());
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			waitForSwing();
			assertFalse(complexStructure.isEquivalent(model.viewComposite));

			// Apply the changes
			invoke(applyAction);
			assertTrue(complexStructure.isEquivalent(model.viewComposite));

			// Change the structure again.
			runSwingLater(() -> {
				getTable().requestFocus();
				setSelection(new int[] { 1 });
				clearAction.actionPerformed(new DefaultActionContext());
				deleteAction.actionPerformed(new DefaultActionContext());// Must be undefined before it can delete.
			});
			waitForSwing();
			assertFalse(complexStructure.isEquivalent(model.viewComposite));

			// Undo the apply
			undo(program, false);
			// Verify the Reload Structure Editor? dialog is displayed.
			dialog = waitForWindow("Reload Structure Editor?");
			assertNotNull(dialog);
			pressButton(dialog, "No");
			dialog.dispose();
			dialog = null;
			assertFalse(complexStructure.isEquivalent(model.viewComposite));

			// Redo the apply
			redo(program, false);
			// Verify the Reload Structure Editor? dialog is displayed.
			dialog = waitForWindow("Reload Structure Editor?");
			assertNotNull(dialog);
			pressButton(dialog, "No");
			dialog.dispose();
			dialog = null;
			assertFalse(complexStructure.isEquivalent(model.viewComposite));
		}
		finally {
			dialog = null;
			program.removeListener(restoreListener);
		}
	}

	// Test add a structure, start to edit it, and then undo the program so it goes away.
	// This should close the edit session.
	@Test
	public void testProgramRestoreRemovesEditedDt() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		Window dialog;
		try {
			Structure s1 = new StructureDataType("s1", 0);
			s1.add(new ByteDataType());
			Structure s2 = new StructureDataType("s2", 0);
			s2.add(new WordDataType());
			s1.add(s2);

			// Add the s1 data type so that we can undo its add.
			boolean commit = true;
			Structure s1Struct = null;
			startTransaction("Structure Editor Test Initialization");
			try {
				s1Struct =
					(Structure) pgmTestCat.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			finally {
				endTransaction(commit);
			}
			assertNotNull(s1Struct);
			final Structure myS1Structure = s1Struct;

			init(myS1Structure, pgmTestCat, false);
			program.addListener(restoreListener);

			// Change the structure.
			runSwingLater(() -> {
				getTable().requestFocus();
				// Select blank line after components.
				setSelection(new int[] { myS1Structure.getNumComponents() });
				try {
					model.add(new WordDataType());
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			waitForSwing();
			assertFalse(complexStructure.isEquivalent(model.viewComposite));

			// Verify the editor provider is displayed.
			String mySubTitle = getProviderSubTitle(myS1Structure);
			assertTrue("Couldn't find editor = " + mySubTitle,
				isProviderShown(tool.getToolFrame(), "Structure Editor", mySubTitle));

			// Undo the apply
			undo(program, false);
			waitForSwing();

			// Verify the "Reload Structure Editor?" dialog is NOT displayed.
			dialog = getWindow("Reload Structure Editor?");
			assertNull(dialog);

			// Verify the editor provider is gone.
			assertFalse(isProviderShown(tool.getToolFrame(), "Structure Editor", mySubTitle));
		}
		finally {
			dialog = null;
			program.removeListener(restoreListener);
		}
	}

	// Test add a structure containing inner struct, start to edit inner struct, and then undo the
	// program so it goes away. This should close the edit session.
	@Test
	public void testProgramRestoreRemovesEditedDtComp() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		Window dialog;
		try {
			Structure s1 = new StructureDataType("s1", 0);
			s1.setCategoryPath(pgmTestCat.getCategoryPath());
			s1.add(new ByteDataType());
			Structure s2 = new StructureDataType("s2", 0);
			s2.setCategoryPath(pgmTestCat.getCategoryPath());
			s2.add(new WordDataType());
			s1.add(s2);

			// Add the s1 data type so that we can undo its add.
			boolean commit = true;
			Structure s1Struct = null;
			startTransaction("Structure Editor Test Initialization");
			try {
				s1Struct =
					(Structure) pgmTestCat.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			finally {
				endTransaction(commit);
			}
			assertNotNull(s1Struct);
			final Structure myS2Structure = (Structure) s1Struct.getComponent(1).getDataType();
			assertNotNull(myS2Structure);
			assertTrue(s2.isEquivalent(myS2Structure));

			init(myS2Structure, pgmTestCat, false);
			program.addListener(restoreListener);

			// Change the structure.
			runSwing(() -> {
				getTable().requestFocus();
				// Select blank line after components.
				setSelection(new int[] { myS2Structure.getNumComponents() });
				try {
					model.add(new WordDataType());
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			}, false);
			waitForSwing();
			assertFalse(complexStructure.isEquivalent(model.viewComposite));

			// Verify the editor provider is displayed.
			String mySubTitle = getProviderSubTitle(myS2Structure);
			assertTrue("Couldn't find editor = " + mySubTitle,
				isProviderShown(tool.getToolFrame(), "Structure Editor", mySubTitle));

			// Undo the apply
			undo(program, false);
			waitForSwing();

			// Verify the "Reload Structure Editor?" dialog is NOT displayed.
			dialog = getWindow("Reload Structure Editor?");
			assertNull(dialog);

			// Verify the editor provider is gone.
			assertFalse(isProviderShown(tool.getToolFrame(), "Structure Editor", mySubTitle));
		}
		finally {
			dialog = null;
			program.removeListener(restoreListener);
		}
	}

	// Test add a structure, start to edit a structure that contains it, and then undo the program
	// so it goes away. The editor stays since the structure existed previously, but editor reloads.
	@Test
	public void testProgramRestoreRemovesEditedComponentDtYes() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		Window dialog;
		try {
			Structure myStruct = new StructureDataType("myStruct", 0);
			myStruct.add(new WordDataType());

			init(emptyStructure, pgmTestCat, false);
			program.addListener(restoreListener);

			// Add the data type so that we can undo its add.
			boolean commit = true;
			Structure pgmMyStruct = null;
			startTransaction("Structure Editor Test Initialization");
			try {
				pgmMyStruct = (Structure) pgmTestCat.addDataType(myStruct,
					DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			finally {
				endTransaction(commit);
			}
			assertNotNull(pgmMyStruct);
			final Structure myStructure = pgmMyStruct;

			// Change the structure.
			runSwingLater(() -> {
				getTable().requestFocus();
				// Select blank line after components.
				setSelection(new int[] { emptyStructure.getNumComponents() });
				try {
					model.add(myStructure);
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			waitForSwing();
			assertFalse(emptyStructure.isEquivalent(model.viewComposite));

			// Verify the editor provider is displayed.
			String mySubTitle = getProviderSubTitle(emptyStructure);
			assertTrue("Couldn't find editor = " + mySubTitle,
				isProviderShown(tool.getToolFrame(), "Structure Editor", "emptyStructure (Test)"));

			// Undo the apply
			undo(program, false);

			// Verify the Reload Structure Editor? dialog is displayed.
			dialog = waitForWindow("Reload Structure Editor?");
			assertNotNull(dialog);
			pressButton(dialog, "Yes");
			dialog.dispose();
			dialog = null;
			assertTrue(emptyStructure.isEquivalent(model.viewComposite));

			// Verify the editor provider is reloaded.
			assertTrue(
				isProviderShown(tool.getToolFrame(), "Structure Editor", "emptyStructure (Test)"));
		}
		finally {
			dialog = null;
			program.removeListener(restoreListener);
		}
	}

	// Test add a structure, start to edit a structure that contains it, and then undo the program
	// so it goes away. The editor stays since the structure existed previously, but doesn't reload.
	@Test
	public void testProgramRestoreRemovesEditedComponentDtNo() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		Window dialog;
		try {
			Structure myStruct = new StructureDataType("myStruct", 0);
			myStruct.add(new WordDataType());

			init(emptyStructure, pgmTestCat, false);
			program.addListener(restoreListener);

			// Add the data type so that we can undo its add.
			boolean commit = true;
			Structure pgmMyStruct = null;
			startTransaction("Structure Editor Test Initialization");
			try {
				pgmMyStruct = (Structure) pgmTestCat.addDataType(myStruct,
					DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			finally {
				endTransaction(commit);
			}
			assertNotNull(pgmMyStruct);
			final Structure myStructure = pgmMyStruct;

			// Change the structure.
			runSwingLater(() -> {
				getTable().requestFocus();
				// Select blank line after components.
				setSelection(new int[] { emptyStructure.getNumComponents() });
				try {
					model.add(myStructure);
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			waitForSwing();
			assertFalse(emptyStructure.isEquivalent(model.viewComposite));

			// Verify the editor provider is displayed.
			String mySubTitle = getProviderSubTitle(emptyStructure);
			assertTrue("Couldn't find editor = " + mySubTitle,
				isProviderShown(tool.getToolFrame(), "Structure Editor", "emptyStructure (Test)"));

			// Undo the apply
			undo(program, false);
			// Verify the Reload Structure Editor? dialog is displayed.
			dialog = waitForWindow("Reload Structure Editor?");
			assertNotNull(dialog);
			pressButton(dialog, "No");
			dialog.dispose();
			dialog = null;
			assertFalse(emptyStructure.isEquivalent(model.viewComposite));

			// Verify the editor provider is still on screen.
			assertTrue(
				isProviderShown(tool.getToolFrame(), "Structure Editor", "emptyStructure (Test)"));
		}
		finally {
			dialog = null;
			program.removeListener(restoreListener);
		}
	}

	// Test Undo / Redo of program.
	@Test
	public void testUnModifiedDtAndProgramRestored() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		try {
			init(complexStructure, pgmTestCat, false);
			program.addListener(restoreListener);

			// Change the structure
			runSwingLater(() -> {
				getTable().requestFocus();
				setSelection(new int[] { 4, 5 });
				deleteAction.actionPerformed(new DefaultActionContext());
				try {
					model.add(new WordDataType());
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});
			waitForSwing();
			assertFalse(complexStructure.isEquivalent(model.viewComposite));
			// Apply the changes
			invoke(applyAction);
			assertTrue(complexStructure.isEquivalent(model.viewComposite));
			// Undo the apply
			undo(program);
			assertTrue(complexStructure.isEquivalent(model.viewComposite));
			// Redo the apply
			redo(program);
			assertTrue(complexStructure.isEquivalent(model.viewComposite));
		}
		finally {
			program.removeListener(restoreListener);
		}
	}

	@Test
	public void testCloseEditorProviderUnmodified() throws Exception {
		env.showTool();
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, complexStructure, false));
			model = provider.getModel();
		});
		DataType dt = model.viewComposite.clone(null);
		waitForSwing();

		assertNotNull(provider);
		assertTrue(tool.isVisible(provider));
		assertTrue(complexStructure.isEquivalent(model.viewComposite));

		runSwing(() -> provider.closeComponent());

		assertFalse(tool.isVisible(provider));
		assertTrue(complexStructure.isEquivalent(dt));
	}

	@Test
	public void testCloseEditorProviderAndSave() throws Exception {
		Window dialog;
		init(complexStructure, pgmTestCat, false);
		DataType oldDt = model.viewComposite.clone(null);

		// Change the structure
		runSwingLater(() -> {
			getTable().requestFocus();
			setSelection(new int[] { 4, 5 });
			deleteAction.actionPerformed(new DefaultActionContext());
			try {
				model.add(new WordDataType());
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});
		waitForSwing();
		DataType newDt = model.viewComposite.clone(null);
		assertFalse(complexStructure.isEquivalent(model.viewComposite));

		assertTrue(complexStructure.isEquivalent(oldDt));
		runSwing(() -> provider.closeComponent(), false);
		waitForSwing();

		dialog = waitForWindow("Save Structure Editor Changes?");
		assertNotNull(dialog);
		pressButton(dialog, "Yes");
		dialog.dispose();

		assertFalse(tool.isVisible(provider));
		assertTrue(complexStructure.isEquivalent(newDt));
		assertFalse(complexStructure.isEquivalent(oldDt));
	}

	@Test
	public void testCloseEditorAndNoSave() throws Exception {

		init(complexStructure, pgmTestCat, false);
		DataType oldDt = model.viewComposite.clone(null);

		// Change the structure
		runSwing(() -> {
			getTable().requestFocus();
			setSelection(new int[] { 4, 5 });
			deleteAction.actionPerformed(new DefaultActionContext());
			try {
				model.add(new WordDataType());
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		}, false);
		waitForSwing();
		DataType newDt = model.viewComposite.clone(null);
		assertFalse(complexStructure.isEquivalent(model.viewComposite));

		closeProviderIgnoringChanges();
		assertFalse(complexStructure.isEquivalent(newDt));
		assertTrue(complexStructure.isEquivalent(oldDt));
	}

	@Test
	public void testCloseEditorAndCancel() throws Exception {
		Window dialog;
		init(complexStructure, pgmTestCat, false);

		// Change the structure
		runSwingLater(() -> {
			getTable().requestFocus();
			setSelection(new int[] { 4, 5 });
			deleteAction.actionPerformed(new DefaultActionContext());
			try {
				model.add(new WordDataType());
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});
		waitForSwing();
		DataType newDt = model.viewComposite.clone(null);
		assertFalse(complexStructure.isEquivalent(model.viewComposite));

		runSwingLater(() -> provider.closeComponent());
		waitForSwing();

		dialog = waitForWindow("Save Structure Editor Changes?");
		assertNotNull(dialog);
		pressButton(dialog, "Cancel");
		dialog.dispose();
		dialog = null;
		assertTrue(tool.isVisible(provider));
		assertFalse(complexStructure.isEquivalent(model.viewComposite));
		assertTrue(newDt.isEquivalent(model.viewComposite));
	}

	@Test
	public void testEditWillReEditLastColumnWhenPressingKeyboardEditAction() throws Exception {
		//
		// This is a regression test.   The user would edit a field by pressing the keyboard edit
		// action (F2).  The user would finish the edit by pressing Enter.   The UI would show the
		// current table cell as the cell that was just edited (this is correct).  When the user
		// again presses the edit actions, the first editable cell in the current row would start
		// to be edited (this was incorrect).   This test ensures that the currently selected cell
		// is edited in this case.
		//

		init(simpleStructure, pgmBbCat, false);

		int row = 3;
		int column = model.getNameColumn();
		assertNull(getComment(3));
		clickTableCell(getTable(), row, column, 1);
		performAction(editFieldAction, provider, true);

		assertIsEditingField(row, column);

		setText("Wow");
		enter();

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(3, model.getMinIndexSelected());
		assertEquals("Wow", getFieldName(3));

		performAction(editFieldAction, provider, true);
		assertIsEditingField(row, column);
	}

	@Test
	public void testEditAfterUsingArrowKeys() throws Exception {

		//
		// This is a regression test.  Using F2 to start an edit would edit the wrong cell after
		// the user had navigated the table using the left/right arrow keys.
		//

		init(simpleStructure, pgmBbCat, false);

		int row = 3;
		int column = model.getNameColumn();
		assertNull(getComment(3));
		clickTableCell(getTable(), row, column, 1);
		assertColumn(column);

		leftArrow();
		assertColumn(column - 1);

		rightArrow();
		assertColumn(column);

		performAction(editFieldAction, provider, true);
		assertIsEditingField(row, column);
		escape();
	}

	@Test
	public void testEditorHexModeDefaultsFromOptions() throws Exception {
		// options default is hex
		provider = edit(complexStructure);
		model = provider.getModel();
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x2f", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("0x2d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x145", model.getLengthAsString());

		closeProvider(provider);
		setOptions(HEX_OPTION_NAME, false);

		provider = edit(complexStructure);
		model = provider.getModel();
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("47", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("45", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("325", model.getLengthAsString());
	}

	@Test
	public void testHexDisplayOptionsChangeDoesntAffectExisting() throws Exception {
		// options default is hex
		provider = edit(complexStructure);
		model = provider.getModel();
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x2f", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("0x2d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x145", model.getLengthAsString());

		setOptions(HEX_OPTION_NAME, false);

		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x2f", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("0x2d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x145", model.getLengthAsString());
	}

	@Test
	public void testToggleHexModeAction() throws Exception {
		provider = edit(complexStructure);
		model = provider.getModel();
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x2f", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("0x2d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x145", model.getLengthAsString());

		DockingActionIf action = getAction(plugin, "Editor: Show Numbers In Hex");
		setToggleActionSelected((ToggleDockingActionIf) action, new DefaultActionContext(), false);

		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("47", model.getValueAt(15, model.getOffsetColumn()));
		assertEquals("45", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("325", model.getLengthAsString());

	}

	@Test
	public void testExternalChangeMaintainsSelection() throws Exception {
		env.showTool();
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, complexStructure, false));
			model = provider.getModel();
		});

		assertNotNull(provider);
		assertTrue(tool.isVisible(provider));
		assertTrue(complexStructure.isEquivalent(model.viewComposite));

		Composite dt = model.viewComposite;

		// set selected row
		int row = 2;
		setSelection(new int[] { row });

		// update data type
		int editRow = 4; // offset 8; 'simpleUnion'
		String newFieldName = "newFieldName";
		tx(program, () -> {
			DataTypeComponent dtc = dt.getComponent(editRow);
			dtc.setFieldName(newFieldName);
		});

		// verify editor is updated
		assertEquals(newFieldName, model.getValueAt(editRow, model.getNameColumn()));

		// verify selection has not changed
		int[] rows = getSelection();
		assertEquals(1, rows.length);
		assertEquals(row, rows[0]);

		closeProviderIgnoringChanges();
	}

	private void closeProviderIgnoringChanges() {

		runSwingLater(() -> provider.closeComponent());

		Window dialog = waitForWindow("Save Structure Editor Changes?");
		assertNotNull(dialog);
		pressButton(dialog, "No");
		dialog.dispose();

		assertFalse(tool.isVisible(provider));
	}

	protected StructureEditorProvider edit(DataType dt) {
		runSwing(() -> {
			plugin.edit(dt);
		});
		return waitForComponentProvider(StructureEditorProvider.class);
	}
}
