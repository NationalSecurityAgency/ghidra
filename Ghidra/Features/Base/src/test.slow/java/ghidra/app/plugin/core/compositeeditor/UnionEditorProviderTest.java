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

import docking.ActionContext;
import ghidra.framework.options.Options;
import ghidra.program.model.data.*;
import ghidra.util.Swing;
import ghidra.util.exception.UsrException;

public class UnionEditorProviderTest extends AbstractUnionEditorTest {

	@Test
	public void testReplaceDataType() throws Exception {
		try {
			txId = program.startTransaction("Replace DataType");
			assertEquals(87, complexUnion.getComponent(12).getDataType().getLength());
			assertEquals(29, complexUnion.getComponent(15).getDataType().getLength());
			assertEquals(29, complexUnion.getComponent(20).getDataType().getLength());
			assertEquals(87, complexUnion.getComponent(12).getLength());
			assertEquals(29, complexUnion.getComponent(15).getLength());
			assertEquals(29, complexUnion.getComponent(20).getLength());
			assertEquals(87, complexUnion.getLength());
			assertEquals(21, complexUnion.getNumComponents());
			final Structure newSimpleStructure =
				new StructureDataType(new CategoryPath("/aa/bb"), "simpleStructure", 10);
			newSimpleStructure.add(new PointerDataType(), 8);
			newSimpleStructure.replace(2, new CharDataType(), 1);
			// Change the struct.  simpleStructure was 29 bytes.
			programDTM.replaceDataType(simpleStructure, newSimpleStructure, true);
			assertEquals(54, complexUnion.getComponent(12).getDataType().getLength());
			assertEquals(18, complexUnion.getComponent(15).getDataType().getLength());
			assertEquals(18, complexUnion.getComponent(20).getDataType().getLength());
			assertEquals(54, complexUnion.getComponent(12).getLength());
			assertEquals(18, complexUnion.getComponent(15).getLength());
			assertEquals(18, complexUnion.getComponent(20).getLength());
			assertEquals(56, complexUnion.getLength());
			assertEquals(21, complexUnion.getNumComponents());
		}
		finally {
			program.endTransaction(txId, true);
		}
	}

	@Test
	public void testOffsetsAreZero() throws Exception {
		init(complexUnion, pgmTestCat, false);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		insertAtPoint(dt, 0, 3);
		model.add(model.getNumComponents(), dt);

		int num = model.getNumComponents();
		for (int i = 0; i < num; i++) {
			assertEquals(0, model.getComponent(i).getOffset());
		}
	}

	// Test Undo / Redo of program.
	@Test
	public void testModifiedDtAndProgramRestored() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		Window dialog;
		try {
			init(complexUnion, pgmTestCat, false);
			program.addListener(restoreListener);

			// Change the union.
			Swing.runLater(() -> {
				delete(4, 5);
				try {
					model.add(new WordDataType());
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});

			waitForTasks();
			assertFalse(complexUnion.isEquivalent(model.viewComposite));

			// Apply the changes
			invoke(applyAction);
			assertTrue(complexUnion.isEquivalent(model.viewComposite));

			// Change the union again.
			Swing.runLater(() -> {
				delete(1);
			});
			waitForSwing();
			assertFalse(complexUnion.isEquivalent(model.viewComposite));

			// Undo the apply
			undo(program, false);

			// Verify the Reload Union Editor? dialog is displayed.
			dialog = waitForWindow("Reload Union Editor?");
			assertNotNull(dialog);
			pressButton(dialog, "No");
			dialog.dispose();
			dialog = null;
			assertFalse(complexUnion.isEquivalent(model.viewComposite));

			// Redo the apply
			redo(program, false);

			// Verify the Reload Union Editor? dialog is displayed.
			dialog = waitForWindow("Reload Union Editor?");
			assertNotNull(dialog);
			pressButton(dialog, "No");
			dialog.dispose();
			dialog = null;
			assertFalse(complexUnion.isEquivalent(model.viewComposite));
		}
		finally {
			dialog = null;
			program.removeListener(restoreListener);
			cleanup();
		}
	}

	// Test Undo / Redo of program.
	@Test
	public void testUnModifiedDtAndProgramRestored() throws Exception {
		RestoreListener restoreListener = new RestoreListener();
		try {
			init(complexUnion, pgmTestCat, false);
			program.addListener(restoreListener);

			// Change the union.
			Swing.runLater(() -> {
				delete(4, 5);
				try {
					model.add(new WordDataType());
				}
				catch (UsrException e) {
					Assert.fail(e.getMessage());
				}
			});

			waitForTasks();
			assertFalse(complexUnion.isEquivalent(model.viewComposite));

			// Apply the changes
			invoke(applyAction);
			assertTrue(complexUnion.isEquivalent(model.viewComposite));

			// Undo the apply
			undo(program);
			assertTrue(complexUnion.isEquivalent(model.viewComposite));

			// Redo the apply
			redo(program);
			assertTrue(complexUnion.isEquivalent(model.viewComposite));
		}
		finally {
			program.removeListener(restoreListener);
			cleanup();
		}
	}

	@Test
	public void testCloseEditorProviderUnmodified() throws Exception {
		init(complexUnion, pgmTestCat, false);
		DataType dt = model.viewComposite.clone(null);

		waitForSwing();
		assertTrue(tool.isVisible(provider));
		assertTrue(complexUnion.isEquivalent(model.viewComposite));

		runSwing(() -> provider.closeComponent());
		waitForSwing();

		assertFalse(tool.isVisible(provider));
		assertTrue(complexUnion.isEquivalent(dt));
	}

	@Test
	public void testCloseEditorProviderAndSave() throws Exception {
		Window dialog;
		init(complexUnion, pgmTestCat, false);
		DataType oldDt = model.viewComposite.clone(null);

		// Change the union.
		Swing.runLater(() -> {
			delete(4, 5);
			try {
				model.add(new WordDataType());
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});

		waitForTasks();
		DataType newDt = model.viewComposite.clone(null);
		assertFalse(complexUnion.isEquivalent(model.viewComposite));

		assertTrue(complexUnion.isEquivalent(oldDt));
		Swing.runLater(() -> provider.closeComponent());
		waitForSwing();

		dialog = waitForWindow("Save Union Editor Changes?");
		assertNotNull(dialog);
		pressButton(dialog, "Yes");
		dialog.dispose();
		dialog = null;
		provider = null;
		assertFalse(tool.isVisible(provider));
		assertTrue(complexUnion.isEquivalent(newDt));
		assertFalse(complexUnion.isEquivalent(oldDt));
	}

	@Test
	public void testCloseEditorAndNoSave() throws Exception {
		Window dialog;
		init(complexUnion, pgmTestCat, false);
		DataType oldDt = model.viewComposite.clone(null);

		// Change the union.
		Swing.runLater(() -> {
			delete(4, 5);
			try {
				model.add(new WordDataType());
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});

		waitForTasks();

		DataType newDt = model.viewComposite.clone(null);
		assertFalse(complexUnion.isEquivalent(model.viewComposite));

		assertTrue(complexUnion.isEquivalent(oldDt));
		Swing.runLater(() -> provider.closeComponent());
		waitForSwing();

		dialog = waitForWindow("Save Union Editor Changes?");
		assertNotNull(dialog);
		pressButton(dialog, "Yes");
		dialog.dispose();
		dialog = null;
		assertFalse(tool.isVisible(provider));
		assertTrue(complexUnion.isEquivalent(newDt));
		assertFalse(complexUnion.isEquivalent(oldDt));
	}

	@Test
	public void testCloseEditorAndCancel() throws Exception {
		Window dialog;
		init(complexUnion, pgmTestCat, false);

		// Change the union.
		Swing.runLater(() -> {
			delete(4, 5);
			try {
				model.add(new WordDataType());
			}
			catch (UsrException e) {
				Assert.fail(e.getMessage());
			}
		});

		waitForTasks();
		DataType newDt = model.viewComposite.clone(null);
		assertFalse(complexUnion.isEquivalent(model.viewComposite));

		Swing.runLater(() -> provider.closeComponent());
		waitForSwing();

		dialog = waitForWindow("Save Union Editor Changes?");
		assertNotNull(dialog);
		pressButton(dialog, "Cancel");
		dialog.dispose();
		dialog = null;
		assertTrue(tool.isVisible(provider));
		assertFalse(complexUnion.isEquivalent(model.viewComposite));
		assertTrue(newDt.isEquivalent(model.viewComposite));
	}

	@Test
	public void testChangeHexNumbersOption() throws Exception {
		init(complexUnion, pgmTestCat, false);
		DataType oldDt = model.viewComposite.clone(null);

		Options options = tool.getOptions("Editors");
		String hexNumbersName = "Union Editor" + Options.DELIMITER + "Show Numbers In Hex";

		// Get the hex length option value
		boolean hexLength = options.getBoolean(hexNumbersName, false);
		assertEquals(false, hexLength);
		// Check the length value is in decimal
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("29", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("87", model.getLengthAsString());

		// Set the hex length option value to Hex
		options.setBoolean(hexNumbersName, true);

		// Get the hex length option value
		hexLength = options.getBoolean(hexNumbersName, false);
		assertEquals(true, hexLength);
		// Check the value (length should still be decimal in editor)
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("29", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("87", model.getLengthAsString());

		// Close the editor
		Swing.runLater(() -> provider.closeComponent());
		waitForSwing();
		// Editor should be closed.
		assertFalse(tool.isVisible(provider));
		assertTrue(complexUnion.isEquivalent(oldDt));
		// Re-open the editor
		init(complexUnion, pgmTestCat, true);

		// Get the hex option value (length should now be hexadecimal in editor)
		hexLength = options.getBoolean(hexNumbersName, false);
		assertEquals(true, hexLength);
		// Check the value is in hexadecimal
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x1d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x57", model.getLengthAsString());

		// Set the hex length option value to decimal
		options.setBoolean(hexNumbersName, false);

		// Get the hex option value
		hexLength = options.getBoolean(hexNumbersName, false);
		assertEquals(false, hexLength);
		// Check the value (length should still be hexadecimal in editor)
		assertEquals(true, model.isShowingNumbersInHex());
		assertEquals("0x1d", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("0x57", model.getLengthAsString());

		// Close the editor
		Swing.runLater(() -> provider.closeComponent());
		waitForSwing();
		// Editor should be closed.
		assertFalse(tool.isVisible(provider));
		assertTrue(complexUnion.isEquivalent(oldDt));

		// Re-open the editor
		init(complexUnion, pgmTestCat, false);

		// Get the hex option value (length should now be decimal in editor)
		hexLength = options.getBoolean(hexNumbersName, false);
		assertEquals(false, hexLength);
		// Check the value is in hexadecimal
		assertEquals(false, model.isShowingNumbersInHex());
		assertEquals("29", model.getValueAt(15, model.getLengthColumn()));
		assertEquals("87", model.getLengthAsString());
	}

	private void delete(int... rows) {

		getTable().requestFocus();
		model.setSelection(rows);
		deleteAction.actionPerformed(new ActionContext());
	}
}
