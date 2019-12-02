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

import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

public class StructureEditorUnlockedActions4Test
		extends AbstractStructureEditorUnlockedActionsTest {

	@Test
	public void testChangeSizeToZero() throws Exception {
		init(complexStructure, pgmTestCat);
		int originalLength = complexStructure.getLength();
		int newLength = 0;

		assertEquals(originalLength, model.getLength());

		waitForSwing();
		JTextField textField =
			(JTextField) findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(textField);

		setText(textField, Integer.toString(newLength));
		triggerEnter(textField);

		Window truncateDialog = waitForWindow("Truncate Structure In Editor?");
		assertNotNull(truncateDialog);
		pressButtonByText(truncateDialog, "Yes");
		waitForSwing();

		assertEquals(newLength, model.getLength());
		invoke(applyAction);
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertEquals(1, complexStructure.getLength());
		assertTrue(complexStructure.isNotYetDefined());
	}

	@Test
	public void testArrayOnVarDt() throws Exception {
		init(complexStructure, pgmTestCat);
		NumberInputDialog dialog;
		runSwing(() -> {
			model.clearComponent(6);
		});
		int num = model.getNumComponents();

		setSelection(new int[] { 5 });
		DataType dt5 = getDataType(5);
		assertTrue(dt5 instanceof Pointer);
		assertEquals(2, model.getComponent(5).getLength());

		// Make array of 3 pointers
		invoke(arrayAction);
		dialog = env.waitForDialogComponent(NumberInputDialog.class, 1000);
		assertNotNull(dialog);
		okInput(dialog, 3);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num - 4, model.getNumComponents());
		assertTrue(((Array) getDataType(5)).getDataType().isEquivalent(dt5));
		assertEquals(6, getDataType(5).getLength());
		assertEquals(6, model.getComponent(5).getLength());
	}

	@Test
	public void testDeleteOneUndefinedComp() {
		init(complexStructure, pgmTestCat);

		int len = model.getLength();
		int num = model.getNumComponents();
		setSelection(new int[] { 0 });
		int compLen = model.getComponent(0).getLength();
		invoke(deleteAction);
		assertEquals(model.getLength(), len - compLen);
		assertEquals(1, model.getNumSelectedComponentRows());
		assertEquals(0, model.getSelectedRows()[0]);
		assertEquals(num - 1, model.getNumComponents());
	}

	@Test
	public void testDuplicateAction() throws Exception {
		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			try {
				model.setComponentName(1, "comp1");
				model.setComponentComment(1, "comment 1");
				model.clearComponent(2);
			}
			catch (InvalidInputException e) {
				failWithException("Unexpected error", e);
			}
			catch (InvalidNameException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			catch (DuplicateNameException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		});
		int len = model.getLength();
		int num = model.getNumComponents();

		// Duplicate Byte
		setSelection(new int[] { 1 });
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		invoke(duplicateAction);
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		checkSelection(new int[] { 1 });
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt1);
		assertEquals(getDataType(3), dt2);
		assertEquals("comp1", getFieldName(1));
		assertEquals("comment 1", getComment(1));
		assertNull(getFieldName(2));
		assertNull(getComment(2));

		// Can't duplicate blank line
		listener.clearStatus();
		setSelection(new int[] { model.getNumComponents() });
		assertFalse(runSwing(() -> duplicateAction.isEnabled()));
	}

	@Test
	public void testEditComponentAction() throws Exception {
		//		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, complexStructure, false));
			model = provider.getModel();
		});
		waitForSwing();
		getActions();

		assertEquals("", model.getStatus());
		setSelection(new int[] { 21 });
		String complexSubTitle = getProviderSubTitle(complexStructure);
		String simpleSubTitle = getProviderSubTitle(simpleStructure);
		assertTrue("Couldn't find editor = " + complexSubTitle,
			isProviderShown(tool.getToolFrame(), "Structure Editor", complexSubTitle));
		assertTrue(!isProviderShown(tool.getToolFrame(), "Structure Editor", simpleSubTitle));
		invoke(editComponentAction);
		assertEquals("", model.getStatus());
		assertTrue("Couldn't find editor = " + complexSubTitle,
			isProviderShown(tool.getToolFrame(), "Structure Editor", complexSubTitle));
		assertTrue("Couldn't find editor = " + simpleSubTitle,
			isProviderShown(tool.getToolFrame(), "Structure Editor", simpleSubTitle));

		runSwing(() -> provider.closeComponent());
	}

	@Test
	public void testFavoritesFixedOnMultiple() {
		init(simpleStructure, pgmBbCat);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = model.getNumComponents();
		setSelection(new int[] { 3, 4, 5 });// 16 bytes selected
		DataType dt6 = getDataType(6);
		invoke(fav);
		assertTrue(getDataType(3).isEquivalent(dt));
		assertTrue(getDataType(18).isEquivalent(dt));
		assertTrue(getDataType(19).isEquivalent(dt6));
		checkSelection(new int[] { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 });
		assertEquals(num + 13, model.getNumComponents());
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

	//	@Test
	//	public void testCreatePointerOnArray() throws Exception {
	//		init(complexStructure, pgmTestCat);
	//		int num = model.getNumComponents();
	//
	//		setSelection(new int[] { 14 });
	//		DataType dt14 = getDataType(14);
	//		assertEquals("byte[7]", dt14.getDisplayName());
	//		invoke(pointerAction);
	//		assertEquals(num + 3, model.getNumComponents());
	//		assertEquals("byte[7] *", getDataType(14).getDisplayName());
	//		assertTrue(((Pointer) getDataType(14)).getDataType().isEquivalent(dt14));
	//		assertEquals(4, getDataType(14).getLength());
	//		assertEquals(4, model.getComponent(14).getLength());
	//	}
	//
	//	@Test
	//	public void testCreatePointerOnTypedef() throws Exception {
	//		init(complexStructure, pgmTestCat);
	//		int num = model.getNumComponents();
	//
	//		setSelection(new int[] { 19 });
	//		DataType dt19 = getDataType(19);
	//		assertEquals("simpleStructureTypedef", dt19.getDisplayName());
	//		invoke(pointerAction);
	//		assertEquals(num + 25, model.getNumComponents());
	//		assertEquals("simpleStructureTypedef *", getDataType(19).getDisplayName());
	//		assertTrue(((Pointer) getDataType(19)).getDataType().isEquivalent(dt19));
	//		assertEquals(4, model.getComponent(19).getLength());
	//	}

	@Test
	public void testApplyComponentChange() throws Exception {
		init(complexStructure, pgmTestCat);

		setSelection(new int[] { 3, 4 });
		runSwing(() -> {
			try {
				model.clearSelectedComponents();
				model.deleteSelectedComponents(TaskMonitor.DUMMY);
			}
			catch (UsrException e) {
				failWithException("Unexpected error", e);
			}
		});
		DataType viewCopy = model.viewComposite.clone(null);

		assertTrue(!complexStructure.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		invoke(applyAction);
		assertTrue(viewCopy.isEquivalent(complexStructure));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
	}
}
