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

public class StructureEditorUnlockedActions6Test
		extends AbstractStructureEditorUnlockedActionsTest {

	@Test
	public void testArrayOnArray() throws Exception {
		init(complexStructure, pgmTestCat);
		NumberInputDialog dialog;
		runSwing(() -> {
			model.clearComponent(16);
		});
		int num = model.getNumComponents();

		setSelection(new int[] { 15 });
		DataType dt15 = getDataType(15);
		assertTrue(dt15 instanceof Array);

		// Make array of 2 arrays
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertEquals(num - 45, model.getNumComponents());
		assertEquals("string[2][5]", getDataType(15).getDisplayName());
		assertTrue(((Array) getDataType(15)).getDataType().isEquivalent(dt15));
		assertEquals(90, getDataType(15).getLength());
		assertEquals(90, model.getComponent(15).getLength());
	}

	@Test
	public void testArrayOnFixedDt() throws Exception {
		init(simpleStructure, pgmBbCat);
		NumberInputDialog dialog;
		runSwing(() -> {
			getModel().clearComponents(new int[] { 4, 5, 6 });
		});
		int num = model.getNumComponents();

		setSelection(new int[] { 3 });
		DataType dt3 = getDataType(3);
		assertEquals("dword", dt3.getDisplayName());

		// Make array of 5 quadwords
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 5);
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertEquals("dword[5]", getDataType(3).getDisplayName());
		assertEquals(num - 16, model.getNumComponents());
		assertTrue(((Array) getDataType(3)).getDataType().isEquivalent(dt3));
		assertEquals(20, getDataType(3).getLength());
		assertEquals(20, model.getComponent(3).getLength());
	}

	@Test
	public void testChangeSizeFromZero() throws Exception {
		init(emptyStructure, pgmRootCat);
		int originalLength = 0;
		assertTrue(emptyStructure.isNotYetDefined());
		assertTrue(emptyStructure.isZeroLength());
		int newLength = 5;

		assertEquals(originalLength, model.getLength());
		assertEquals(0, model.getNumComponents());

		waitForSwing();
		JTextField textField =
			(JTextField) findComponentByName(provider.editorPanel, "Total Length");
		assertNotNull(textField);

		setText(textField, Integer.toString(newLength));
		triggerEnter(textField);

		Window truncateDialog = getWindow("Truncate Structure In Editor?");
		assertNull(truncateDialog);

		assertEquals(newLength, model.getLength());

		waitForSwing();

		assertEquals(newLength, model.getLength());
		assertEquals(5, model.getNumComponents());
		invoke(applyAction);
		DataTypeManager originalDTM = model.getOriginalDataTypeManager();
		Structure appliedStructure =
			(Structure) originalDTM.getDataType(pgmRootCat.getCategoryPath(),
				emptyStructure.getName());
		assertTrue(appliedStructure.isEquivalent(model.viewComposite));
		assertEquals(newLength, appliedStructure.getLength());
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
	public void testFavoritesVariableOnBlank() throws Exception {
		init(emptyStructure, pgmTestCat);
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
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertEquals(7, model.getLength());
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
		assertEquals(7, getLength(0));
	}
}
