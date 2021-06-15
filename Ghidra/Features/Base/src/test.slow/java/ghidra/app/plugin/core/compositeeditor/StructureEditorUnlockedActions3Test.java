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

import java.awt.Container;
import java.awt.event.KeyEvent;

import javax.swing.JTable;
import javax.swing.JTextField;

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class StructureEditorUnlockedActions3Test
		extends AbstractStructureEditorUnlockedActionsTest {

	@Test
	public void testDuplicateMultipleAction() throws Exception {
		NumberInputDialog dialog;
		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			model.clearComponent(3);
		});
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		DataType dt2 = getDataType(2);// word
		DataType dt7 = getDataType(7);// SimpleUnion

		invoke(duplicateMultipleAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertEquals(num - 2, model.getNumComponents());
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt2);
		assertEquals(getDataType(4), dt2);
		assertEquals(getDataType(5), dt7);
	}

	@Test
	public void testDuplicateVariableSizeDt() throws Exception {
		NumberInputDialog dialog;
		emptyStructure.add(new ByteDataType());
		emptyStructure.add(new StringDataType(), 5);

		init(emptyStructure, pgmTestCat);

		int num = model.getNumComponents();

		setSelection(new int[] { 1 });
		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);

		invoke(duplicateMultipleAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		waitForBusyTool(tool); // the 'Duplicate Multiple' action uses a task

		num += 2;
		assertEquals(num, model.getNumComponents());
		checkSelection(new int[] { 1 });
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt1);
		assertEquals(getDataType(3), dt1);
		assertEquals(getDataType(0).getDisplayName(), "byte");
		assertEquals(getDataType(1).getDisplayName(), "string");
		assertEquals(getDataType(2).getDisplayName(), "string");
		assertEquals(getDataType(3).getDisplayName(), "string");
		assertEquals(1, getLength(0));
		assertEquals(5, getLength(1));
		assertEquals(5, getLength(2));
		assertEquals(5, getLength(3));
	}

	@Test
	public void testEditFieldOnBlankLine() throws Exception {
		init(emptyStructure, pgmTestCat);

		assertFalse(model.isEditingField());
		triggerActionKey(getTable(), editFieldAction);
		assertTrue(model.isEditingField());
		assertEquals(0, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		triggerActionKey(getTable(), 0, KeyEvent.VK_ESCAPE);
	}

	@Test
	public void testEditFieldOnComponent() throws Exception {
		init(complexStructure, pgmTestCat);

		setSelection(new int[] { 3 });
		assertFalse(model.isEditingField());
		invoke(editFieldAction);
		JTable table = getTable();
		Container component = (Container) table.getEditorComponent();
		assertTrue(model.isEditingField());
		assertEquals(3, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		JTextField textField = findComponent(component, JTextField.class);
		triggerText(textField, "Ab\b\b\t");

		assertTrue(model.isEditingField());
		assertEquals(3, model.getRow());

		escape();// Remove the choose data type dialog.
		assertNotEditingField();
	}

	@Test
	public void testEditFieldSetBitfieldDataType() throws Exception {
		init(complexStructure, pgmTestCat);

		DataTypeComponent dtc = model.getComponent(3);
		assertNotNull(dtc);
		assertFalse(dtc.isBitFieldComponent());

		setSelection(new int[] { 3 });
		assertFalse(model.isEditingField());
		invoke(editFieldAction);
		JTable table = getTable();
		Container component = (Container) table.getEditorComponent();
		assertTrue(model.isEditingField());
		assertEquals(3, model.getRow());
		assertEquals(model.getDataTypeColumn(), model.getColumn());

		JTextField textField = findComponent(component, JTextField.class);
		triggerText(textField, "char:2\n");

		waitForSwing();

		assertFalse(model.isEditingField());
		assertEquals(3, model.getRow());
		assertNotEditingField();

		dtc = model.getComponent(3);
		assertNotNull(dtc);
		assertTrue(dtc.isBitFieldComponent());
	}

	@Test
	public void testFavoritesFixedOnBlankLine() {
		init(emptyStructure, pgmTestCat);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = model.getNumComponents();
		assertEquals(0, model.getLength());
		assertEquals(0, model.getNumComponents());
		invoke(fav);
		assertEquals(1, model.getLength());
		assertEquals(num + 1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(dt));
	}

	@Test
	public void testFavoritesFixedOnComponent() {
		init(simpleStructure, pgmBbCat);

		DataType dt = model.getOriginalDataTypeManager().getDataType("/byte");
		assertNotNull(dt);
		FavoritesAction fav = new FavoritesAction(provider, dt);

		int num = model.getNumComponents();
		setSelection(new int[] { 3 });
		assertFalse(getDataType(3).isEquivalent(dt));
		invoke(fav);// replacing dword with byte followed by 3 undefineds
		assertEquals(num + 3, model.getNumComponents());
		assertTrue(getDataType(3).isEquivalent(dt));
		checkSelection(new int[] { 3, 4, 5, 6 });
	}

	@Test
	public void testApplyDescriptionChange() throws Exception {
		init(complexStructure, pgmTestCat);

		String desc = "This is a sample description.";
		runSwing(() -> {
			model.setDescription(desc);
		});
		DataType viewCopy = model.viewComposite.clone(null);

		assertEquals(desc, model.getDescription());
		assertEquals("A complex structure.", complexStructure.getDescription());
		assertTrue(complexStructure.isEquivalent(model.viewComposite));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		invoke(applyAction);
		assertTrue(viewCopy.isEquivalent(complexStructure));
		assertTrue(viewCopy.isEquivalent(model.viewComposite));
		assertEquals(desc, model.getDescription());
		assertEquals(desc, complexStructure.getDescription());
	}
}
