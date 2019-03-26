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

import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.DataType;

public class StructureEditorUnlockedCellEdit1Test
		extends AbstractStructureEditorUnlockedCellEditTest {

	@Test
	public void testEditDynamicDataTypeAtLastComponent() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "string";
		int numComponents = simpleStructure.getNumComponents();
		int editRow = numComponents - 1;
		DataType dt = getDataType(editRow);
		int originalLastDtSize = dt.getLength();
		int originalStructSize = 29;
		int newStringComponentSize = 15;

		assertEquals(originalStructSize, model.getLength());
		assertEquals(1, originalLastDtSize);
		editCell(getTable(), editRow, column);
		assertIsEditingField(editRow, column);

		deleteAllInCellEditor();
		type(str);
		enter();

		NumberInputDialog dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, newStringComponentSize);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(editRow, model.getMinIndexSelected());
		assertCellString(str, editRow, column);
		assertEquals(originalStructSize - originalLastDtSize + newStringComponentSize,
			model.getLength());
		assertEquals(-1, getDataType(editRow).getLength());
		assertEquals(newStringComponentSize, model.getComponent(editRow).getLength());
		assertEquals(numComponents, model.getNumComponents());
	}

	@Test
	public void testEditDynamicDataTypeBeyondLastComponent() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "string";
		int numComponents = simpleStructure.getNumComponents();
		int editRow = numComponents;
		DataType dt = getDataType(editRow);
		assertNull(dt);
		int originalStructSize = 29;
		int newStringComponentSize = 15;

		assertEquals(originalStructSize, model.getLength());
		editCell(getTable(), editRow, column);
		assertIsEditingField(editRow, column);

		deleteAllInCellEditor();
		type(str);
		enter();

		NumberInputDialog dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, newStringComponentSize);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(editRow + 1, model.getMinIndexSelected());
		assertCellString(str, editRow, column);
		assertEquals(originalStructSize + newStringComponentSize, model.getLength());
		assertEquals(-1, getDataType(editRow).getLength());
		assertEquals(newStringComponentSize, model.getComponent(editRow).getLength());
		assertEquals(numComponents + 1, model.getNumComponents());
	}

	@Test
	public void testEditDynamicDataTypeInEmptyStructure() throws Exception {
		init(emptyStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "string";
		int numComponents = emptyStructure.getNumComponents();
		int editRow = numComponents;
		DataType dt = getDataType(editRow);
		assertNull(dt);
		int originalStructSize = 0;
		int newStringComponentSize = 15;

		assertEquals(originalStructSize, model.getLength());
		editCell(getTable(), editRow, column);
		assertIsEditingField(editRow, column);

		deleteAllInCellEditor();
		type(str);
		enter();

		NumberInputDialog dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, newStringComponentSize);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(editRow + 1, model.getMinIndexSelected());
		assertCellString(str, editRow, column);
		assertEquals(newStringComponentSize, model.getLength());
		assertEquals(-1, getDataType(editRow).getLength());
		assertEquals(newStringComponentSize, model.getComponent(editRow).getLength());
		assertEquals(numComponents + 1, model.getNumComponents());
	}

	@Test
	public void testEditToVariableDataType() throws Exception {
		init(simpleStructure, pgmBbCat);
		int column = model.getDataTypeColumn();
		String str = "string";
		DataType dt = getDataType(7);

		assertEquals(29, model.getLength());
		assertEquals(1, dt.getLength());
		editCell(getTable(), 7, column);
		assertIsEditingField(7, column);

		deleteAllInCellEditor();
		type(str);
		enter();

		NumberInputDialog dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 15);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		assertNotEditingField();
		assertEquals(1, model.getNumSelectedRows());
		assertEquals(7, model.getMinIndexSelected());
		assertCellString(str, 7, column);
		assertEquals(43, model.getLength());
		assertEquals("string", getDataType(7).getDisplayName());
		assertEquals(15, model.getComponent(7).getLength());
	}

}
