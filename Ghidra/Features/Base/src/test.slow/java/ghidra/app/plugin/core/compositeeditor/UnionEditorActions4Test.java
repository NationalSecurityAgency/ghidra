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
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;

public class UnionEditorActions4Test extends AbstractUnionEditorTest {

	@Test
	public void testArrayOnVarDt() throws Exception {
		init(complexUnion, pgmTestCat, false);
		NumberInputDialog dialog;
		int num = model.getNumComponents();

		setSelection(new int[] { 4 });
		DataType dt4 = getDataType(4);
		assertEquals(2, model.getComponent(4).getLength());

		// Make array of 3 pointers
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 3);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertTrue(((Array) getDataType(4)).getDataType().isEquivalent(dt4));
		assertEquals(6, getDataType(4).getLength());
		assertEquals(6, model.getComponent(4).getLength());
	}

	@Test
	public void testDuplicateMultipleAction() throws Exception {
		NumberInputDialog dialog;
		init(complexUnion, pgmTestCat, false);

		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);

		invoke(duplicateMultipleAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 5);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);

		num += 5;
		assertEquals(num, model.getNumComponents());
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt2);
		assertEquals(getDataType(4), dt2);
		assertEquals(getDataType(5), dt2);
		assertEquals(getDataType(6), dt2);
		assertEquals(getDataType(7), dt2);
		assertEquals(getDataType(8), dt3);
	}

}
