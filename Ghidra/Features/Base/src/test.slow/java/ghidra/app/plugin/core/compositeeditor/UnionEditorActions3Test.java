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

public class UnionEditorActions3Test extends AbstractUnionEditorTest {

	@Test
	public void testArrayOnArray() throws Exception {
		init(complexUnion, pgmTestCat, false);
		NumberInputDialog dialog;
		int num = model.getNumComponents();

		setSelection(new int[] { 11 });
		DataType dt11 = getDataType(11);

		// Make array of 2 arrays
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertEquals("string[2][5]", getDataType(11).getDisplayName());
		assertTrue(((Array) getDataType(11)).getDataType().isEquivalent(dt11));
		assertEquals(90, getDataType(11).getLength());
		assertEquals(90, model.getComponent(11).getLength());
	}

	@Test
	public void testArrayOnFixedDt() throws Exception {
		init(simpleUnion, pgmBbCat, false);
		NumberInputDialog dialog;
		int num = model.getNumComponents();

		setSelection(new int[] { 3 });
		DataType dt3 = getDataType(3);

		// Make array of 5 quadwords
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 5);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertTrue(((Array) getDataType(3)).getDataType().isEquivalent(dt3));
		assertEquals(40, getDataType(3).getLength());
		assertEquals(40, model.getComponent(3).getLength());
	}

}
