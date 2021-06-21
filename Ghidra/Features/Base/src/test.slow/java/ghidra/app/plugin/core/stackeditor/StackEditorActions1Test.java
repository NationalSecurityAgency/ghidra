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
package ghidra.app.plugin.core.stackeditor;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.program.model.data.*;

public class StackEditorActions1Test extends AbstractStackEditorTest {

	public StackEditorActions1Test() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	@Test
	public void testArrayOnArray() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;

		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6, 7, 8 });
		invoke(clearAction);
		setSelection(new int[] { 1 });
		invoke(getCycleGroup(new ByteDataType()));

		setSelection(new int[] { 1 });
		DataType dt1 = getDataType(1);

		// Make array of 2 arrays
		assertEquals("", model.getStatus());
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 3);
		assertEquals("", model.getStatus());
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals("", model.getStatus());
		assertEquals(21, model.getNumComponents());
		assertEquals("byte[2][3]", getDataType(1).getName());
		DataType adt = ((Array) getDataType(1)).getDataType();
		assertTrue(((Array) adt).getDataType().isEquivalent(dt1));
		assertEquals(6, getDataType(1).getLength());
		assertEquals(6, model.getComponent(1).getLength());
	}
}
