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
import ghidra.program.model.data.*;

public class StructureEditorLockedActions4Test extends AbstractStructureEditorLockedActionsTest {

	@Test
	public void testArrayBeforeUndefineds() throws Exception {
		init(simpleStructure, pgmBbCat);
		NumberInputDialog dialog;
		runSwing(() -> {
			getModel().clearComponents(new int[] { 2, 3 });
		});
		setSelection(new int[] { 1 });
		DataType dt1 = getDataType(1);
		DataType dt8 = getDataType(8);

		// Make array of 7 bytes
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		badInput(dialog, 8);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		okInput(dialog, 7);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(6, getModel().getNumComponents());
		assertTrue(((Array) getDataType(1)).getDataType().isEquivalent(dt1));
		assertEquals(7, getDataType(1).getLength());
		assertEquals(7, getModel().getComponent(1).getLength());
		assertEquals(dt8, getDataType(2));
	}

	@Test
	public void testArrayWithNoRoom() throws Exception {
		init(simpleStructure, pgmBbCat);
		NumberInputDialog dialog;
		int num = getModel().getNumComponents();

		setSelection(new int[] { 1 });
		DataType dt1 = getDataType(1);
		checkSelection(new int[] { 1 });

		// Make array of 5 quadwords
		invoke(arrayAction, false);
		waitForPostedSwingRunnables();
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		badInput(dialog, 2);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		okInput(dialog, 1);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, getModel().getNumComponents());
		assertTrue(((Array) getDataType(1)).getDataType().isEquivalent(dt1));
		assertEquals(1, getDataType(1).getLength());
		assertEquals(1, getModel().getComponent(1).getLength());
	}

	@Test
	public void testCycleGroupAsciiLotsOfRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		NumberInputDialog dialog;
		runSwing(() -> {
			getModel().clearComponents(new int[] { 2, 3, 4 });// clear 14 bytes
		});
		DataType dt16 = getDataType(16);
		int dt16Len = getLength(16);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(16), dt16Len);
		assertEquals(getDataType(16), dt16);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		badInput(dialog, 20);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 15);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num - 14, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new StringDataType()));
		checkSelection(new int[] { 1 });
		assertEquals(15, getLength(1));
		assertEquals(getLength(2), dt16Len);
		assertEquals(getDataType(2), dt16);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 10);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num - 9, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new UnicodeDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(6).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(10, getLength(1));
		assertEquals(getLength(7), dt16Len);
		assertEquals(getDataType(7), dt16);

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(16), dt16Len);
		assertEquals(getDataType(16), dt16);
	}

	@Test
	public void testCycleGroupAsciiSomeRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		NumberInputDialog dialog;
		runSwing(() -> {
			getModel().clearComponents(new int[] { 2, 3 });// clear 6 bytes
		});
		DataType dt8 = getDataType(8);
		int dt8Len = getLength(8);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(8), dt8Len);
		assertEquals(getDataType(8), dt8);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 7);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num - 6, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new StringDataType()));
		checkSelection(new int[] { 1 });
		assertEquals(7, getLength(1));
		assertEquals(getLength(2), dt8Len);
		assertEquals(getDataType(2), dt8);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 6);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num - 5, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new UnicodeDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(6, getLength(1));
		assertEquals(getLength(3), dt8Len);
		assertEquals(getDataType(3), dt8);

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new CharDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(7).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(8), dt8Len);
		assertEquals(getDataType(8), dt8);
	}

	@Test
	public void testCycleGroupAsciiNoRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		NumberInputDialog dialog;

		DataType dt1 = getDataType(1);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 0 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(new CharDataType()));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		badInput(dialog, 7);
		okInput(dialog, 1);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(new StringDataType()));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		badInput(dialog, 10);
		okInput(dialog, 1);

		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(new UnicodeDataType()));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(new CharDataType()));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);
	}
}
