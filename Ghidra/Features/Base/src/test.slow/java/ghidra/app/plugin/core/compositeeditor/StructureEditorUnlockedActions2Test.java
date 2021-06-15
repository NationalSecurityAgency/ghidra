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

public class StructureEditorUnlockedActions2Test
		extends AbstractStructureEditorUnlockedActionsTest {

	@Test
	public void testCreatePointerOnStructPointer() {
		init(complexStructure, pgmTestCat);
		int num = model.getNumComponents();

		setSelection(new int[] { 6 });
		DataType dt6 = getDataType(6);
		assertEquals("simpleStructure *", dt6.getDisplayName());
		assertEquals(4, model.getComponent(6).getLength());
		invoke(pointerAction);
		assertEquals(num, model.getNumComponents());
		assertEquals("simpleStructure * *", getDataType(6).getDisplayName());
		assertTrue(((Pointer) getDataType(6)).getDataType().isEquivalent(dt6));
		assertEquals(4, getDataType(6).getLength());
		assertEquals(4, model.getComponent(6).getLength());
	}

	@Test
	public void testCreateStringOnPointerDataType() throws Exception {
		emptyStructure.add(new ByteDataType());
		emptyStructure.add(new StringDataType(), 5);
		emptyStructure.add(new WordDataType());

		init(emptyStructure, pgmTestCat);
		int num = model.getNumComponents();

		setSelection(new int[] { 1 });
		assertTrue(getDataType(1).isEquivalent(new StringDataType()));
		assertEquals(5, model.getComponent(1).getLength());

		invoke(pointerAction);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals("pointer", getDataType(1).getDisplayName());
		assertNull(((Pointer) getDataType(1)).getDataType());
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertEquals(1, model.getComponent(2).getLength());

		setSelection(new int[] { 1 });
		CycleGroupAction charCycleAction = getCycleGroup(CharDataType.dataType);
		invoke(charCycleAction);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals("char *", getDataType(1).getDisplayName());
		assertTrue(((Pointer) getDataType(1)).getDataType().isEquivalent(CharDataType.dataType));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertEquals(1, model.getComponent(2).getLength());

		invoke(charCycleAction);
		assertEquals(num + 1, model.getNumComponents());
		assertEquals("string *", getDataType(1).getDisplayName());
		assertTrue(((Pointer) getDataType(1)).getDataType().isEquivalent(StringDataType.dataType));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertEquals(1, model.getComponent(2).getLength());

	}

	@Test
	public void testCycleGroupOnBlankLine() {
		init(emptyStructure, pgmTestCat);

		assertEquals(0, model.getNumComponents());
		checkSelection(new int[] { 0 });

		CycleGroupAction action = getCycleGroup(new ByteDataType());
		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		assertEquals(1, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new WordDataType()));
		assertEquals(2, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new DWordDataType()));
		assertEquals(4, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new QWordDataType()));
		assertEquals(8, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(action);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		assertEquals(1, getLength(0));
		checkSelection(new int[] { 0 });

		CycleGroupAction floatAction = getCycleGroup(new FloatDataType());
		invoke(floatAction);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new FloatDataType()));
		assertEquals(4, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(floatAction);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new DoubleDataType()));
		assertEquals(8, getLength(0));
		checkSelection(new int[] { 0 });

		invoke(floatAction);
		assertEquals(1, model.getNumComponents());
		assertTrue(getDataType(0).isEquivalent(new FloatDataType()));
		assertEquals(4, getLength(0));
		checkSelection(new int[] { 0 });
	}

	@Test
	public void testCycleGroupOnComponent() throws Exception {
		init(simpleStructure, pgmBbCat);
		NumberInputDialog dialog;

		DataType dt1 = getDataType(1);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		invoke(action);// CHange word to char followed by 1 undefined
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), DataType.DEFAULT);
		assertEquals(getDataType(4), dt3);

		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertEquals(2, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new StringDataType()));
		assertEquals(getDataType(3), dt3);

		setSelection(new int[] { 2 });
		invoke(action, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		okInput(dialog, 2);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals(num, model.getNumComponents());
		assertEquals(2, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new UnicodeDataType()));
		assertEquals(getDataType(3), dt3);

		invoke(action);// Change from unicode back to char and 1 undefined
		assertEquals(num + 1, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), DataType.DEFAULT);
		assertEquals(getDataType(4), dt3);
	}

	@Test
	public void testCycleGroupOnMultiLine() throws Exception {
		init(simpleStructure, pgmBbCat);

		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 1, 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals(num, model.getNumComponents());
		checkSelection(new int[] { 1, 2 });
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt3);
		assertNotEquals("", model.getStatus());
	}

	@Test
	public void testDeleteContiguousAtEndAction() {
		init(complexStructure, pgmTestCat);

		DataType dt3 = getDataType(3);
		DataType dt19 = getDataType(19);
		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 20, 21, 22 });
		// simpleStructureTypedef * *[2][3]   length = 24
		// simpleStructure                    length = 29
		// refStructure *                     length =  4
		invoke(deleteAction);
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(getDataType(3), dt3);
		assertEquals(getDataType(19), dt19);
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(model.getLength(), len - 57);
	}

	@Test
	public void testDeleteNonContiguousAction() {
		init(complexStructure, pgmTestCat);

		DataType dt1 = getDataType(1);
		DataType dt20 = getDataType(20);

		int num = model.getNumComponents();
		int len = model.getLength();
		setSelection(new int[] { 0, 21, 22 });
		invoke(deleteAction);
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(getDataType(0), dt1);
		assertEquals(getDataType(19), dt20);
		assertEquals(1, model.getNumSelectedComponentRows());
		assertEquals(model.getLength(), len - (1 + 29 + 4));
	}

	@Test
	public void testDeleteOneCompAtEnd() {
		init(complexStructure, pgmTestCat);

		int len = model.getLength();
		int num = model.getNumComponents();
		setSelection(new int[] { 22 });// refStructure *
		invoke(deleteAction);
		assertEquals(model.getLength(), len - 4);
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(num - 1, model.getNumComponents());
	}
}
