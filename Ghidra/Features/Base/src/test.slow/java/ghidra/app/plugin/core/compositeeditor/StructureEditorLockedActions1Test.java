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

import ghidra.program.model.data.*;
import ghidra.util.exception.UsrException;

public class StructureEditorLockedActions1Test extends AbstractStructureEditorLockedActionsTest {

	@Test
	public void testArrayOnSelection() throws Exception {
		init(simpleStructure, pgmBbCat);

		setSelection(new int[] { 1, 2, 3 });
		DataType dt1 = getDataType(1);
		DataType dt4 = getDataType(4);

		// Make array of 7 bytes
		invoke(arrayAction);
		assertEquals(6, getModel().getNumComponents());
		assertTrue(((Array) getDataType(1)).getDataType().isEquivalent(dt1));
		assertEquals(7, getDataType(1).getLength());
		assertEquals(7, getModel().getComponent(1).getLength());
		assertEquals(dt4, getDataType(2));
	}

	@Test
	public void testArrayOnSelectionExtraUndefineds() throws Exception {
		init(simpleStructure, pgmBbCat);
		runSwing(() -> {
			try {
				model.clearComponents(new int[] { 4, 5 });
			}
			catch (UsrException e) {
				failWithException("Unexpected error", e);
			}
		});
		setSelection(new int[] { 3, 4, 5, 6, 7, 8, 9, 10 });// starts with DWord 
		DataType dt3 = getDataType(3);
		DataType dt11 = getDataType(11);
		int num = model.getNumComponents();

		// Make array of 7 bytes
		invoke(arrayAction);
		assertEquals(num - 4, getModel().getNumComponents());
		checkSelection(new int[] { 3, 4, 5, 6 });
		assertTrue(((Array) getDataType(3)).getDataType().isEquivalent(dt3));
		assertEquals(8, getDataType(3).getLength());
		assertEquals(8, getModel().getComponent(3).getLength());
		assertEquals(DataType.DEFAULT, getDataType(4));
		assertEquals(DataType.DEFAULT, getDataType(5));
		assertEquals(DataType.DEFAULT, getDataType(6));
		assertEquals(dt11, getDataType(7));
	}

	@Test
	public void testClearAction() throws Exception {
		init(complexStructure, pgmTestCat);
		runSwing(() -> {
			try {
				model.setComponentName(2, "comp2");
				model.setComponentComment(2, "comment 2");
			}
			catch (UsrException e) {
				failWithException("Unexpected error", e);
			}
		});
		int num = getModel().getNumComponents();

		// Duplicate Word
		setSelection(new int[] { 2 });
		DataType dt3 = getDataType(3);

		invoke(clearAction);

		assertEquals(num + 1, getModel().getNumComponents());
		checkSelection(new int[] { 2, 3 });
		assertEquals(getDataType(2), DataType.DEFAULT);
		assertEquals(getDataType(3), DataType.DEFAULT);
		assertEquals(getDataType(4), dt3);
		assertNull(getFieldName(2));
		assertNull(getComment(2));
	}

	@Test
	public void testCreateCycleOnPointer() throws Exception {
		init(simpleStructure, pgmBbCat);
		runSwing(() -> {
			try {
				model.clearComponents(new int[] { 2, 3 });
			}
			catch (UsrException e) {
				failWithException("Unexpected error", e);
			}
		});
		setSelection(new int[] { 1 });
		invoke(pointerAction);
		CycleGroupAction cycleByte = getCycleGroup(new ByteDataType());
		invoke(cycleByte);
		assertEquals(9, getModel().getNumComponents());
		assertEquals("byte *", getDataType(1).getDisplayName());
		assertEquals("byte *", getDataType(1).getName());
		assertTrue(ByteDataType.dataType.isEquivalent(((Pointer) getDataType(1)).getDataType()));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, getModel().getComponent(1).getLength());
		assertEquals(DataType.DEFAULT, getDataType(2));
		assertEquals(29, model.getLength());
		invoke(cycleByte);
		assertEquals(9, getModel().getNumComponents());
		assertEquals("word *", getDataType(1).getDisplayName());
		assertEquals("word *", getDataType(1).getName());
		assertTrue(WordDataType.dataType.isEquivalent(((Pointer) getDataType(1)).getDataType()));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, getModel().getComponent(1).getLength());
		assertEquals(DataType.DEFAULT, getDataType(2));
		assertEquals(29, model.getLength());
	}

	@Test
	public void testCreatePointerOnUndefined() throws Exception {
		init(simpleStructure, pgmBbCat);
		runSwing(() -> {
			model.clearComponent(3);
		});
		setSelection(new int[] { 3 });
		invoke(pointerAction);
		assertEquals("pointer", getDataType(3).getDisplayName());
		assertEquals("pointer", getDataType(3).getName());
		assertNull(((Pointer) getDataType(3)).getDataType());
		assertEquals(4, getDataType(3).getLength());
		assertEquals(4, getModel().getComponent(3).getLength());
		assertEquals(29, model.getLength());
	}

	@Test
	public void testCreatePointerToSelfAndApply() throws Exception {
		init(complexStructure, pgmTestCat);
		int num = getModel().getNumComponents();

		addAtPoint(complexStructure, 3, 0);

		assertEquals(num, getModel().getNumComponents());
		assertEquals("complexStructure *", getDataType(3).getDisplayName());
		assertEquals("complexStructure *32", getDataType(3).getName());
		assertTrue(((Pointer) getDataType(3)).getDataType().isEquivalent(getModel().viewComposite));
		assertEquals(4, getDataType(3).getLength());
		assertEquals(4, getModel().getComponent(3).getLength());

		invoke(applyAction);
		assertTrue(complexStructure.isEquivalent(getModel().viewComposite));
	}

	@Test
	public void testCycleGroupByteLotsOfRoom() throws Exception {
		init(complexStructure, pgmTestCat);
		getModel().clearComponents(new int[] { 2, 3, 4 });// clear 14 bytes

		DataType dt16 = getDataType(16);
		int dt16Len = getLength(16);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new ByteDataType());

		invoke(action);
		assertEquals(num - 1, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(14).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(2, getLength(1));
		assertEquals(getLength(15), dt16Len);
		assertEquals(getDataType(15), dt16);

		invoke(action);
		assertEquals(num - 3, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new DWordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(12).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(13), dt16Len);
		assertEquals(getDataType(13), dt16);

		invoke(action);
		assertEquals(num - 7, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new QWordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(8).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(8, getLength(1));
		assertEquals(getLength(9), dt16Len);
		assertEquals(getDataType(9), dt16);

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new ByteDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(15).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(16), dt16Len);
		assertEquals(getDataType(16), dt16);

		invoke(action);
		assertEquals(num - 1, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(14).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(2, getLength(1));
		assertEquals(getLength(15), dt16Len);
		assertEquals(getDataType(15), dt16);
	}

	@Test
	public void testCycleGroupByteNoRoom() throws Exception {
		init(complexStructure, pgmTestCat);

		DataType dt1 = getDataType(1);
		int num = getModel().getNumComponents();
		int len = getModel().getLength();

		setSelection(new int[] { 0 });
		CycleGroupAction action = getCycleGroup(new ByteDataType());

		invoke(action);
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);

		invoke(action);
		assertTrue(!"".equals(getModel().getStatus()));
		assertEquals(num, getModel().getNumComponents());
		assertEquals(len, getModel().getLength());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(1));
		assertEquals(getDataType(1), dt1);
	}

}
