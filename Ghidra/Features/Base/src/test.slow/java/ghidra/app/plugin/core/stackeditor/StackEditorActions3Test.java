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
import ghidra.app.plugin.core.compositeeditor.CycleGroupAction;
import ghidra.program.model.data.*;

public class StackEditorActions3Test extends AbstractStackEditorTest {

	public StackEditorActions3Test() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	@Test
	public void testCreatePointerOnUndefined() throws Exception {
		init(SIMPLE_STACK);
		int ordinal = 6;

		setSelection(new int[] { ordinal });
		assertEquals("", model.getStatus());
		invoke(pointerAction);
		assertEquals("", model.getStatus());
		assertEquals("pointer", getDataType(ordinal).getDisplayName());
		assertEquals("pointer", getDataType(ordinal).getName());
		assertNull(((Pointer) getDataType(ordinal)).getDataType());
		assertEquals(4, getDataType(ordinal).getLength());
		assertEquals(4, model.getComponent(ordinal).getLength());
		assertEquals(0x1e, model.getLength());
	}

	@Test
	public void testCycleAsciiOnUndefined() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;

		DataType dt1 = getDataType(1);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), dt3);

		invoke(action);
		dialog = getDialogComponent(NumberInputDialog.class);
		assertNull(dialog);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(1, getLength(2));
		checkSelection(new int[] { 2 });
		assertEquals(getDataType(1), dt1);
		assertTrue(getDataType(2).isEquivalent(new CharDataType()));
		assertEquals(getDataType(3), dt3);
	}

	@Test
	public void testCycleGroupAsciiNoRoom() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;

		DataType dt5 = getDataType(5);
		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 4 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(0x1e, model.getLength());
		assertEquals(20, model.getNumComponents());
		assertEquals(-0x9, getOffset(4));
		assertEquals(0xa, getOffset(model.getNumComponents() - 1));
		checkSelection(new int[] { 4 });
		assertEquals(4, getLength(5));
		assertEquals(getDataType(5), dt5);

		invoke(action);
		dialog = getDialogComponent(NumberInputDialog.class);
		assertNull(dialog);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(20, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(4).isEquivalent(new CharDataType()));
		checkSelection(new int[] { 4 });
		assertEquals(4, getLength(5));
		assertEquals(getDataType(5), dt5);
	}

	@Test
	public void testCycleGroupByteLotsOfRoom() throws Exception {
		init(SIMPLE_STACK);
		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6 });
		model.clearSelectedComponents();

		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 0 });
		CycleGroupAction action = getCycleGroup(new ByteDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(0));

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 1, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new WordDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(2, getLength(0));

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new DWordDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(4, getLength(0));

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 7, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new QWordDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(8, getLength(0));

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new ByteDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(1, getLength(0));

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 1, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new WordDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(2, getLength(0));
	}

	@Test
	public void testCycleGroupByteNoRoom() throws Exception {
		init(SIMPLE_STACK);

		DataType dt5 = getDataType(5);
		int len = model.getLength();

		setSelection(new int[] { 4 });
		CycleGroupAction action = getCycleGroup(new ByteDataType());
		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(20, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(4).isEquivalent(new ByteDataType()));
		checkSelection(new int[] { 4 });
		assertEquals(4, getLength(5));
		assertEquals(getDataType(5), dt5);

		invoke(action);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(20, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(4).isEquivalent(new ByteDataType()));
		checkSelection(new int[] { 4 });
		assertEquals(4, getLength(5));
		assertEquals(getDataType(5), dt5);
	}

	@Test
	public void testCycleGroupByteSomeRoom() throws Exception {
		init(SIMPLE_STACK);

		DataType dt5 = getDataType(5);
		int dt5Len = getLength(5);
		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new ByteDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new ByteDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(5), dt5Len);
		assertEquals(getDataType(5), dt5);

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 1, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(3).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(2, getLength(1));
		assertEquals(getLength(4), dt5Len);
		assertEquals(getDataType(4), dt5);

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new DWordDataType()));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(2), dt5Len);
		assertEquals(getDataType(2), dt5);

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new ByteDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(1, getLength(1));
		assertEquals(getLength(5), dt5Len);
		assertEquals(getDataType(5), dt5);

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 1, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new WordDataType()));
		assertTrue(getDataType(2).isEquivalent(DataType.DEFAULT));
		assertTrue(getDataType(3).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 1 });
		assertEquals(2, getLength(1));
		assertEquals(getLength(4), dt5Len);
		assertEquals(getDataType(4), dt5);
	}

	@Test
	public void testCycleGroupFloatLotsOfRoom() throws Exception {
		init(SIMPLE_STACK);
		setSelection(new int[] { 0, 1, 2, 3, 4, 5, 6 });
		model.clearSelectedComponents();

		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 0 });
		CycleGroupAction action = getCycleGroup(new FloatDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new FloatDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(4, getLength(0));

		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 7, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(0).isEquivalent(new DoubleDataType()));
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 0 });
		assertEquals(8, getLength(0));
	}

	@Test
	public void testCycleGroupFloatNoRoom() throws Exception {
		init(SIMPLE_STACK);

		DataType dt5 = getDataType(5);
		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 4 });
		CycleGroupAction action = getCycleGroup(new FloatDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(4).isEquivalent(DataType.DEFAULT));
		checkSelection(new int[] { 4 });
		assertEquals(4, getLength(5));
		assertEquals(getDataType(5), dt5);
	}

	@Test
	public void testCycleGroupFloatSomeRoom() throws Exception {
		init(SIMPLE_STACK);

		DataType dt5 = getDataType(5);
		int dt5Len = getLength(5);
		int num = model.getNumComponents();
		int len = model.getLength();

		setSelection(new int[] { 1 });
		CycleGroupAction action = getCycleGroup(new FloatDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("", model.getStatus());
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new FloatDataType()));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(2), dt5Len);
		assertEquals(getDataType(2), dt5);

		invoke(action);
		assertEquals("No new data type in the cycle group fits.", model.getStatus());
		assertEquals(num - 3, model.getNumComponents());
		assertEquals(len, model.getLength());
		assertTrue(getDataType(1).isEquivalent(new FloatDataType()));
		checkSelection(new int[] { 1 });
		assertEquals(4, getLength(1));
		assertEquals(getLength(2), dt5Len);
		assertEquals(getDataType(2), dt5);
	}

	@Test
	public void testCycleGroupOnMultiLine() throws Exception {
		init(SIMPLE_STACK);

		DataType dt0 = getDataType(0);
		DataType dt1 = getDataType(1);
		DataType dt2 = getDataType(2);
		DataType dt3 = getDataType(3);
		int num = model.getNumComponents();

		setSelection(new int[] { 1, 2 });
		CycleGroupAction action = getCycleGroup(new CharDataType());

		assertEquals("", model.getStatus());
		invoke(action);
		assertEquals("Can only cycle when a single row is selected.", model.getStatus());
		assertEquals(num, model.getNumComponents());
		checkSelection(new int[] { 1, 2 });
		assertEquals(getDataType(0), dt0);
		assertEquals(getDataType(1), dt1);
		assertEquals(getDataType(2), dt2);
		assertEquals(getDataType(3), dt3);
	}
}
