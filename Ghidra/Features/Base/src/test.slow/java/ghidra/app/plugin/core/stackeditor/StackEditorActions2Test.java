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

import javax.swing.JTextField;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.dialogs.NumberInputDialog;
import ghidra.app.plugin.core.compositeeditor.CycleGroupAction;
import ghidra.app.plugin.core.compositeeditor.FavoritesAction;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;

public class StackEditorActions2Test extends AbstractStackEditorTest {

	public StackEditorActions2Test() {
		super(false);
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		env.showTool();
	}

	@Test
	public void testApplyComponentChange() throws Exception {

		editStack(function.getEntryPoint().toString());

		Variable sv;
		StackFrame stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);
		sv = stack.getVariableContaining(-0x8);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(new DWordDataType()));

		// set local var at -0x8
		setSelection(new int[] { 2 });
		assertEquals("", model.getStatus());
		invoke(getCycleGroup(new ByteDataType()));
		assertEquals("", model.getStatus());

		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xc, stackModel.getParameterSize());

		// Apply the changes
		invoke(applyAction);
		assertEquals("", model.getStatus());
		closeEditor();
		stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x0, stack.getReturnAddressOffset());
		assertEquals(0x14, stack.getLocalSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0xc, stack.getParameterSize());
		sv = stack.getVariableContaining(-0x8);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(new ByteDataType()));
	}

	@Test
	public void testApplyDataTypeChanges() throws Exception {

		editStack(function.getEntryPoint().toString());

		Variable sv;
		StackFrame stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);

		sv = stack.getVariableContaining(0x7);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(ByteDataType.dataType));
		// Change 0x10 to char
		setSelection(new int[] { 11 });
		assertEquals("", model.getStatus());
		invoke(getCycleGroup(new CharDataType()));
		assertEquals("", model.getStatus());
		assertEquals("char", stackModel.getComponent(11).getDataType().getDisplayName());

		sv = stack.getVariableContaining(0xa);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(WordDataType.dataType));
		// Change 0xc to char
		setSelection(new int[] { 15 });
		invoke(pointerAction);
		assertEquals("", model.getStatus());
		FavoritesAction fav = getFavorite("string");
		assertTrue(fav.isEnabled());
		invoke(fav);
		assertEquals("", model.getStatus());
		assertEquals("string *", stackModel.getComponent(15).getDataType().getDisplayName());

		sv = stack.getVariableContaining(-0x8);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(DWordDataType.dataType));
		// set local var at -0x8
		setSelection(new int[] { 4 });
		invoke(pointerAction);
		assertEquals("", model.getStatus());
		assertEquals("pointer", stackModel.getComponent(4).getDataType().getDisplayName());

		sv = stack.getVariableContaining(4);
		assertNull(sv);
		// set local var at -0xa
		setSelection(new int[] { 2 });
		invoke(getCycleGroup(new ByteDataType()));
		assertEquals("", model.getStatus());
		invoke(getCycleGroup(new ByteDataType()));
		assertEquals("", model.getStatus());
		assertEquals("word", stackModel.getComponent(2).getDataType().getDisplayName());

		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xc, stackModel.getParameterSize());

		// Apply the changes
		invoke(applyAction);
		assertEquals("", model.getStatus());
		closeEditor();
		stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x0, stack.getReturnAddressOffset());
		assertEquals(0x14, stack.getLocalSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0xc, stack.getParameterSize());

		sv = stack.getVariableContaining(-0xa);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(DWordDataType.dataType));

		sv = stack.getVariableContaining(-0x8);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(WordDataType.dataType));

		sv = stack.getVariableContaining(-0x4);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(DWordDataType.dataType));

		sv = stack.getVariableContaining(0x7);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(CharDataType.dataType));

		sv = stack.getVariableContaining(0xa);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(WordDataType.dataType));

		sv = stack.getVariableContaining(0xc);
		assertNotNull(sv);
		assertTrue(sv.getDataType().isEquivalent(
			PointerDataType.getPointer(StringDataType.dataType, program.getDataTypeManager())));
	}

	@Test
	public void testApplyLocalSizeChange() throws Exception {

		editStack(function.getEntryPoint().toString());

		StackFrame stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);

		// Change local size from 0x20 to 0x18
		JTextField localSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Local Size", true);
		setField(localSizeField, "0x18");
		assertEquals("", model.getStatus());
		waitForSwing();
		assertEquals(0x24, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x18, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xc, stackModel.getParameterSize());

		// Apply the changes
		invoke(applyAction);
		assertEquals("", model.getStatus());
		stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x14, stack.getLocalSize());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x14, stackModel.getLocalSize());
		closeEditor();
	}

	@Test
	public void testApplyNoVarStack() throws Exception {

		editStack(function.getEntryPoint().toString());

		StackFrame stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);

		// Select all and clear.
		runSwing(() -> getTable().selectAll(), true);
		invoke(clearAction);
		assertEquals("", model.getStatus());
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);

		// Apply the changes
		invoke(applyAction);
		assertEquals("", model.getStatus());
		stack = function.getStackFrame();
		assertEquals(0x4, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x4, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0x0, stackModel.getParameterSize());
		assertEquals(0x4, stack.getFrameSize());
		assertEquals(0x0, stack.getReturnAddressOffset());
		assertEquals(0x4, stack.getLocalSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x0, stack.getParameterSize());
		assertEquals(0, stack.getStackVariables().length);
		closeEditor();
	}

	@Test
	public void testApplyParamSizeChange() throws Exception {

		editStack(function.getEntryPoint().toString());

		StackFrame stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);

		// Change param size from 0x9 to 0xf
		JTextField paramSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Parameter Size", true);
		setField(paramSizeField, "0xf");
		assertEquals("", model.getStatus());
		waitForSwing();
		assertEquals(0x23, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xf, stackModel.getParameterSize());

		setSelection(new int[] { model.getNumComponents() - 1 });
		invoke(getCycleGroup(new ByteDataType()));

		// Apply the changes
		invoke(applyAction);
		assertEquals("", model.getStatus());
		stack = function.getStackFrame();
		assertEquals(0x23, stack.getFrameSize());
		assertEquals(0xf, stack.getParameterSize());
		assertEquals(0x23, stackModel.getFrameSize());
		assertEquals(0xf, stackModel.getParameterSize());
		closeEditor();
	}

	@Test
	public void testApplyParamSizeChangeThatReduces() throws Exception {

		editStack(function.getEntryPoint().toString());

		StackFrame stack = function.getStackFrame();
		assertEquals(0x20, stack.getFrameSize());
		assertEquals(0x4, stack.getParameterOffset());
		assertEquals(0xc, stack.getParameterSize());
		assertEquals(0x20, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0xc, stackModel.getParameterSize());
		assertEquals(7, stack.getStackVariables().length);

		// Change param size from 0xd to 0xf
		JTextField paramSizeField =
			(JTextField) findComponentByName(tool.getToolFrame(), "Parameter Size", true);
		setField(paramSizeField, "0xa");
		assertEquals("", model.getStatus());
		waitForSwing();
		assertEquals(0x1e, stackModel.getFrameSize());
		assertEquals(0x0, stackModel.getReturnAddressOffset());
		assertEquals(0x14, stackModel.getLocalSize());
		assertEquals(0x4, stackModel.getParameterOffset());
		assertEquals(0xa, stackModel.getParameterSize());

		// Apply the changes
		// The apply will drop the undefined at 0xd, and param size will become 0x5.
		invoke(applyAction);
		assertEquals("", model.getStatus());
		stack = function.getStackFrame();
		assertEquals(0x1c, stack.getFrameSize());
		assertEquals(0x8, stack.getParameterSize());
		assertEquals(0x1c, stackModel.getFrameSize());
		assertEquals(0x8, stackModel.getParameterSize());
		closeEditor();
	}

	@Test
	public void testArrayBeforeUndefineds() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;

		setSelection(new int[] { 1 });
		DataType dt1 = getDataType(1);
		DataType dt5 = getDataType(5);
		assertEquals(20, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		assertEquals(1, getDataType(1).getLength());
		assertEquals(1, model.getComponent(1).getLength());

		assertEquals("", model.getStatus());
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		badInput(dialog, 5);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		okInput(dialog, 4);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals("", model.getStatus());
		assertEquals(17, model.getNumComponents());
		assertTrue(((Array) getDataType(1)).getDataType().isEquivalent(dt1));
		assertEquals(4, getDataType(1).getLength());
		assertEquals(4, model.getComponent(1).getLength());
		assertEquals(dt5, getDataType(2));
	}

	@Test
	public void testArrayWithNoRoom() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;
		int num = model.getNumComponents();

		setSelection(new int[] { 0 });
		DataType dt0 = getDataType(0);
		checkSelection(new int[] { 0 });

		assertEquals("", model.getStatus());
		invoke(arrayAction, false);
		waitForSwing();
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Enter Number", dialog.getTitle());
		badInput(dialog, 2);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		assertEquals("Value must be between 1 and 1", dialog.getStatusText());
		assertEquals("Enter Number", dialog.getTitle());
		okInput(dialog, 1);
		dialog = null;
		waitUntilDialogProviderGone(NumberInputDialog.class, 2000);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertTrue(((Array) getDataType(0)).getDataType().isEquivalent(dt0));
		assertEquals(4, getDataType(0).getLength());
		assertEquals(4, model.getComponent(0).getLength());
	}

	@Test
	public void testCancelArray() throws Exception {
		init(SIMPLE_STACK);
		NumberInputDialog dialog;

		setSelection(new int[] { 1 });
		assertEquals(20, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		assertEquals(1, getDataType(1).getLength());
		assertEquals(1, model.getComponent(1).getLength());

		// Cancel the array dialog
		assertEquals("", model.getStatus());
		invoke(arrayAction, false);
		dialog = waitForDialogComponent(NumberInputDialog.class);
		assertNotNull(dialog);
		cancelInput(dialog);
		assertEquals("", model.getStatus());
		dialog = null;
		assertEquals(20, model.getNumComponents());
		assertTrue(getDataType(1).isEquivalent(DataType.DEFAULT));
		assertEquals(1, getDataType(1).getLength());
		assertEquals(1, model.getComponent(1).getLength());
	}

	@Test
	public void testClearAction() throws Exception {
		init(SIMPLE_STACK);
		model.setComponentName(2, "comp0");
		model.setComponentComment(2, "comment 0");

		int num = model.getNumComponents();

		// Duplicate Word
		setSelection(new int[] { 0 });
		DataType dt1 = getDataType(1);

		assertEquals("", model.getStatus());
		invoke(clearAction);
		assertEquals("", model.getStatus());
		assertEquals(num + 3, model.getNumComponents());
		checkSelection(new int[] { 0, 1, 2, 3 });
		assertEquals(getDataType(0), DataType.DEFAULT);
		assertEquals(getDataType(1), DataType.DEFAULT);
		assertEquals(getDataType(2), DataType.DEFAULT);
		assertEquals(getDataType(3), DataType.DEFAULT);
		assertEquals(dt1, getDataType(4));
		assertNull(getFieldName(0));
		assertNull(getComment(0));
	}

	@Test
	public void testCreateCycleDataTypeOnPointer() throws Exception {
		init(SIMPLE_STACK);

		setSelection(new int[] { 0 });
		invoke(pointerAction);
		assertEquals("", model.getStatus());
		assertEquals(20, model.getNumComponents());
		assertCellString("pointer", 0, model.getDataTypeColumn());
		assertEquals("pointer", getDataType(0).getName());
		assertTrue(getDataType(0).isEquivalent(PointerDataType.dataType));
		assertEquals(4, model.getComponent(0).getLength());
		assertEquals("", model.getStatus());

		CycleGroupAction cycleChar = getCycleGroup(new CharDataType());
		invoke(cycleChar);
		assertEquals("", model.getStatus());
		assertEquals(20, model.getNumComponents());
		assertCellString("char *", 0, model.getDataTypeColumn());
		assertEquals("char *", getDataType(0).getName());
		assertTrue(
			getDataType(0).isEquivalent(PointerDataType.getPointer(CharDataType.dataType, null)));
		assertEquals(4, model.getComponent(0).getLength());
		assertEquals("", model.getStatus());

		invoke(cycleChar);
		assertEquals("", model.getStatus());
		assertEquals(20, model.getNumComponents());
		assertCellString("string *", 0, model.getDataTypeColumn());
		assertEquals("string *", getDataType(0).getName());
		assertTrue(
			getDataType(0).isEquivalent(PointerDataType.getPointer(StringDataType.dataType, null)));
		assertEquals(4, model.getComponent(0).getLength());
		assertEquals("", model.getStatus());

	}

	@Test
	public void testCreatePointerOnPointer() throws Exception {
		init(SIMPLE_STACK);
		int ordinal = 5;
		int num = model.getNumComponents();
		assertCellString("pointer32", ordinal, model.getDataTypeColumn());
		assertEquals(4, model.getComponent(ordinal).getLength());
		DataType dt = getDataType(ordinal);

		setSelection(new int[] { ordinal });
		assertEquals("", model.getStatus());
		invoke(pointerAction);
		assertEquals("", model.getStatus());
		assertEquals(num, model.getNumComponents());
		assertCellString("pointer32 *", ordinal, model.getDataTypeColumn());
		assertEquals("pointer32 *", getDataType(ordinal).getName());
		assertTrue(((Pointer) getDataType(ordinal)).getDataType().isEquivalent(dt));
		assertEquals(4, getDataType(ordinal).getLength());
		assertEquals(4, model.getComponent(ordinal).getLength());
	}
}
