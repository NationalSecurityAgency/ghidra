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

import org.junit.Test;

import ghidra.app.plugin.core.compositeeditor.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;

public class PositiveStackEditorEnablementTest extends AbstractStackEditorTest {

	public PositiveStackEditorEnablementTest() {
		super(true);
	}

	@Test
	public void testEmptyStackEditorState() throws Exception {
		init(EMPTY_STACK);

		assertEquals(4, stackModel.getNumComponents());// empty stack always equals absolute value of param offset
		assertEquals(4, stackModel.getRowCount());// blank row
		assertEquals(4, stackModel.getLength());// size is 0
		assertTrue(!stackModel.hasChanges());// no Changes yet
		assertTrue(stackModel.isValidName());// name should be valid
		assertEquals(0, stackModel.getNumSelectedComponentRows());
		assertEquals(0, stackModel.getNumSelectedRows());
		checkSelection(new int[] {});
//		assertTrue(!stackModel.isLocked());
//		assertTrue(!stackModel.isLockable());
		assertEquals(function.getName(), stackModel.getCompositeName());
		assertEquals(stackModel.getTypeName(), "Stack");

		// Check enablement.
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNoVarPosStackEditorState() throws Exception {
		init(NO_VAR_STACK);

		assertEquals(4, stackModel.getNumComponents());// no components
		assertEquals(4, stackModel.getRowCount());// blank row
		assertEquals(4, stackModel.getLength());// size is 0
		assertEquals(0, stackModel.getEditorStack().getNegativeLength());
		assertEquals(4, stackModel.getEditorStack().getPositiveLength());
		assertTrue(!stackModel.hasChanges());// no Changes yet
		assertTrue(stackModel.isValidName());// name should be valid
		assertEquals(0, stackModel.getNumSelectedComponentRows());
		assertEquals(0, stackModel.getNumSelectedRows());
		checkSelection(new int[] {});
//		assertTrue(!stackModel.isLocked());
//		assertTrue(!stackModel.isLockable());
		assertEquals("entry", stackModel.getCompositeName());
		assertEquals(stackModel.getTypeName(), "Stack");

		// Check enablement.
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}

		setSelection(new int[] { 0 });

		// Check enablement.
		int numBytes = getModel().getMaxReplaceLength(0);
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				DataType favDt = fav.getDataType();
				int len = favDt.getLength();
				boolean enabled = ((len <= numBytes) && ((favDt instanceof Pointer) || (len > 0)));
				int offset = model.getComponent(0).getOffset();
				int paramOffset = getModel().getEditorStack().getParameterOffset();
				if (offset < 0 && offset > paramOffset) {
					enabled = false;
				}
				checkEnablement(action, enabled);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof EditFieldAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testSimplePosStackEditorState() throws Exception {
		init(SIMPLE_STACK);

		assertEquals(22, model.getNumComponents());
		assertEquals(22, model.getRowCount());
		assertEquals(0x20, model.getLength());
		assertEquals(0x20, stackFrame.getFrameSize());
		assertTrue(!model.hasChanges());// no Changes yet
		assertTrue(model.isValidName());// name should be valid
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(0, model.getNumSelectedRows());
//		assertTrue(!model.isLocked());
//		assertTrue(!model.isLockable());
		assertEquals("entry", stackModel.getCompositeName());
		assertEquals(stackModel.getTypeName(), "Stack");

		setSelection(new int[] { 19 });// undefined (no variable here).

		int numBytes = getModel().getMaxReplaceLength(19);
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				DataType favDt = fav.getDataType();
				int len = favDt.getLength();
				boolean enabled = ((len <= numBytes) && ((favDt instanceof Pointer) || (len > 0)));
				checkEnablement(action, enabled);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof EditFieldAction) || (action instanceof ClearAction) ||
				(action instanceof PointerAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}

		setSelection(new int[] { 14 });// pointer

		numBytes = getModel().getMaxReplaceLength(14);
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				DataType favDt = fav.getDataType();
				int len = favDt.getLength();
				boolean enabled = (len <= numBytes)
//								&& !(favDt instanceof TerminatedStringDataType)
//								&& !(favDt instanceof TerminatedUnicodeDataType)
				;
				checkEnablement(action, enabled);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof EditFieldAction) || (action instanceof ClearAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testFirstComponentSelectedEnablement() throws Exception {
		init(SIMPLE_STACK);

		// Check enablement on first component selected.
		model.setSelection(new int[] { 0 });
		int numBytes = getModel().getMaxReplaceLength(0);
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				DataType favDt = fav.getDataType();
				int len = favDt.getLength();
				boolean enabled = ((len <= numBytes) && ((favDt instanceof Pointer) || (len > 0)));
				checkEnablement(action, enabled);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof EditFieldAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testCentralComponentSelectedEnablement() throws Exception {
		init(SIMPLE_STACK);

		// Check enablement on central component selected.
		model.setSelection(new int[] { 1 });
		int numBytes = getModel().getMaxReplaceLength(1);
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				DataType favDt = fav.getDataType();
				int len = favDt.getLength();
				boolean enabled = ((len <= numBytes) && ((favDt instanceof Pointer) || (len > 0)));
				checkEnablement(action, enabled);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof EditFieldAction) || (action instanceof ClearAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testLastComponentSelectedEnablement() throws Exception {
		init(SIMPLE_STACK);

		// Check enablement on last component selected.
		model.setSelection(new int[] { model.getNumComponents() - 1 });
		int numBytes = getModel().getMaxReplaceLength(model.getNumComponents() - 1);
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				DataType favDt = fav.getDataType();
				int len = favDt.getLength();
				boolean enabled = ((len <= numBytes) && ((favDt instanceof Pointer) || (len > 0)));
				checkEnablement(action, enabled);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof EditFieldAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testContiguousSelectionEnablement() throws Exception {
		init(SIMPLE_STACK);

		// Check enablement on a contiguous multi-component selection.
		model.setSelection(new int[] { 2, 3, 4 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) || (action instanceof PointerAction) ||
				(action instanceof ClearAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNonContiguousSelectionEnablement() throws Exception {
		init(SIMPLE_STACK);

		// Check enablement on a non-contiguous multi-component selection.
		model.setSelection(new int[] { 2, 3, 6, 7 });
		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof CycleGroupAction) ||
				(action instanceof HexNumbersAction) || (action instanceof ClearAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

}
