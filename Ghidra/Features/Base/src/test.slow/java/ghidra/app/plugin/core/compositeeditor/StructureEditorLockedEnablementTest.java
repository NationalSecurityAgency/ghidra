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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Assert;
import org.junit.Test;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

public class StructureEditorLockedEnablementTest extends AbstractStructureEditorTest {

	@Override
	protected void init(Structure dt, final Category cat, boolean addIfNotThere) {
		boolean commit = true;
		startTransaction("Structure Editor Test Initialization");
		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = (Structure) dt.clone(dataTypeManager);
			}
			CategoryPath categoryPath = cat.getCategoryPath();
			if (!dt.getCategoryPath().equals(categoryPath)) {
				try {
					dt.setCategoryPath(categoryPath);
				}
				catch (DuplicateNameException e) {
					commit = false;
					Assert.fail(e.getMessage());
				}
			}
			if (addIfNotThere && !dataTypeManager.contains(dt)) {
				dataTypeManager.addDataType(dt, null);
			}
		}
		finally {
			endTransaction(commit);
		}
		final Structure structDt = dt;
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, structDt, false));
			model = provider.getModel();
//				model.setLocked(true);
		});
//		assertTrue(model.isLocked());
		getActions();
	}

	@Test
	public void testEmptyStructureEditorState() {
		DataTypeManager catDTM = pgmTestCat.getDataTypeManager();
		Structure desiredEmptyStructure = emptyStructure;
		int txID = program.startTransaction("Removing emptyStruct from DTM.");
		try {
			programDTM.remove(emptyStructure, TaskMonitorAdapter.DUMMY_MONITOR);
			if (emptyStructure.getDataTypeManager() != catDTM) {
				desiredEmptyStructure = (Structure) emptyStructure.copy(catDTM);
				desiredEmptyStructure.setCategoryPath(pgmTestCat.getCategoryPath());
			}
		}
		catch (DuplicateNameException e) {
			Assert.fail(e.getMessage());
		}
		finally {
			program.endTransaction(txID, true);
		}

		init(desiredEmptyStructure, pgmTestCat, false);

//		assertTrue(!getModel().isLocked());
//		assertTrue(getModel().isLockable());
//		getModel().setLocked(true);
		assertEquals(0, getModel().getNumComponents());// no components
		assertEquals(1, getModel().getRowCount());// blank row
		assertEquals(0, getModel().getLength());// size is 0
		assertTrue(getModel().hasChanges());// new empty structure that hasn't been saved yet
		assertTrue(getModel().isValidName());// name should be valid
		assertEquals(emptyStructure.getDescription(), getModel().getDescription());
		assertEquals(0, getModel().getNumSelectedComponentRows());
		assertEquals(1, getModel().getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertEquals(emptyStructure.getName(), getModel().getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(),
			getModel().getOriginalCategoryPath().getPath());
		assertEquals(getModel().getTypeName(), "Structure");

		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof EditFieldAction) || (action instanceof AddBitFieldAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction) || (action instanceof ApplyAction)) {
				checkEnablement(action, true);
			}
			else if (action instanceof FavoritesAction) {
				FavoritesAction favoritesAction = (FavoritesAction) action;
				String name = favoritesAction.getName();
				checkEnablement(action,
					name.equals("byte") || name.equals("word") || name.equals("dword") ||
						name.equals("qword") || name.equals("int") || name.equals("long") ||
						name.equals("uint") || name.equals("ulong") || name.equals("float") ||
						name.equals("double") || name.equals("longdouble") || name.equals("char") ||
						name.equals("string") || name.equals("TerminatedCString") ||
						name.equals("TerminatedUnicode") || name.equals("pointer"));
			}
			else if (action instanceof CycleGroupAction) {
				CycleGroupAction cycleGroupAction = (CycleGroupAction) action;
				String name = cycleGroupAction.getName();
				checkEnablement(action,
					name.equals("Cycle: byte,word,dword,qword") ||
						name.equals("Cycle: float,double") ||
						name.equals("Cycle: char,string,unicode"));
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNonEmptyStructureEditorState() {
		init(simpleStructure, pgmBbCat, false);

//		assertTrue(getModel().isLocked());
//		assertTrue(getModel().isLockable());
		assertEquals(simpleStructure.getNumComponents(), getModel().getNumComponents());
		assertEquals(simpleStructure.getNumComponents() + 1, getModel().getRowCount());
		assertEquals(simpleStructure.getLength(), getModel().getLength());
		assertTrue(!getModel().hasChanges());// no Changes yet
		assertTrue(getModel().isValidName());// name should be valid
		assertEquals(simpleStructure.getDescription(), getModel().getDescription());
		assertEquals(0, getModel().getNumSelectedComponentRows());
		assertEquals(1, getModel().getNumSelectedRows());
		checkSelection(new int[] { 8 });
		assertEquals(simpleStructure.getName(), getModel().getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(),
			getModel().getOriginalCategoryPath().getPath());

		for (CompositeEditorTableAction action : actions) {
			if ((action instanceof EditFieldAction) || (action instanceof AddBitFieldAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else if (action instanceof FavoritesAction) {
				FavoritesAction favoritesAction = (FavoritesAction) action;
				String name = favoritesAction.getName();
				checkEnablement(action,
					name.equals("byte") || name.equals("word") || name.equals("dword") ||
						name.equals("qword") || name.equals("int") || name.equals("long") ||
						name.equals("uint") || name.equals("ulong") || name.equals("float") ||
						name.equals("double") || name.equals("longdouble") || name.equals("char") ||
						name.equals("string") || name.equals("TerminatedCString") ||
						name.equals("TerminatedUnicode") || name.equals("pointer"));
			}
			else if (action instanceof CycleGroupAction) {
				CycleGroupAction cycleGroupAction = (CycleGroupAction) action;
				String name = cycleGroupAction.getName();
				checkEnablement(action,
					name.equals("Cycle: byte,word,dword,qword") ||
						name.equals("Cycle: float,double") ||
						name.equals("Cycle: char,string,unicode"));
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testUndefinedFirstComponentSelectedEnablement() {
		init(simpleStructure, pgmBbCat, true);

		// Check enablement on first component selected.
		setSelection(new int[] { 0 });
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				int len = fav.getDataType().getLength();
				int numBytes = getModel().getMaxReplaceLength(0);
				checkEnablement(action, len <= numBytes);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof EditFieldAction) ||
				(action instanceof AddBitFieldAction) ||
				(action instanceof ShowComponentPathAction) || (action instanceof MoveDownAction) ||
				(action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testCentralComponentSelectedEnablement() {
		init(simpleStructure, pgmBbCat, true);

		// Check enablement on central component selected.
		setSelection(new int[] { 3 });
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				int len = fav.getDataType().getLength();
				int numBytes = getModel().getMaxReplaceLength(3);
				checkEnablement(action, len <= numBytes);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof EditFieldAction) ||
				(action instanceof AddBitFieldAction) ||
				(action instanceof ShowComponentPathAction) || (action instanceof MoveUpAction) ||
				(action instanceof MoveDownAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testLastComponentSelectedEnablement() {
		init(simpleStructure, pgmBbCat, true);

		int last = getModel().getNumComponents() - 1;

		// Check enablement on last component selected.
		setSelection(new int[] { last });
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				checkEnablement(action, true);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof EditFieldAction) ||
				(action instanceof AddBitFieldAction) ||
				(action instanceof ShowComponentPathAction) || (action instanceof MoveUpAction) ||
				(action instanceof ClearAction) || (action instanceof DeleteAction) ||
				(action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testContiguousSelectionEnablement() {
		init(complexStructure, pgmTestCat, true);

		// Check enablement on a contiguous multi-component selection.
		setSelection(new int[] { 2, 3, 4 });
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				int len = fav.getDataType().getLength();
				int numBytes =
					getModel().getNumBytesInRange(getModel().getSelectedRangeContaining(2));
				checkEnablement(action, len <= numBytes);
			}
			else if ((action instanceof CycleGroupAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof MoveUpAction) ||
				(action instanceof MoveDownAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNonContiguousSelectionEnablement() {
		init(complexStructure, pgmTestCat, true);

		// Check enablement on a non-contiguous multi-component selection.
		setSelection(new int[] { 2, 3, 6, 7 });
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				FavoritesAction fav = (FavoritesAction) action;
				int len = fav.getDataType().getLength();
				int numBytes =
					getModel().getNumBytesInRange(getModel().getSelectedRangeContaining(2));
				checkEnablement(action, len <= numBytes);
			}
			else if ((action instanceof CycleGroupAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testMultiDupEnablement() throws Exception {
		init(complexStructure, pgmBbCat, true);
		model.clearComponents(new int[] { 3, 10 });

		setSelection(new int[] { 0 });
		assertEquals("undefined", getDataType(0).getDisplayName());
		assertTrue(duplicateAction.isEnabled());
		assertTrue(duplicateMultipleAction.isEnabled());

		setSelection(new int[] { 1 });
		assertEquals("byte", getDataType(1).getDisplayName());
		assertTrue(!duplicateAction.isEnabled());
		assertTrue(!duplicateMultipleAction.isEnabled());

		setSelection(new int[] { 2 });
		assertEquals("word", getDataType(2).getDisplayName());
		assertTrue(duplicateAction.isEnabled());
		assertTrue(duplicateMultipleAction.isEnabled());

		setSelection(new int[] { 3 });
		assertEquals("undefined", getDataType(3).getDisplayName());
		assertTrue(duplicateAction.isEnabled());
		assertTrue(duplicateMultipleAction.isEnabled());

		setSelection(new int[] { 11 });
		assertEquals("byte * *", getDataType(11).getDisplayName());
		assertTrue(!duplicateAction.isEnabled());
		assertTrue(!duplicateMultipleAction.isEnabled());

		setSelection(new int[] { 12 });
		assertEquals("simpleUnion *", getDataType(12).getDisplayName());
		assertTrue(duplicateAction.isEnabled());
		assertTrue(duplicateMultipleAction.isEnabled());

		setSelection(new int[] { 13 });
		assertEquals("undefined", getDataType(13).getDisplayName());
		assertTrue(duplicateAction.isEnabled());
		assertTrue(duplicateMultipleAction.isEnabled());

		int lastComponentIndex = model.getNumComponents() - 1;
		setSelection(new int[] { lastComponentIndex });
		assertEquals("refStructure *", getDataType(lastComponentIndex).getDisplayName());
		assertTrue(duplicateAction.isEnabled());
		assertTrue(duplicateMultipleAction.isEnabled());
	}

	@Test
	public void testUnpackageEnablement() {
		init(complexStructure, pgmBbCat, true);

		setSelection(new int[] { 2 });
		assertEquals("word", getDataType(2).getDisplayName());
		assertTrue(!unpackageAction.isEnabled());

		setSelection(new int[] { 4 });
		assertEquals("simpleUnion", getDataType(4).getDisplayName());
		assertTrue(!unpackageAction.isEnabled());

		setSelection(new int[] { 6 });
		assertEquals("simpleStructure *", getDataType(6).getDisplayName());
		assertTrue(!unpackageAction.isEnabled());

		setSelection(new int[] { 14 });
		assertEquals("byte[7]", getDataType(14).getDisplayName());
		assertTrue(unpackageAction.isEnabled());

		setSelection(new int[] { 19 });
		assertEquals("simpleStructureTypedef", getDataType(19).getDisplayName());
		assertTrue(!unpackageAction.isEnabled());

		setSelection(new int[] { 21 });
		assertEquals("simpleStructure", getDataType(21).getDisplayName());
		assertTrue(unpackageAction.isEnabled());

		setSelection(new int[] { 23 });
		assertEquals(23, model.getNumComponents());
		assertTrue(!unpackageAction.isEnabled());
	}

}
