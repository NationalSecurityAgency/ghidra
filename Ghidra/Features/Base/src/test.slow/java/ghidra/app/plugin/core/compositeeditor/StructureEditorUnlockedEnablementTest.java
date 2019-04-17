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

public class StructureEditorUnlockedEnablementTest extends AbstractStructureEditorTest {

	protected void init(Structure dt, final Category cat) {
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
		}
		finally {
			endTransaction(commit);
		}
		final Structure structDt = dt;
		runSwing(() -> {
			installProvider(new StructureEditorProvider(plugin, structDt, false));
			model = provider.getModel();
//				model.setLocked(false);
		});
//		assertTrue(!model.isLocked());
		getActions();
	}

	@Test
	public void testEmptyStructureEditorState() {
		init(emptyStructure, pgmTestCat);

//		assertTrue(!model.isLocked());
//		assertTrue(model.isLockable());
//		model.setLocked(false);
//		assertTrue(!model.isLocked());
		assertEquals(0, model.getNumComponents());// no components
		assertEquals(1, model.getRowCount());// blank row
		assertEquals(0, model.getLength());// size is 0
		assertTrue(model.hasChanges());// empty structure hasn't been saved yet.
		assertTrue(model.isValidName());// name should be valid
		assertEquals(emptyStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertEquals(emptyStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");

		// Check enablement.
		for (CompositeEditorAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) || (action instanceof InsertUndefinedAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction) ||
				(action instanceof ApplyAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNonEmptyStructureEditorState() throws Exception {
		init(simpleStructure, pgmBbCat);

//		assertTrue(model.isLocked());
//		assertTrue(model.isLockable());
//		model.setLocked(false);
//		assertTrue(!model.isLocked());
		assertEquals(simpleStructure.getNumComponents(), model.getNumComponents());
		assertEquals(simpleStructure.getNumComponents() + 1, model.getRowCount());
		assertEquals(simpleStructure.getLength(), model.getLength());
		assertTrue(!model.hasChanges());// no Changes yet
		assertTrue(model.isValidName());// name should be valid
		assertEquals(simpleStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { model.getNumComponents() });
		assertEquals(simpleStructure.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());

		// Check enablement on blank line selected.
		for (CompositeEditorAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) || (action instanceof InsertUndefinedAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testNoSelectionResultsInBlankLineSelect() {
		init(simpleStructure, pgmBbCat);

		// Check enablement when no component selected.
		getTable().clearSelection();
		checkSelection(new int[] { model.getNumComponents() });
	}

	@Test
	public void testFirstComponentSelectedEnablement() {
		init(simpleStructure, pgmBbCat);

		// Check enablement on first component selected.
		setSelection(new int[] { 0 });
		for (CompositeEditorAction action : actions) {
			if ((action instanceof EditFieldAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof MoveDownAction) ||
				(action instanceof ClearAction) || (action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof DeleteAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
				checkEnablement(action, true);
			}
			else if (action instanceof FavoritesAction) {
				FavoritesAction favoritesAction = (FavoritesAction) action;
				String name = favoritesAction.getName();
				checkEnablement(action,
					name.equals("byte") || name.equals("char") || name.equals("string") ||
						name.equals("TerminatedCString") || name.equals("TerminatedUnicode"));
			}
			else if (action instanceof CycleGroupAction) {
				CycleGroupAction cycleGroupAction = (CycleGroupAction) action;
				String name = cycleGroupAction.getName();
				checkEnablement(action,
					name.equals("Cycle: byte,word,dword,qword") ||
						name.equals("Cycle: float,double") ||
						name.equals("Cycle: char,string,unicode") || name.equals("char") ||
						name.equals("string"));
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testCentralComponentSelectedEnablement() {
		init(simpleStructure, pgmBbCat);

		// Check enablement on central component selected.
		runSwing(() -> setSelection(new int[] { 1 }));
		for (CompositeEditorAction action : actions) {
			if ((action instanceof EditFieldAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof MoveDownAction) ||
				(action instanceof MoveUpAction) || (action instanceof ClearAction) ||
				(action instanceof DeleteAction) || (action instanceof ArrayAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
				checkEnablement(action, true);
			}
			else if (action instanceof FavoritesAction) {
				FavoritesAction favoritesAction = (FavoritesAction) action;
				String name = favoritesAction.getName();
				checkEnablement(action,
					name.equals("byte") || name.equals("char") || name.equals("string") ||
						name.equals("TerminatedCString") || name.equals("TerminatedUnicode"));
			}
			else if (action instanceof CycleGroupAction) {
				CycleGroupAction cycleGroupAction = (CycleGroupAction) action;
				String name = cycleGroupAction.getName();
				checkEnablement(action,
					name.equals("Cycle: byte,word,dword,qword") ||
						name.equals("Cycle: float,double") ||
						name.equals("Cycle: char,string,unicode") || name.equals("char") ||
						name.equals("string"));
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testLastComponentSelectedEnablement() {
		init(simpleStructure, pgmBbCat);

		// Check enablement on last component selected.
		setSelection(new int[] { model.getNumComponents() - 1 });
		for (CompositeEditorAction action : actions) {
			if ((action instanceof EditFieldAction) ||
				(action instanceof ShowComponentPathAction) ||
				(action instanceof InsertUndefinedAction) || (action instanceof MoveUpAction) ||
				(action instanceof ClearAction) || (action instanceof DuplicateAction) ||
				(action instanceof DuplicateMultipleAction) || (action instanceof DeleteAction) ||
				(action instanceof ArrayAction) || (action instanceof PointerAction) ||
				(action instanceof HexNumbersAction) ||
				(action instanceof CreateInternalStructureAction)) {
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
						name.equals("Cycle: char,string,unicode") || name.equals("char") ||
						name.equals("string"));
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testBlankLineSelectedEnablement() {
		init(simpleStructure, pgmBbCat);

		// Check enablement on last component selected.
		setSelection(new int[] { model.getNumComponents() });
		for (CompositeEditorAction action : actions) {
			if ((action instanceof FavoritesAction) || (action instanceof CycleGroupAction) ||
				(action instanceof EditFieldAction) || (action instanceof InsertUndefinedAction) ||
				(action instanceof PointerAction) || (action instanceof HexNumbersAction)) {
				checkEnablement(action, true);
			}
			else {
				checkEnablement(action, false);
			}
		}
	}

	@Test
	public void testEditComponentEnablement() {
		init(complexStructure, pgmBbCat);

		setSelection(new int[] { 2 });
		assertEquals("word", getDataType(2).getDisplayName());
		assertTrue(!editComponentAction.isEnabled());

		setSelection(new int[] { 4 });
		assertEquals("simpleUnion", getDataType(4).getDisplayName());
		assertTrue(editComponentAction.isEnabled());

		setSelection(new int[] { 6 });
		assertEquals("simpleStructure *", getDataType(6).getDisplayName());
		assertTrue(editComponentAction.isEnabled());

		setSelection(new int[] { 14 });
		assertEquals("byte[7]", getDataType(14).getDisplayName());
		assertTrue(!editComponentAction.isEnabled());

		setSelection(new int[] { 19 });
		assertEquals("simpleStructureTypedef", getDataType(19).getDisplayName());
		assertTrue(editComponentAction.isEnabled());

		setSelection(new int[] { 21 });
		assertEquals("simpleStructure", getDataType(21).getDisplayName());
		assertTrue(editComponentAction.isEnabled());

		setSelection(new int[] { 23 });
		assertEquals(23, model.getNumComponents());
		assertTrue(!editComponentAction.isEnabled());
	}

	@Test
	public void testUnpackageEnablement() {
		init(complexStructure, pgmBbCat);

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
