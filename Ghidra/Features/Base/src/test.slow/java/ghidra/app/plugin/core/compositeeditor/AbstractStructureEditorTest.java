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

import javax.swing.JTextField;

import org.junit.Assert;

import ghidra.program.model.data.*;
import ghidra.util.exception.DuplicateNameException;

public abstract class AbstractStructureEditorTest extends AbstractEditorTest {

	StructureEditorModel structureModel;

	// Editor Actions
	ApplyAction applyAction;
	ArrayAction arrayAction;
	ClearAction clearAction;
	CreateInternalStructureAction createInternalStructureAction;
	DeleteAction deleteAction;
	DuplicateAction duplicateAction;
	DuplicateMultipleAction duplicateMultipleAction;
	EditComponentAction editComponentAction;
	EditBitFieldAction editBitFieldAction;
	EditFieldAction editFieldAction;
	MoveDownAction moveDownAction;
	MoveUpAction moveUpAction;
	PointerAction pointerAction;
	ShowComponentPathAction showComponentPathAction;
	UnpackageAction unpackageAction;
	InsertUndefinedAction insertUndefinedAction;
	HexNumbersAction hexNumbersAction;

	StructureEditorModel getModel() {
		return (StructureEditorModel) model;
	}

	protected void init(Structure dt, final Category cat, final boolean showInHex) {

		assertEquals("Category path mismatch", dt.getCategoryPath(), cat.getCategoryPath());

		boolean commit = true;
		startTransaction("Structure Editor Test Initialization");
		try {
			DataTypeManager dataTypeManager = cat.getDataTypeManager();
			if (dt.getDataTypeManager() != dataTypeManager) {
				dt = dt.clone(dataTypeManager);
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
			installProvider(new StructureEditorProvider(plugin, structDt, showInHex));
			model = provider.getModel();
		});
		waitForSwing();
		getActions();
		structureModel = (StructureEditorModel) model;
	}

	protected void cleanup() {
		clearActions();
		runSwing(() -> provider.dispose());
	}

	void clearActions() {
		actions = null;
		favorites.clear();
		cycles.clear();
		applyAction = null;
		arrayAction = null;
		clearAction = null;
		createInternalStructureAction = null;
		deleteAction = null;
		duplicateAction = null;
		duplicateMultipleAction = null;
		editComponentAction = null;
		editBitFieldAction = null;
		editFieldAction = null;
		moveDownAction = null;
		moveUpAction = null;
		pointerAction = null;
		showComponentPathAction = null;
		unpackageAction = null;
		insertUndefinedAction = null;
		hexNumbersAction = null;
	}

	void getActions() {
		actions = provider.getActions();
		for (CompositeEditorTableAction action : actions) {
			if (action instanceof FavoritesAction) {
				favorites.add((FavoritesAction) action);
			}
			else if (action instanceof CycleGroupAction) {
				cycles.add((CycleGroupAction) action);
			}
			else if (action instanceof ApplyAction) {
				applyAction = (ApplyAction) action;
			}
			else if (action instanceof ArrayAction) {
				arrayAction = (ArrayAction) action;
			}
			else if (action instanceof ClearAction) {
				clearAction = (ClearAction) action;
			}
			else if (action instanceof CreateInternalStructureAction) {
				createInternalStructureAction = (CreateInternalStructureAction) action;
			}
			else if (action instanceof DeleteAction) {
				deleteAction = (DeleteAction) action;
			}
			else if (action instanceof DuplicateAction) {
				duplicateAction = (DuplicateAction) action;
			}
			else if (action instanceof DuplicateMultipleAction) {
				duplicateMultipleAction = (DuplicateMultipleAction) action;
			}
			else if (action instanceof EditComponentAction) {
				editComponentAction = (EditComponentAction) action;
			}
			else if (action instanceof EditBitFieldAction) {
				editBitFieldAction = (EditBitFieldAction) action;
			}
			else if (action instanceof EditFieldAction) {
				editFieldAction = (EditFieldAction) action;
			}
			else if (action instanceof MoveDownAction) {
				moveDownAction = (MoveDownAction) action;
			}
			else if (action instanceof MoveUpAction) {
				moveUpAction = (MoveUpAction) action;
			}
			else if (action instanceof PointerAction) {
				pointerAction = (PointerAction) action;
			}
			else if (action instanceof ShowComponentPathAction) {
				showComponentPathAction = (ShowComponentPathAction) action;
			}
			else if (action instanceof UnpackageAction) {
				unpackageAction = (UnpackageAction) action;
			}
			else if (action instanceof InsertUndefinedAction) {
				insertUndefinedAction = (InsertUndefinedAction) action;
			}
			else if (action instanceof HexNumbersAction) {
				hexNumbersAction = (HexNumbersAction) action;
			}
		}
	}

	String getMnemonic(int index) {
		return (String) model.getValueAt(index, model.getMnemonicColumn());
	}

	protected void setText(String s) {
		JTextField tf = getActiveEditorTextField();
		setText(tf, s);
	}
}
