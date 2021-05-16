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

import java.awt.Component;

import javax.swing.JTable;

import docking.ActionContext;
import docking.DockingWindowManager;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.util.exception.AssertException;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class EditBitFieldAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Edit Bitfield";
	private final static String GROUP_NAME = BITFIELD_ACTION_GROUP;
	private final static String DESCRIPTION = "Edit an existing bitfield";
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	public EditBitFieldAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, null);
		setDescription(DESCRIPTION);
		if (!(model instanceof CompEditorModel)) {
			throw new AssertException("unsupported use");
		}
		adjustEnablement();
	}

	private DataTypeComponent getUnalignedBitFieldComponent() {
		CompEditorModel editorModel = (CompEditorModel) model;
		if ((editorModel.viewComposite instanceof Structure) &&
			!editorModel.viewComposite.isPackingEnabled() &&
			editorModel.getNumSelectedRows() == 1) {
			int rowIndex = model.getSelectedRows()[0];
			if (rowIndex < model.getNumComponents()) {
				DataTypeComponent dtComponent = model.getComponent(rowIndex);
				if (dtComponent.isBitFieldComponent()) {
					return dtComponent;
				}
			}
		}
		return null;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		CompEditorModel editorModel = (CompEditorModel) model;

		DataTypeComponent dtComponent = getUnalignedBitFieldComponent();
		if (dtComponent == null) {
			return;
		}

		BitFieldEditorDialog dlg = new BitFieldEditorDialog(editorModel.viewComposite,
			provider.dtmService, dtComponent.getOrdinal(), model.showHexNumbers,
			ordinal -> refreshTableAndSelection(editorModel, ordinal));
		Component c = provider.getComponent();
		DockingWindowManager.showDialog(c, dlg);
		requestTableFocus();
	}

	private void refreshTableAndSelection(CompEditorModel editorModel, int ordinal) {
		editorModel.fireTableDataChanged();
		editorModel.compositeInfoChanged();
		JTable editorTable = provider.getTable();
		editorTable.getSelectionModel().setSelectionInterval(ordinal, ordinal);
	}

	@Override
	public void adjustEnablement() {
		setEnabled(getUnalignedBitFieldComponent() != null);
	}

}
