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

import docking.DockingWindowManager;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;

/**
 * Editor panel for Union datatype
 */
public class StructureEditorPanel extends CompEditorPanel<Structure, StructureEditorModel> {

	public StructureEditorPanel(StructureEditorModel model, StructureEditorProvider provider) {
		super(model, provider);
	}

	@Override
	boolean launchBitFieldEditor(int modelRow, int modelColumn) {
		if (!model.viewComposite.isPackingEnabled() &&
			model.getDataTypeColumn() == modelColumn && modelRow < model.getNumComponents()) {
			// check if we are attempting to edit a bitfield
			DataTypeComponent dtComponent = model.getComponent(modelRow);
			if (dtComponent.isBitFieldComponent()) {
				table.getCellEditor().cancelCellEditing();
				BitFieldEditorDialog dlg = new BitFieldEditorDialog(model.viewComposite,
					provider.dtmService, modelRow, model.showHexNumbers,
					ordinal -> refreshTableAndSelection(model, ordinal));
				Component c = provider.getComponent();
				DockingWindowManager.showDialog(c, dlg);
				return true;
			}
		}
		return false;
	}

	private void refreshTableAndSelection(StructureEditorModel editorModel, int ordinal) {
		editorModel.notifyCompositeChanged();
		editorModel.setSelection(new int[] { ordinal, ordinal });
	}
}
