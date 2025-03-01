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

import javax.swing.Icon;

import docking.DockingWindowManager;
import generic.theme.GIcon;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Structure;
import ghidra.util.Msg;

/**
 * Editor for a Structure Data Type.
 */
public class StructureEditorProvider extends CompositeEditorProvider {

	private BitFieldEditorDialog bitFieldEditor;

	protected static final Icon STRUCTURE_EDITOR_ICON =
		new GIcon("icon.plugin.composite.editor.provider.structure");

	public StructureEditorProvider(Plugin plugin, Structure structureDataType,
			boolean showHexNumbers) {
		super(plugin);
		setIcon(STRUCTURE_EDITOR_ICON);
		editorModel = new StructureEditorModel(this, showHexNumbers);
		editorModel.load(structureDataType);
		initializeActions();
		editorPanel = new CompEditorPanel((StructureEditorModel) editorModel, this);
		plugin.getTool().addComponentProvider(this, true);
		updateTitle();
		addActionsToTool();
		editorPanel.getTable().requestFocus();
		editorModel.selectionChanged();
	}

	@Override
	public String getName() {
		return "Structure Editor";
	}

	@Override
	protected CompositeEditorTableAction[] createActions() {
		//@formatter:off
		return new CompositeEditorTableAction[] {
			new ApplyAction(this),
			new UndoChangeAction(this),
			new RedoChangeAction(this),
//			new ToggleLockAction(this),
			new InsertUndefinedAction(this),
			new MoveUpAction(this),
			new MoveDownAction(this),
			new ClearAction(this),
			new DuplicateAction(this),
			new DuplicateMultipleAction(this),
			new DeleteAction(this),
			new PointerAction(this),
			new ArrayAction(this),
			new FindReferencesToStructureFieldAction(this),
			new UnpackageAction(this),
			new EditComponentAction(this),
			new EditFieldAction(this),
			new HexNumbersAction(this),
			new CreateInternalStructureAction(this),
			new ShowComponentPathAction(this),
			new AddBitFieldAction(this),
			new EditBitFieldAction(this),
			new ShowDataTypeInTreeAction(this),

//			new ViewBitFieldAction(this)
		};
		//@formatter:on
	}

	@Override
	public String getHelpName() {
		return "Structure_Editor";
	}

	@Override
	public String getHelpTopic() {
		return "DataTypeEditors";
	}

	@Override
	protected void closeDependentEditors() {
		if (bitFieldEditor != null && bitFieldEditor.isVisible()) {
			bitFieldEditor.close();
		}
	}

	private void refreshTableAndSelection(int ordinal) {
		editorModel.notifyCompositeChanged();
		editorModel.setSelection(new int[] { ordinal, ordinal });
	}

	void showAddBitFieldEditor() {

		int[] selectedRows = editorModel.getSelectedRows();

		if (editorPanel.hasInvalidEntry() || editorPanel.hasUncomittedEntry() ||
			selectedRows.length != 1 || editorModel.viewComposite.isPackingEnabled()) {
			Msg.error(this, "Unsupported add bitfield editor use");
			return;
		}

		bitFieldEditor =
			new BitFieldEditorDialog(editorModel.viewComposite, dtmService, -(selectedRows[0] + 1),
				editorModel.showHexNumbers, ordinal -> refreshTableAndSelection(ordinal));

		DockingWindowManager.showDialog(editorPanel, bitFieldEditor);
		requestTableFocus();
	}

	void showBitFieldEditor() {

		DataTypeComponent dtComponent = getSelectedNonPackedBitFieldComponent();
		if (dtComponent == null) {
			Msg.error(this, "Unsupported bitfield editor use");
			return;
		}

		bitFieldEditor = new BitFieldEditorDialog(editorModel.viewComposite, dtmService,
			dtComponent.getOrdinal(), editorModel.showHexNumbers,
			ordinal -> refreshTableAndSelection(ordinal));
		DockingWindowManager.showDialog(editorPanel, bitFieldEditor);
		requestTableFocus();
	}

	/**
	 * Get the selected bitfield component if contained within a non-packed structure
	 * @return selected bitfield component or null
	 */
	DataTypeComponent getSelectedNonPackedBitFieldComponent() {
		if (!editorModel.viewComposite.isPackingEnabled() &&
			editorModel.getNumSelectedRows() == 1) {
			int rowIndex = editorModel.getSelectedRows()[0];
			if (rowIndex < editorModel.getNumComponents()) {
				DataTypeComponent dtComponent = editorModel.getComponent(rowIndex);
				if (dtComponent.isBitFieldComponent()) {
					return dtComponent;
				}
			}
		}
		return null;
	}
}
