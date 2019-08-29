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

import javax.swing.ImageIcon;

import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.data.Structure;
import resources.ResourceManager;

/**
 * Editor for a Structure Data Type.
 */
public class StructureEditorProvider extends CompositeEditorProvider {

	protected static final ImageIcon STRUCTURE_EDITOR_ICON =
		ResourceManager.loadImage("images/cstruct.png");

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
			new FindReferencesToField(this),
			new UnpackageAction(this),
			new EditComponentAction(this), 
			new EditFieldAction(this), 
			new HexNumbersAction(this),
			new CreateInternalStructureAction(this),
			new ShowComponentPathAction(this),
			new AddBitFieldAction(this),
			new EditBitFieldAction(this),
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
}
