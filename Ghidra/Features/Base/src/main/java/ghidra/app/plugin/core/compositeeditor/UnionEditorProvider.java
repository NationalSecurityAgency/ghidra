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
import ghidra.program.model.data.Union;
import resources.ResourceManager;

/**
 * Editor for a Union Data Type.
 */
public class UnionEditorProvider extends CompositeEditorProvider {

	protected static final ImageIcon UNION_EDITOR_ICON =
		ResourceManager.loadImage("images/cUnion.png");

	public UnionEditorProvider(Plugin plugin, Union unionDataType, boolean showInHex) {
		super(plugin);
		setIcon(UNION_EDITOR_ICON);
		editorModel = new UnionEditorModel(this, showInHex);
		editorModel.load(unionDataType);
		initializeActions();
		editorPanel = new UnionEditorPanel((UnionEditorModel) editorModel, this);
		updateTitle();
		plugin.getTool().addComponentProvider(this, true);
		addActionsToTool();
		editorPanel.getTable().requestFocus();
		editorModel.selectionChanged();
	}

	@Override
	public String getName() {
		return "Union Editor";
	}

	@Override
	protected CompositeEditorTableAction[] createActions() {
		//@formatter:off
		return new CompositeEditorTableAction[] { 
			new ApplyAction(this), 
			new MoveUpAction(this),
			new MoveDownAction(this), 
			new DuplicateAction(this), 
			new DuplicateMultipleAction(this),
			new DeleteAction(this), 
			new PointerAction(this), 
			new ArrayAction(this),
			new ShowComponentPathAction(this), 
			new EditComponentAction(this),
			new EditFieldAction(this), 
			new HexNumbersAction(this),
			new AddBitFieldAction(this),
			new EditBitFieldAction(this)
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
