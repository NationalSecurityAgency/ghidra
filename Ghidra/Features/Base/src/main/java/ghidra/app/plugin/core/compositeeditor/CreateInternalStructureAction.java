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

import java.util.Arrays;

import javax.swing.Icon;

import docking.ActionContext;
import generic.theme.GIcon;
import ghidra.util.Swing;
import ghidra.util.exception.UsrException;

/**
 * Action for use in the structure data type editor.
 * This action has help associated with it.
 */
public class CreateInternalStructureAction extends CompositeEditorTableAction {

	private final static Icon ICON = new GIcon("icon.plugin.composite.editor.create");
	public final static String ACTION_NAME = "Create Structure From Selection";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION =
		"Create a new structure from the selected components and replace them with it.";
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	public CreateInternalStructureAction(StructureEditorProvider provider) {
		super(provider, ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setDescription(DESCRIPTION);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}
		int[] selectedComponentRows = model.getSelectedComponentRows();
		boolean hasComponentSelection = model.hasComponentSelection();
		boolean hasContiguousSelection = model.isContiguousComponentSelection();
		if (selectedComponentRows.length == 0) {
			return;
		}

		if (!hasComponentSelection || !hasContiguousSelection) {
			return;
		}

		Arrays.sort(selectedComponentRows);
		int numComponents = model.getNumComponents();
		int maxRow = selectedComponentRows[selectedComponentRows.length - 1];
		if (maxRow < numComponents) {
			createStructure();
		}

		requestTableFocus();
		Swing.runLater(() -> {
			provider.toFront();
			provider.requestFocus();
			provider.editorPanel.requestFocus();
			provider.editorPanel.table.requestFocus();
		});
	}

	private void createStructure() {
		try {
			((StructureEditorModel) model).createInternalStructure();
		}
		catch (UsrException e) {
			model.setStatus(e.getMessage(), true);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return !hasIncompleteFieldEntry() && isCreateInternalStructureAllowed();
	}

	private boolean isCreateInternalStructureAllowed() {
		return model.hasComponentSelection() && model.isContiguousComponentSelection();
	}
}
