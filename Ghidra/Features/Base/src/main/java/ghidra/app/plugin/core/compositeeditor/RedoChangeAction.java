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

import docking.ActionContext;
import docking.action.KeyBindingData;
import generic.theme.GIcon;

/**
 * {@link RedoChangeAction} facilitates an redo of recently undone/reverted composite editor changes.
 */
public class RedoChangeAction extends CompositeEditorTableAction {

	public static String DESCRIPTION = "Redo Change";
	public final static String ACTION_NAME = "Redo Editor Change";
	private final static String GROUP_NAME = UNDOREDO_ACTION_GROUP;
	private final static Icon ICON = new GIcon("icon.redo");
	private final static String[] POPUP_PATH = new String[] { DESCRIPTION };

	public RedoChangeAction(CompositeEditorProvider provider) {
		super(provider, ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setKeyBindingData(new KeyBindingData("ctrl shift Z"));
		setDescription("Redo editor change");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}
		CompositeViewerDataTypeManager viewDTM = model.getViewDataTypeManager();
		viewDTM.redo();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (hasIncompleteFieldEntry()) {
			return false;
		}
		CompositeViewerDataTypeManager viewDTM = model.getViewDataTypeManager();
		boolean canRedo = viewDTM.canRedo();
		setEnabled(canRedo);
		String description = DESCRIPTION + (canRedo ? (": " + viewDTM.getRedoName()) : "");
		setDescription(description);
		return canRedo;
	}
}
