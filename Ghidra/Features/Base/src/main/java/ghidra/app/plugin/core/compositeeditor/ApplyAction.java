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
import generic.theme.GIcon;
import ghidra.app.util.datatype.EmptyCompositeException;
import ghidra.program.model.data.InvalidDataTypeException;

/**
 * ApplyAction is an action for applying editor changes.
 */
public class ApplyAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Apply Editor Changes";
	private final static String GROUP_NAME = MAIN_ACTION_GROUP;
	private final static Icon ICON = new GIcon("icon.plugin.composite.editor.apply");
	private final static String[] POPUP_PATH = new String[] { "Apply Edits" };

	public ApplyAction(CompositeEditorProvider<?, ?> provider) {
		super(provider, ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);

		setDescription("Apply editor changes");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}

		provider.editorPanel.comitEntryChanges();

		try {
			model.apply();
		}
		catch (EmptyCompositeException | InvalidDataTypeException e) {
			model.setStatus(e.getMessage(), true);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (hasIncompleteFieldEntry()) {
			return false;
		}
		return model.hasChanges() && model.isValidName();
	}
}
