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

import java.awt.event.KeyEvent;

import javax.swing.Icon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import generic.theme.GIcon;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

public class DeleteAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Delete Components";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static Icon ICON = new GIcon("icon.plugin.composite.editor.delete");
	private final static String[] popupPath = new String[] { "Delete" };
	private final static KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_DELETE, 0);

	public DeleteAction(CompositeEditorProvider provider) {
		super(provider, ACTION_NAME, GROUP_NAME, popupPath, null, ICON);

		setKeyBindingData(new KeyBindingData(KEY_STROKE));
		setDescription("Delete the selected components");
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!isEnabledForContext(context)) {
			return;
		}
		TaskLauncher.launchModal(getName(), this::doDelete);
		requestTableFocus();
	}

	private void doDelete(TaskMonitor monitor) {
		try {
			model.deleteSelectedComponents();
		}
		catch (CancelledException e) {
			// user cancelled
		}
		catch (UsrException e) {
			model.setStatus(e.getMessage(), true);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return !hasIncompleteFieldEntry() && model.isDeleteAllowed();
	}

}
