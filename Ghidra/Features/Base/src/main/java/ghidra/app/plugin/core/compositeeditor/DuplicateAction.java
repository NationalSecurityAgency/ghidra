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

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Action to duplicate the selected row
 */
public class DuplicateAction extends CompositeEditorTableAction {

	private final static ImageIcon ICON = ResourceManager.loadImage("images/DuplicateData.png");
	public final static String ACTION_NAME = "Duplicate Component";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Duplicate the selected component";
	private final static String[] POPUP_PATH = new String[] { ACTION_NAME };
	private final static KeyStroke KEY_STROKE =
		KeyStroke.getKeyStroke(KeyEvent.VK_D, InputEvent.ALT_DOWN_MASK);

	public DuplicateAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null,
			ICON);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(KEY_STROKE));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		int[] indices = model.getSelectedComponentRows();
		if (indices.length != 1) {
			return;
		}

		int max = model.getMaxDuplicates(indices[0]);
		if (max != 0) {
			try {
				// note: only duplicating one item; no need for a task
				model.duplicateMultiple(indices[0], 1, TaskMonitor.DUMMY);
			}
			catch (UsrException e1) {
				model.setStatus(e1.getMessage(), true);
			}
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(model.isDuplicateAllowed());
	}
}
