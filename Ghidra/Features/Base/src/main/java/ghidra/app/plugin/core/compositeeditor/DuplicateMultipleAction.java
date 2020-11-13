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
import docking.widgets.dialogs.NumberInputDialog;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Action that allows the user to make multiple duplicates of the selected item
 */
public class DuplicateMultipleAction extends CompositeEditorTableAction {

	private final static ImageIcon ICON =
		ResourceManager.loadImage("images/MultiDuplicateData.png");
	public final static String ACTION_NAME = "Duplicate Multiple of Component";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Duplicate multiple of the selected component";
	private final static String[] POPUP_PATH = new String[] { ACTION_NAME };

	private KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_M, InputEvent.ALT_DOWN_MASK);

	public DuplicateMultipleAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(keyStroke));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		int[] indices = model.getSelectedComponentRows();
		if (indices.length != 1) {
			return;
		}

		int row = indices[0];
		int min = 1;
		int max = model.getMaxDuplicates(row);
		if (max == 0) {
			return;
		}

		int initial = model.getLastNumDuplicates();
		NumberInputDialog numberInputDialog =
			new NumberInputDialog("duplicates", ((initial > 0) ? initial : 1), min, max);
		String helpAnchor = provider.getHelpName() + "_" + "Duplicates_NumberInputDialog";
		HelpLocation helpLoc = new HelpLocation(provider.getHelpTopic(), helpAnchor);
		numberInputDialog.setHelpLocation(helpLoc);

		if (numberInputDialog.show()) {
			int count = numberInputDialog.getValue();
			TaskLauncher.launchModal("Duplicating Component",
				monitor -> doInsert(row, count, monitor));
		}

		requestTableFocus();
	}

	private void doInsert(int row, int count, TaskMonitor monitor) {
		try {
			model.duplicateMultiple(row, count, monitor);
		}
		catch (CancelledException e) {
			// user cancelled
		}
		catch (UsrException e) {
			model.setStatus(e.getMessage(), true);
		}
		model.fireTableDataChanged();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(model.isDuplicateAllowed());
	}
}
