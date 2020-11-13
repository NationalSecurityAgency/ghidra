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

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.widgets.OptionDialog;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.UsrException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class UnpackageAction extends CompositeEditorTableAction {

	private final static ImageIcon ICON = ResourceManager.loadImage("images/Unpackage.gif");
	public final static String ACTION_NAME = "Unpackage Component";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Replace the selected composite with its components";
	private final static KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_EQUALS, 0);
	private static String[] POPUP_PATH = new String[] { ACTION_NAME };

	public UnpackageAction(StructureEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(KEY_STROKE));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// If lots of components, verify the user really wants to unpackage.
		int currentRowIndex =
			model.getSelection().getFieldRange(0).getStart().getIndex().intValue();
		int subComps = model.getNumSubComponents(currentRowIndex);
		if (subComps > 1000) {
			String question = "Are you sure you want to unpackage " + subComps + " components?";
			String title = "Continue with unpackage?";
			int response =
				OptionDialog.showYesNoDialog(model.getProvider().getComponent(), title, question);
			if (response != 1) { // User did not select yes.
				return;
			}
		}

		TaskLauncher.launchModal("Unpackaging Component",
			monitor -> doUnpackage(currentRowIndex, monitor));

		requestTableFocus();
	}

	private void doUnpackage(int row, TaskMonitor monitor) {
		try {
			((StructureEditorModel) model).unpackage(row, monitor);
		}
		catch (CancelledException e) {
			// user cancelled
		}
		catch (UsrException e1) {
			model.setStatus(e1.getMessage(), true);
		}
		model.fireTableDataChanged();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(model.isUnpackageAllowed());
	}
}
