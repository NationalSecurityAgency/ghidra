/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.HelpLocation;
import ghidra.util.exception.UsrException;

import java.awt.Event;
import java.awt.event.KeyEvent;

import javax.swing.ImageIcon;
import javax.swing.KeyStroke;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.widgets.dialogs.NumberInputDialog;

/**
 * Action for use in the composite data type editor.
 * This action has help associated with it.
 */
public class DuplicateMultipleAction extends CompositeEditorTableAction {

	private final static ImageIcon duplicateMultipleIcon =
		ResourceManager.loadImage("images/MultiDuplicateData.png");
	private final static String ACTION_NAME = "Duplicate Multiple of Component";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static String DESCRIPTION = "Duplicate multiple of the selected component";
	private KeyStroke keyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_M, Event.ALT_MASK);
	private static String[] popupPath = new String[] { ACTION_NAME };

	public DuplicateMultipleAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, popupPath, null,
			duplicateMultipleIcon);
		setDescription(DESCRIPTION);
		setKeyBindingData(new KeyBindingData(keyStroke));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		int[] indices = model.getSelectedComponentRows();
		if (indices.length == 1) {
			int min = 1;
			int max = model.getMaxDuplicates(indices[0]);
			if (max != 0) {
				int initial = model.getLastNumDuplicates();
				NumberInputDialog numberInputDialog =
					new NumberInputDialog("duplicates", ((initial > 0) ? initial : 1), min, max);
				String helpAnchor = provider.getHelpName() + "_" + "Duplicates_NumberInputDialog";
				HelpLocation helpLoc = new HelpLocation(provider.getHelpTopic(), helpAnchor);
				numberInputDialog.setHelpLocation(helpLoc);
				if (numberInputDialog.show()) {
					int numDuplicates = numberInputDialog.getValue();
					try {
						model.duplicateMultiple(indices[0], numDuplicates);
					}
					catch (UsrException e1) {
						model.setStatus(e1.getMessage(), true);
					}
				}
			}
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(model.isDuplicateAllowed());
	}
}
