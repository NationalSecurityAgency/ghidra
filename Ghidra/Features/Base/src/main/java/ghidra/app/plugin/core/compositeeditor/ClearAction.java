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
import ghidra.util.Msg;
import ghidra.util.exception.UsrException;
import resources.ResourceManager;

public class ClearAction extends CompositeEditorTableAction {

	public final static String ACTION_NAME = "Clear Components";
	private final static String GROUP_NAME = COMPONENT_ACTION_GROUP;
	private final static ImageIcon ICON = ResourceManager.loadImage("images/erase16.png");
	private final static String[] POPUP_PATH = new String[] { "Clear" };
	private final static KeyStroke KEY_STROKE = KeyStroke.getKeyStroke(KeyEvent.VK_C, 0);

	public ClearAction(CompositeEditorProvider provider) {
		super(provider, EDIT_ACTION_PREFIX + ACTION_NAME, GROUP_NAME, POPUP_PATH, null, ICON);

		setDescription("Clear the selected components");
		setKeyBindingData(new KeyBindingData(KEY_STROKE));
		adjustEnablement();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		try {
			model.clearSelectedComponents();
		}
		catch (OutOfMemoryError memExc) {
			String errMsg = "Couldn't clear components. Out of memory.";
			Msg.showError(this, null, "Out of Memory", errMsg, memExc);
		}
		catch (UsrException ue) {
			model.setStatus(ue.getMessage());
		}
		requestTableFocus();
	}

	@Override
	public void adjustEnablement() {
		setEnabled(model.isClearAllowed());
	}
}
