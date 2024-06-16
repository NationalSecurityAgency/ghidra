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
package docking.action;

import java.awt.*;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.DockingWindowManager;
import ghidra.util.Swing;

/**
 * An action to trigger a context menu over the focus owner.  This allows context menus to be
 * triggered from the keyboard.
 */
public class ShowContextMenuAction extends DockingAction {

	public ShowContextMenuAction(KeyStroke keyStroke, boolean isPrimary) {
		super(isPrimary ? "Show Context Menu" : "Show Context Menu Alternate",
			DockingWindowManager.DOCKING_WINDOWS_OWNER, isPrimary);

		// Only the primary action will appear in the tool' key binding settings UI.  The primary
		// action can be managed by the users.  The secondary action is not managed at this time.
		if (isPrimary) {
			setKeyBindingData(new KeyBindingData(keyStroke));
		}
		else {
			createSystemKeyBinding(keyStroke);
		}
	}

	@Override
	public void actionPerformed(ActionContext context) {

		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window window = kfm.getActiveWindow();
		if (window == null) {
			return;
		}

		// use the focused component to determine what should get the context menu
		Component focusOwner = kfm.getFocusOwner();
		if (focusOwner != null) {
			Swing.runLater(() -> {
				DockingWindowManager.showContextMenu(focusOwner);
			});
		}
	}

}
