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
package docking;

import java.awt.event.ActionEvent;

import javax.swing.SwingUtilities;

import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import docking.menu.MenuHandler;

public class MenuBarMenuHandler extends MenuHandler {

	private final DockingWindowManager windowManager;

	public MenuBarMenuHandler(DockingWindowManager windowManager) {
		this.windowManager = windowManager;
	}

	@Override
	public void menuItemEntered(DockingActionIf action) {
		DockingWindowManager.setMouseOverAction(action);
	}

	@Override
	public void menuItemExited(DockingActionIf action) {
		DockingWindowManager.clearMouseOverHelp();
	}

	@Override
	public void processMenuAction(final DockingActionIf action, final ActionEvent event) {

		DockingWindowManager.clearMouseOverHelp();

		ActionContext context = windowManager.getActionContext(action);
		if (context == null) {
			return;  // nothing to do
		}

		context.setSourceObject(event.getSource());

		// this gives the UI some time to repaint before executing the action
		SwingUtilities.invokeLater(() -> {
			windowManager.setStatusText("");
			if (action.isValidContext(context) && action.isEnabledForContext(context)) {
				if (action instanceof ToggleDockingActionIf) {
					ToggleDockingActionIf toggleAction = ((ToggleDockingActionIf) action);
					toggleAction.setSelected(!toggleAction.isSelected());
				}
				action.actionPerformed(context);
			}
		});
	}
}
