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

import java.awt.KeyboardFocusManager;
import java.awt.Window;

import docking.*;
import docking.actions.dialog.ActionChooserDialog;
import docking.actions.dialog.ActionDisplayLevel;
import docking.tool.ToolConstants;
import generic.util.action.SystemKeyBindings;
import ghidra.util.HelpLocation;

/**
 * Action for displaying the {@link ActionChooserDialog}. This action determines the focused 
 * {@link ComponentProvider} or {@link DialogComponentProvider} and displays the 
 * {@link ActionChooserDialog} with actions relevant to that focused component.
 */
public class ShowActionChooserDialogAction extends DockingAction {

	public ShowActionChooserDialogAction() {
		super("Show Action Chooser Dialog", ToolConstants.TOOL_OWNER);
		createSystemKeyBinding(SystemKeyBindings.ACTION_CHOOSER_KEY);
		setHelpLocation(new HelpLocation("KeyboardNavigation", "ActionChooserDialog"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window focusedWindow = kfm.getFocusedWindow();

		Tool tool = DockingWindowManager.getActiveInstance().getTool();

		if (focusedWindow instanceof DockingDialog dialog) {
			context = dialog.getDialogComponent().getActionContext(null);
			showActionsDialog(tool, dialog, context);
		}
		else if (focusedWindow instanceof DockingFrame dockingFrame) {
			showActionsDialog(tool, dockingFrame, context);
		}
	}

	private void showActionsDialog(Tool tool, DockingFrame frame, ActionContext context) {
		ComponentProvider provider = tool.getWindowManager().getActiveComponentProvider();
		ActionChooserDialog actionsDialog = new ActionChooserDialog(tool, provider, context);
		tool.showDialog(actionsDialog);
	}

	private void showActionsDialog(Tool tool, DockingDialog dialog, ActionContext context) {
		DialogComponentProvider dialogProvider = dialog.getDialogComponent();

		// There is a special case when the active dialog is the ActionChooserDialog. 
		// Instead of popping up another ActionChooserDialog, we interpret this action's 
		// keybinding to mean to show even more actions in the current dialog.
		if (dialogProvider instanceof ActionChooserDialog actionsDialog) {
			ActionDisplayLevel level = actionsDialog.getActionDisplayLevel();
			actionsDialog.setActionDisplayLevel(level.getNextLevel());
			return;
		}

		ActionChooserDialog actionsDialog = new ActionChooserDialog(tool, dialogProvider, context);
		tool.showDialog(actionsDialog);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

}
