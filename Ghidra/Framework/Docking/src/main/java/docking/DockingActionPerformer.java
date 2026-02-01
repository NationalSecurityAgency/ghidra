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

import docking.action.DockingActionIf;
import docking.action.ToggleDockingActionIf;
import ghidra.util.Msg;
import ghidra.util.Swing;

/**
 * A simple class to handle executing the given action.  This class will generate the action context
 * as needed and validate the context before executing the action.
 */
public class DockingActionPerformer {

	private DockingActionPerformer() {
		// static only
	}

	/**
	 * Executes the given action later on the Swing thread.
	 * @param action the action.
	 * @param event the event that triggered the action.
	 */
	public static void perform(DockingActionIf action, ActionEvent event) {
		perform(action, event, DockingWindowManager.getActiveInstance());
	}

	/**
	 * Executes the given action later on the Swing thread.
	 * @param action the action.
	 * @param event the event that triggered the action.
	 * @param windowManager the window manager containing the action being processed.
	 */
	public static void perform(DockingActionIf action, ActionEvent event,
			DockingWindowManager windowManager) {

		if (windowManager == null) {
			// not sure if this can happen
			Msg.error(DockingActionPerformer.class,
				"No window manager found; unable to execute action: " + action.getFullName());
		}

		DockingWindowManager.clearMouseOverHelp();
		ActionContext context = windowManager.createActionContext(action);

		context.setSourceObject(event.getSource());
		context.setEventClickModifiers(event.getModifiers());

		// this gives the UI some time to repaint before executing the action
		Swing.runLater(() -> {
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
