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
package ghidra.feature.vt.gui.actions;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.task.CreateManualMatchTask;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

public abstract class AbstractManualMatchFromToolsAction extends DockingAction {

	private final VTPlugin plugin;
	private SubToolContext subToolContext;

	public AbstractManualMatchFromToolsAction(VTPlugin plugin, String name) {
		super(name, VTPlugin.OWNER);
		this.plugin = plugin;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		Function sourceFunction = subToolContext.getSourceFunction();
		Function destinationFunction = subToolContext.getDestinationFunction();

		if (!validateSelectedFunctions(sourceFunction, destinationFunction)) {
			return;
		}

		final VTController controller = plugin.getController();
		if (!validateExistingMatch(controller)) {
			return;
		}

		if (!validateCursorPosition()) {
			return;
		}

		CreateManualMatchTask task = getTask(controller, sourceFunction, destinationFunction);

		task.addTaskListener(new TaskListener() {
			@Override
			public void taskCompleted(Task t) {
				controller.setSelectedMatch(task.getNewMatch());
			}

			@Override
			public void taskCancelled(Task t) {
				// don't care; nothing to do
			}
		});

		plugin.getController().runVTTask(task);
	}

	protected abstract CreateManualMatchTask getTask(VTController controller,
			Function sourceFunction, Function destinationFunction);

	private boolean validateSelectedFunctions(Function sourceFunction,
			Function destinationFunction) {
		if (sourceFunction == null || destinationFunction == null) {
			Msg.showInfo(getClass(), null, "Cannot Create Match",
				"The current location must be inside of a function in both the source and " +
					"destination programs");
			return false;
		}
		return true;
	}

	private boolean validateExistingMatch(VTController controller) {
		VTMatch match = subToolContext.getMatch();
		if (match == null) {
			return true;
		}

		int choice = OptionDialog.showOptionNoCancelDialog(null, "Match Exists",
			"<html>You have attempted to create a manual when a match already exists.<br>" +
				"Would you like to select the match in the matches table?",
			"Yes", "No", OptionDialog.QUESTION_MESSAGE);
		if (choice == 1) {
			controller.setSelectedMatch(match);
		}
		return false;
	}

	private boolean validateCursorPosition() {
		boolean sourceCursorOnScreen = subToolContext.isSourceCursorOnScreen();
		boolean destinationCursorOnScreen = subToolContext.isDestinationCursorOnScreen();

		if (sourceCursorOnScreen && destinationCursorOnScreen) {
			return true;
		}

		String message = "";
		if (!sourceCursorOnScreen) {
			message += " <b>source tool</b>";
		}

		if (!destinationCursorOnScreen) {
			message += " and the <b>destination tool</b>";
		}

		int choice = OptionDialog.showOptionNoCancelDialog(null, "Cursor Offscreen",
			"<html>Your cursor is off the screen in the " + message + ".<br>" +
				"There is a chance the cursor is not in the function you " +
				"currently see.<br>Would you like to continue creating a match?",
			"Yes", "No", OptionDialog.QUESTION_MESSAGE);
		if (choice != 1) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return (context instanceof CodeViewerActionContext);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof CodeViewerActionContext)) {
			return false;
		}

		subToolContext = new SubToolContext(plugin);
		Function sourceFunction = subToolContext.getSourceFunction();
		Function destinationFunction = subToolContext.getDestinationFunction();
		VTMatch match = subToolContext.getMatch();
		return sourceFunction != null && destinationFunction != null && match == null;
	}

}
