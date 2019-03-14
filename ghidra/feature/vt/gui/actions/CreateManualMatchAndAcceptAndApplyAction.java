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

import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.functionassociation.FunctionAssociationContext;
import ghidra.feature.vt.gui.task.CreateAndAcceptApplyManualMatchTask;
import ghidra.program.model.listing.Function;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

/**
 * Action that creates a manual match for the currently selected source and destination functions 
 * in the function association tables and then applies the match.
 */
public class CreateManualMatchAndAcceptAndApplyAction extends AbstractCreateManualMatchAction {

	public static final Icon ICON = ResourceManager.loadImage("images/checkmark_green.gif");

	/**
	 * Creates a manual match action that also does an apply of that match.
	 * @param controller the controller for the version tracking session.
	 */
	public CreateManualMatchAndAcceptAndApplyAction(VTController controller) {
		super("Create and Apply Manual Match", VTPlugin.OWNER, controller);

		setToolBarData(new ToolBarData(ICON, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { "Create And Apply Manual Match" }, ICON));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Create_And_Apply_Manual_Match"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		FunctionAssociationContext providerContext = (FunctionAssociationContext) context;
		Function sourceFunction = providerContext.getSelectedSourceFunction();
		Function destinationFunction = providerContext.getSelectionDestinationFunction();

		final CreateAndAcceptApplyManualMatchTask createTask =
			new CreateAndAcceptApplyManualMatchTask(controller, sourceFunction,
				destinationFunction, true);
		createTask.addTaskListener(new TaskListener() {
			@Override
			public void taskCompleted(Task task) {
				controller.setSelectedMatch(createTask.getNewMatch());
			}

			@Override
			public void taskCancelled(Task task) {
				// don't care; nothing to do
			}
		});

		controller.runVTTask(createTask);
	}
}
