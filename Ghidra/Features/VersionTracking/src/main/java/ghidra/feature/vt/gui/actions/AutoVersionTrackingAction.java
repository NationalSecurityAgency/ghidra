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

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.tool.ToolConstants;
import generic.theme.GIcon;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskListener;

/**
 *  This action runs the {@link AutoVersionTrackingTask}
 */
public class AutoVersionTrackingAction extends DockingAction {
	public static Icon AUTO_VT_ICON = new GIcon("icon.version.tracking.auto");
	private final VTController controller;

	public AutoVersionTrackingAction(VTController controller) {
		super("Automatic Version Tracking", VTPlugin.OWNER);
		this.controller = controller;
		String[] menuPath = { ToolConstants.MENU_FILE, "Automatic Version Tracking" };
		setMenuBarData(new MenuData(menuPath, AUTO_VT_ICON, "AAA"));
		setToolBarData(new ToolBarData(AUTO_VT_ICON, "View"));

		setDescription(
			HTMLUtilities.toWrappedHTML("Runs several correlators and applies good matches.\n" +
				"(For more details see the help page.)"));
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Automatic_Version_Tracking"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {

		VTSession session = controller.getSession();
		return session != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		VTSession session = controller.getSession();
		ToolOptions options = controller.getOptions();


		AutoVersionTrackingTask task = new AutoVersionTrackingTask(session, options);
		task.addTaskListener(new TaskListener() {

			@Override
			public void taskCompleted(Task t) {
				String message = task.getStatusMsg();
				if (message != null) {
					controller.getTool().setStatusInfo(message);
				}
			}

			@Override
			public void taskCancelled(Task t) {
				String message = task.getStatusMsg();
				if (message != null) {
					controller.getTool().setStatusInfo(message);
				}
			}
		});
		TaskLauncher.launch(task);
	}



}
