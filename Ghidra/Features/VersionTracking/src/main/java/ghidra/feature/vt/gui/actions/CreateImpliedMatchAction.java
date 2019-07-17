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

import java.util.List;

import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.*;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.impliedmatches.VTImpliedMatchInfo;
import ghidra.feature.vt.gui.provider.impliedmatches.VTImpliedMatchesTableProvider;
import ghidra.feature.vt.gui.task.*;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;
import resources.ResourceManager;

public class CreateImpliedMatchAction extends DockingAction {

	private final VTController controller;
	private final VTImpliedMatchesTableProvider provider;

	public CreateImpliedMatchAction(VTController controller,
			VTImpliedMatchesTableProvider provider) {
		super("Accept Implied Match", VTPlugin.OWNER);
		this.controller = controller;
		this.provider = provider;

		ImageIcon icon = ResourceManager.loadImage("images/flag.png");
		setToolBarData(new ToolBarData(icon, "1"));
		setPopupMenuData(new MenuData(new String[] { "Accept Implied Match" }, icon, "1"));
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Accept_Implied_Match"));
		setEnabled(false);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		List<VTImpliedMatchInfo> matches = provider.getSelectedImpliedMatches();

		final CreateImpliedMatchesTask myTask = new CreateImpliedMatchesTask(controller, matches);
		myTask.addTaskListener(new TaskListener() {

			@Override
			public void taskCompleted(Task task) {
				List<VTMatch> createdMatches = myTask.getCreatedMatches();
				VtTask acceptTask = new AcceptMatchTask(controller, createdMatches);
				controller.runVTTask(acceptTask);
			}

			@Override
			public void taskCancelled(Task task) {
				// nothing to do
			}
		});
		controller.runVTTask(myTask);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		List<VTImpliedMatchInfo> matches = provider.getSelectedImpliedMatches();
		return matches.size() > 0;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
}
