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
package ghidra.feature.vt.gui.actions;

import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchOneToManyContext;
import ghidra.feature.vt.gui.task.AcceptMatchTask;
import ghidra.util.HelpLocation;

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class AcceptMatchAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.EDIT_MENU_GROUP;

	private final VTController controller;

	public AcceptMatchAction(VTController controller) {
		super("Accept", VTPlugin.OWNER);
		this.controller = controller;

		Icon icon = ResourceManager.loadImage("images/flag.png");
		setToolBarData(new ToolBarData(icon, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { "Accept" }, icon, MENU_GROUP));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Accept_Match"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		List<VTMatch> selectedMatches;
		if (context instanceof VTMatchContext) {
			VTMatchContext matchContext = (VTMatchContext) context;
			selectedMatches = matchContext.getSelectedMatches();
		}
		else if (context instanceof VTMatchOneToManyContext) {
			VTMatchOneToManyContext matchContext = (VTMatchOneToManyContext) context;
			selectedMatches = matchContext.getSelectedMatches();
		}
		else {
			return;
		}
		AcceptMatchTask task = new AcceptMatchTask(controller, selectedMatches);
		controller.runVTTask(task);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		List<VTMatch> selectedMatches;
		if (context instanceof VTMatchContext) {
			VTMatchContext matchContext = (VTMatchContext) context;
			selectedMatches = matchContext.getSelectedMatches();
		}
		else if (context instanceof VTMatchOneToManyContext) {
			VTMatchOneToManyContext matchContext = (VTMatchOneToManyContext) context;
			selectedMatches = matchContext.getSelectedMatches();
		}
		else {
			selectedMatches = new ArrayList<VTMatch>();
		}
		return (selectedMatches.size() > 0);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
}
