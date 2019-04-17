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
import ghidra.feature.vt.gui.task.ApplyMatchTask;
import ghidra.util.HelpLocation;

import java.util.List;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;

public class ApplyMatchAction extends DockingAction {

	public static final String NAME = "Apply Markup";
	private static final String MENU_GROUP = VTPlugin.EDIT_MENU_GROUP;

	private final VTController controller;

	public ApplyMatchAction(VTController controller) {
		super(NAME, VTPlugin.OWNER);
		this.controller = controller;

		Icon icon = ResourceManager.loadImage("images/checkmark_green.gif");
		setToolBarData(new ToolBarData(icon, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { NAME }, icon, MENU_GROUP));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Apply_Markup"));

	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();

		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		controller.runVTTask(task);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof VTMatchContext)) {
			return false;
		}
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		if (matches.size() == 0) {
			return false;
		}

		return true;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
}
