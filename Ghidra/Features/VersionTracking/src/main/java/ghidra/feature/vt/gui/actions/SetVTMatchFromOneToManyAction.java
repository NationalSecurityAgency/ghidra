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

import javax.swing.Icon;

import docking.ActionContext;
import docking.action.*;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.onetomany.VTMatchOneToManyContext;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class SetVTMatchFromOneToManyAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.VT_MAIN_MENU_GROUP;
	public static final Icon SET_MATCH_ICON =
		ResourceManager.loadImage("images/text_align_justify.png");

	final VTController controller;

	public SetVTMatchFromOneToManyAction(VTController controller, boolean addToToolbar) {
		super("Select Same Match In Version Tracking Matches Table", VTPlugin.OWNER);
		this.controller = controller;

		if (addToToolbar) {
			setToolBarData(new ToolBarData(SET_MATCH_ICON, MENU_GROUP));
		}
		MenuData menuData = new MenuData(new String[] { "Select Match in VT Matches Table" },
			SET_MATCH_ICON, MENU_GROUP);
		setPopupMenuData(menuData);
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin",
			"Select_Same_Match_In_Version_Tracking_Matches_Table"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (context instanceof VTMatchOneToManyContext) {
			VTMatch match = getSelectedMatch((VTMatchOneToManyContext) context);
			if (match != null) {
				controller.setSelectedMatch(match);
			}
		}
	}

	private VTMatch getSelectedMatch(VTMatchOneToManyContext context) {
		List<VTMatch> selectedMatches = context.getSelectedMatches();
		if (selectedMatches.size() == 1) {
			return selectedMatches.get(0);
		}
		return null;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (context instanceof VTMatchOneToManyContext) {
			VTMatch match = getSelectedMatch((VTMatchOneToManyContext) context);
			return match != null;
		}
		return false;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (context instanceof VTMatchOneToManyContext) {
			return true;
		}
		return false;
	}
}
