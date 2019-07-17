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
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.feature.vt.gui.task.RemoveMatchTask;
import ghidra.util.HelpLocation;

import java.util.List;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

public class RemoveMatchAction extends DockingAction {

	private static final String MENU_GROUP = VTPlugin.UNEDIT_MENU_GROUP;
	private static final Icon ICON = ResourceManager.loadImage("images/edit-delete.png");
	private final VTController controller;

	public RemoveMatchAction(VTController controller) {
		super("Remove", VTPlugin.OWNER);
		this.controller = controller;

//		setToolBarData(new ToolBarData(ICON, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { "Remove Match" }, ICON, MENU_GROUP));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Remove_Match"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		VTSession session = controller.getSession();
		RemoveMatchTask task = new RemoveMatchTask(session, matches);
		controller.runVTTask(task);
		controller.refresh();
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
		if (!isRemovableMatch(matches.get(0))) {
			return false; // It must be a single manual match.
		}
		return true;
	}

	private boolean isRemovableMatch(VTMatch vtMatch) {
		return vtMatch.getMatchSet().hasRemovableMatches();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return true;
	}
}
