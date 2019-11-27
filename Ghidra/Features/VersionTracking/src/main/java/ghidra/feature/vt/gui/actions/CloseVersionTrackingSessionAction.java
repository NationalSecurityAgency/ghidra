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
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;

public class CloseVersionTrackingSessionAction extends DockingAction {

	private final VTController controller;

	public CloseVersionTrackingSessionAction(VTController controller) {
		super("Close Session", VTPlugin.OWNER);
		this.controller = controller;
		String[] menuPath = { ToolConstants.MENU_FILE, "Close Session..." };
		setMenuBarData(new MenuData(menuPath, "AAB"));
		setDescription("Closes the current Version Tracking Session");
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Version_Tracking_Tool"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		controller.closeVersionTrackingSession();

	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return controller.getSession() != null;
	}

}
