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

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.framework.model.DomainFile;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;

public class ResetToolAction extends DockingAction {

	private VTController controller;
	private final VTSubToolManager toolManager;

	public ResetToolAction(VTController controller, VTSubToolManager toolManager) {
		super("Reset Sub Tools", VTPlugin.OWNER);
		this.controller = controller;
		this.toolManager = toolManager;
		String[] menuPath = { ToolConstants.MENU_EDIT, "Reset Source and Destination Tools" };
		setMenuBarData(new MenuData(menuPath));
		setDescription("Resets source and destination program tools back to default configurations.");
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Reset_Tools"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DomainFile vtSessionFile = null;
		VTSession session = controller.getSession();
		if (session != null) {
			int result =
				OptionDialog.showYesNoDialog(controller.getTool().getToolFrame(),
					"Restart Session?", "This action needs to close and reopen the "
						+ "session to reset the tools.\nDo you want to continue?");

			if (result == OptionDialog.NO_OPTION) {
				return;
			}
			if (session instanceof VTSessionDB) {
				vtSessionFile = ((VTSessionDB) session).getDomainFile();
			}
			if (!controller.closeVersionTrackingSession()) {
				return; // user cancelled  during save dialog
			}
		}
		toolManager.resetTools();

		if (vtSessionFile != null) {
			controller.openVersionTrackingSession(vtSessionFile);
		}
	}
}
