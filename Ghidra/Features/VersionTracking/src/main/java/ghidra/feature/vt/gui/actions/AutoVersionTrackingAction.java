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
import docking.action.*;
import docking.tool.ToolConstants;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.util.HTMLUtilities;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 *  This action runs the {@link AutoVersionTrackingCommand}
 */
public class AutoVersionTrackingAction extends DockingAction {
	public static Icon AUTO_VT_ICON = ResourceManager.loadImage("images/wizard.png");
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

		// In the future we might want to make these user options so the user can change them 
		// I don't want to make this change until the confidence option in the reference
		// correlators is changed to make more sense to the user - currently the confidence has 
		// to be entered as the value before the log 10 is computed but the table shows log 10 value

		// The current passed values for score and confidence (1.0 and 10.0)
		// get you accepted matches with similarity scores >= 1.0 and
		// confidence (log 10) scores 2.0 and up
		AutoVersionTrackingCommand command =
			new AutoVersionTrackingCommand(controller, session, 1.0, 10.0);

		controller.getTool().executeBackgroundCommand(command, session);
	}

}
