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
import ghidra.feature.vt.gui.wizard.VTNewSessionWizardManager;
import ghidra.util.HelpLocation;

import javax.swing.Icon;

import resources.ResourceManager;
import docking.ActionContext;
import docking.action.*;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.wizard.WizardManager;

public class CreateVersionTrackingSessionAction extends DockingAction {
	public static Icon NEW_ICON = ResourceManager.loadImage("images/start-here_16.png");
	private final VTController controller;

	public CreateVersionTrackingSessionAction(VTController controller) {
		super("Create New Session", VTPlugin.OWNER);
		this.controller = controller;
		String[] menuPath = { ToolConstants.MENU_FILE, "New Session..." };
		setMenuBarData(new MenuData(menuPath, NEW_ICON, "AAA"));
		setToolBarData(new ToolBarData(NEW_ICON, "View"));
		setDescription("Creates a new Version Tracking Session");
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Create_Session"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		if (controller.getSession() != null) {
			int result =
				OptionDialog.showYesNoDialog(controller.getTool().getToolFrame(),
					"Create New Session",
					"This will close the the current session.  Do you want to continue?");

			if (result != OptionDialog.YES_OPTION) {
				return;
			}
		}
		if (!controller.closeVersionTrackingSession()) {
			return; // user cancelled  during save dialog
		}
		VTNewSessionWizardManager vtWizardManager = new VTNewSessionWizardManager(controller);
		WizardManager wizardManager =
			new WizardManager("Version Tracking Wizard", true, vtWizardManager);
		wizardManager.showWizard(controller.getParentComponent());
	}

}
