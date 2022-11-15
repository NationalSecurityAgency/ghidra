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
import docking.wizard.WizardManager;
import generic.theme.GIcon;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.wizard.VTAddToSessionWizardManager;
import ghidra.util.HelpLocation;

public class AddToVersionTrackingSessionAction extends DockingAction {

	private final VTController controller;

	public AddToVersionTrackingSessionAction(VTController controller) {

		super("Add To Session", VTPlugin.OWNER);
		this.controller = controller;
		String[] menuPath = { ToolConstants.MENU_FILE, "Add to Session..." };
		Icon plusIcon = new GIcon("icon.version.tracking.action.add.to.session");
		setMenuBarData(new MenuData(menuPath, plusIcon, "AAA"));
		setToolBarData(new ToolBarData(plusIcon, "View"));
		setDescription("Add additional correlations to the current version tracking session");
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Add_To_Session"));

	}

	@Override
	public void actionPerformed(ActionContext context) {
		VTAddToSessionWizardManager vtWizardManager = new VTAddToSessionWizardManager(controller);
		WizardManager wizardManager =
			new WizardManager("Version Tracking Wizard", true, vtWizardManager);
		wizardManager.showWizard(controller.getParentComponent());
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return controller.getSession() != null;
	}
}
