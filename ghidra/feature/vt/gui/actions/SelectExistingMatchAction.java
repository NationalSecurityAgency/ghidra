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
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.functionassociation.FunctionAssociationContext;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Action that selects the function match, if it exists, for the currently selected source and 
 * destination functions in the tables.
 */
public class SelectExistingMatchAction extends DockingAction {

	private static final Icon ICON = ResourceManager.loadImage("images/text_align_justify.png");

	private static final String MENU_GROUP = "Create";

	private final VTController controller;

	/**
	 * Constructor for the action.
	 * @param controller the controller for the current version tracking session.
	 */
	public SelectExistingMatchAction(VTController controller) {
		super("Select Exising Match", VTPlugin.OWNER);
		this.controller = controller;

		setToolBarData(new ToolBarData(ICON, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { "Select Existing Match" }, ICON));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Select_Existing_Match"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		FunctionAssociationContext providerContext = (FunctionAssociationContext) context;
		VTMatch match = providerContext.getExistingMatch();
		controller.setSelectedMatch(match);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof FunctionAssociationContext)) {
			return false;
		}

		FunctionAssociationContext providerContext = (FunctionAssociationContext) context;
		return providerContext.getExistingMatch() != null;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		return (context instanceof FunctionAssociationContext);
	}
}
