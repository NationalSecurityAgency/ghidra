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
import ghidra.feature.vt.api.main.VTAssociation;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.plugin.VTPlugin;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchContext;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

public class CreateSelectionAction extends DockingAction {
	public static final String NAME = "Create Match Table Selection";
	private static final String MENU_GROUP = "Selection";
	private static final Icon ICON = ResourceManager.loadImage("images/text_align_justify.png");
	private final VTController controller;

	public CreateSelectionAction(VTController controller) {
		super(NAME, VTPlugin.OWNER);
		this.controller = controller;
		setToolBarData(new ToolBarData(ICON, MENU_GROUP));
		setPopupMenuData(new MenuData(new String[] { "Make Selections" }, ICON, MENU_GROUP));
		setEnabled(false);
		setHelpLocation(new HelpLocation("VersionTrackingPlugin", "Make Selections"));
		setDescription("Makes selections in both the source and destination tools for the selected matches.");
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
	public void actionPerformed(ActionContext context) {
		Program sourceProgram = controller.getSourceProgram();
		Program destinationProgram = controller.getDestinationProgram();
		AddressSet sourceSet = new AddressSet();
		AddressSet destinationSet = new AddressSet();
		VTMatchContext matchContext = (VTMatchContext) context;
		List<VTMatch> matches = matchContext.getSelectedMatches();
		for (VTMatch vtMatch : matches) {
			VTAssociation association = vtMatch.getAssociation();
			sourceSet.add(association.getSourceAddress());
			destinationSet.add(association.getDestinationAddress());
		}
		controller.setSelectionInSourceTool(sourceSet);
		controller.setSelectionInDestinationTool(destinationSet);
	}

}
