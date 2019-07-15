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
package ghidra.app.plugin.core.codebrowser.actions;

import docking.action.MenuData;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.context.ProgramLocationContextAction;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;

/**
 * Action for recursively collapsing an expandable data element in the listing.  This action
 * can be invoked on an expandable data element or any sub element and will close the
 * outer most data element and all child elements of that structure.
 */
public class CollapseAllDataAction extends ProgramLocationContextAction {

	private CodeViewerProvider provider;

	public CollapseAllDataAction(CodeViewerProvider provider) {
		super("Collapse All Data", provider.getOwner());
		this.provider = provider;

		setPopupMenuData(new MenuData(new String[] { "Collapse All Data" }, null, "Structure"));

		setHelpLocation(new HelpLocation("CodeBrowserPlugin", "ExpandCollapseActions"));

		setEnabled(true);
	}

	@Override
	protected boolean isEnabledForContext(ProgramLocationActionContext context) {
		if (context.getSelection() != null && !context.getSelection().isEmpty()) {
			updatePopupMenuName(true);
			return true;
		}
		Data componentData = getTopLevelComponentData(context.getLocation());
		if (componentData == null) {
			return false;
		}

		if (!isOpen(componentData)) {
			return false;
		}
		updatePopupMenuName(false);
		return true;
	}

	private boolean isOpen(Data componentData) {
		return getModel().isOpen(componentData);
	}

	private void updatePopupMenuName(boolean hasSelection) {
		if (hasSelection) {
			getPopupMenuData().setMenuPath(new String[] { "Collapse All Data In Selection" });
			setDescription("Closes all data recursively in the current selection.");
		}
		else {
			getPopupMenuData().setMenuPath(new String[] { "Collapse All Data" });
			setDescription(
				"Closes all data recursively from the outer most component containing this location.");
		}
	}

	@Override
	protected void actionPerformed(ProgramLocationActionContext context) {
		ListingModel model = getModel();
		ProgramSelection selection = context.getSelection();
		if (selection != null && !selection.isEmpty()) {
			TaskLauncher.launchModal("Collapse Data In Selection",
				monitor -> model.closeAllData(selection, monitor));
			return;
		}

		ProgramLocation location = context.getLocation();
		Data data = getTopLevelComponentData(location);
		TaskLauncher.launchModal("Collapse Data", monitor -> model.closeAllData(data, monitor));
	}

	private ListingModel getModel() {
		ListingPanel listingPanel = provider.getListingPanel();
		return listingPanel.getListingModel();
	}

	private Data getTopLevelComponentData(ProgramLocation location) {
		if (location == null) {
			return null;
		}

		Address address = location.getAddress();
		if (address == null) {
			return null;
		}

		Program program = provider.getProgram();
		Data topLevelData = program.getListing().getDataContaining(address);

		if (topLevelData == null || topLevelData.getNumComponents() <= 0) {
			return null; // no child data components
		}

		return topLevelData;
	}

}
