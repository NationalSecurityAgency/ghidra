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
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskLauncher;

/**
 * Action for recursively expanding an expandable data element in the listing.
 */
public class ExpandAllDataAction extends ProgramLocationContextAction {

	private CodeViewerProvider provider;

	public ExpandAllDataAction(CodeViewerProvider provider) {
		super("Expand All Data", provider.getOwner());
		this.provider = provider;

		setPopupMenuData(new MenuData(new String[] { "Expand All Data" }, null, "Structure"));
		setDescription("Open all data recursively from the current location downward.");

		setHelpLocation(new HelpLocation("CodeBrowserPlugin", "ExpandCollapseActions"));

		setEnabled(true);

		// make sure the action is in all windows that can provide the needed context
		addToWindowWhen(ProgramLocationActionContext.class);
	}

	@Override
	protected boolean isEnabledForContext(ProgramLocationActionContext context) {
		if (context.getSelection() != null && !context.getSelection().isEmpty()) {
			updatePopupMenuName(true);
			return true;
		}
		Data componentData = getComponentData(context.getLocation());
		if (componentData == null) {
			return false;
		}

		updatePopupMenuName(false);
		return true;
	}

	@Override
	protected void actionPerformed(ProgramLocationActionContext context) {
		ListingModel model = getModel();
		ProgramSelection selection = context.getSelection();
		if (selection != null && !selection.isEmpty()) {
			TaskLauncher.launchModal("Expand Data In Selection",
				monitor -> model.openAllData(selection, monitor));
			return;
		}

		ProgramLocation location = context.getLocation();
		Data data = getComponentData(location);
		TaskLauncher.launchModal("Expand Data In Selection",
			monitor -> model.openAllData(data, monitor));
	}

	private void updatePopupMenuName(boolean hasSelection) {
		if (hasSelection) {
			getPopupMenuData().setMenuPath(new String[] { "Expand All Data In Selection" });
			setDescription("Open all data recursively in the current selection.");
		}
		else {
			getPopupMenuData().setMenuPath(new String[] { "Expand All Data" });
			setDescription("Open all data recursively from the current location downward.");
		}
	}

	private ListingModel getModel() {
		ListingPanel listingPanel = provider.getListingPanel();
		return listingPanel.getListingModel();
	}

	private Data getComponentData(ProgramLocation location) {
		if (location == null) {
			return null;
		}
		Data data = DataUtilities.getDataAtLocation(location);

		if (data == null || data.getNumComponents() <= 0) {
			return null; // no expandable data at location
		}

		return data;
	}

}
