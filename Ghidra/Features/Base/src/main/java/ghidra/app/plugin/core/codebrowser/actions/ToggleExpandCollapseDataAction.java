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

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.context.ProgramLocationContextAction;
import ghidra.app.plugin.core.codebrowser.CodeViewerProvider;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.task.*;

/**
 * Action for toggling the expanded/collapsed state of an single expandable data element.  This
 * action works for both top level structures and structures inside other structures.  Also,
 * if invoked on any data element inside a structure, it will collapse the immediate parent
 * of that element.
 */
public class ToggleExpandCollapseDataAction extends ProgramLocationContextAction {

	private CodeViewerProvider provider;

	public ToggleExpandCollapseDataAction(CodeViewerProvider provider) {
		super("Toggle Expand/Collapse Data", provider.getOwner());
		this.provider = provider;

		setPopupMenuData(
			new MenuData(new String[] { "Toggle Expand/Collapse Data" }, null, "Structure"));
		setKeyBindingData(new KeyBindingData(' ', 0));

		setHelpLocation(new HelpLocation("CodeBrowserPlugin", "ExpandCollapseActions"));
		setDescription(
			"Opens or closes the component data for this location or if on a non-component data in " +
				"another data component, then closes the parent component.");

		setEnabled(true);
	}

	@Override
	protected boolean isEnabledForContext(ProgramLocationActionContext context) {
		Data data = getClosestComponentDataUnit(context.getLocation());
		if (data == null) {
			return false;
		}

		return true;
	}

	@Override
	protected void actionPerformed(ProgramLocationActionContext context) {
		ListingPanel listingPanel = provider.getListingPanel();
		ListingModel layoutModel = listingPanel.getListingModel();

		ProgramLocation location = context.getLocation();
		Data data = getClosestComponentDataUnit(location);
		new TaskLauncher(new OpenCloseDataTask(data, layoutModel), listingPanel);
	}

	private Data getClosestComponentDataUnit(ProgramLocation location) {
		if (location == null) {
			return null;
		}

		Data data = DataUtilities.getDataAtLocation(location);

		if (data == null) {
			return null;
		}

		if (data.getNumComponents() > 0) {
			return data;
		}

		return data.getParent();
	}

	private static class OpenCloseDataTask extends Task {
		private ListingModel model;
		private Data data;

		public OpenCloseDataTask(Data data, ListingModel model) {
			super("Open/Close Data In Selection", true, true, true, true);
			this.data = data;
			this.model = model;
		}

		@Override
		public void run(TaskMonitor monitor) {
			if (!model.isOpen(data)) {
				model.openData(data);
			}
			else {
				model.closeData(data);
			}
		}
	}
}
