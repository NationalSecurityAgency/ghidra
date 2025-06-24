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
		Data cursorData = DataUtilities.getDataAtLocation(context.getLocation());
		return cursorData != null &&
			(cursorData.getNumComponents() > 0 || cursorData.getParent() != null);
	}

	@Override
	protected void actionPerformed(ProgramLocationActionContext context) {
		ListingPanel listingPanel = provider.getListingPanel();
		ListingModel layoutModel = listingPanel.getListingModel();

		ProgramLocation location = context.getLocation();
		Data cursorData = DataUtilities.getDataAtLocation(location);
		Data actionData = cursorData.getNumComponents() > 0 ? cursorData : cursorData.getParent();
		boolean collapsing = layoutModel.isOpen(actionData);
		if (collapsing && cursorData != actionData) {
			ProgramLocation newLoc = new ProgramLocation(context.getProgram(),
				actionData.getAddress(), actionData.getComponentPath(), null, 0, 0, 0);
			listingPanel.goTo(newLoc);
		}
		layoutModel.toggleOpen(actionData);
	}

}
