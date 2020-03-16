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
package ghidra.app.plugin.core.select.flow;

import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.util.HelpLocation;

/**
 * <CODE>SelectByFlowAction</CODE> allows the user to Select Code By Flowing from
 * the current program selection or by location if there is no selection.<BR>
 * Base class for actions in SelectByFlowPlugin.
 */
class SelectByFlowAction extends ListingContextAction {
	static final String GROUP = "FlowSelection";
	/** the plugin associated with this action. */
	SelectByFlowPlugin selectByFlowPlugin;

	private int selectionType; // SELECT_ALL_FLOWS_FROM, SELECT_LIMITED_FLOWS_FROM,
								// SELECT_SUBROUTINES,
								// SELECT_ALL_FLOWS_TO, SELECT_LIMITED_FLOWS_TO

	/**
	 * Creates a new action with the given name and associated to the given
	 * plugin.
	 * @param name the name for this action.
	 * @param plugin the plugin this action is associated with.
	 * @param selectionType
	 * SELECT_ALL_FLOWS_FROM indicates all flows from addresses in the current selection or 
	 * location should be followed.
	 * <BR>
	 * SELECT_LIMITED_FLOWS_FROM indicates all flows from addresses in the current selection or 
	 * location should be followed where the property for following that flow type is set to true.
	 * <BR>
	 * SELECT_SUBROUTINES indicates all flows except calls should be followed.
	 * <BR>
	 * SELECT_ALL_FLOWS_TO indicates all flows to addresses in the current selection or location
	 * should be followed.
	 * <BR>
	 * SELECT_LIMITED_FLOWS_TO indicates all flows to addresses in the current selection or 
	 * location should be followed where the property for following that flow type is set to true.
	 */
	SelectByFlowAction(String name, SelectByFlowPlugin plugin, int selectionType) {
		super(name, plugin.getName());
		this.selectByFlowPlugin = plugin;
		this.selectionType = selectionType;

		// this is in the main tool menu, so make it a tool action
		setSupportsDefaultToolContext(true);

		String[] menuPath = null;
		if (selectionType == SelectByFlowPlugin.SELECT_FUNCTIONS) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "Function" };
		}
		else if (selectionType == SelectByFlowPlugin.SELECT_SUBROUTINES) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "Subroutine" };
		}
		else if (selectionType == SelectByFlowPlugin.SELECT_DEAD_SUBROUTINES) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "Dead Subroutines" };
		}
		else if (selectionType == SelectByFlowPlugin.SELECT_LIMITED_FLOWS_FROM) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "Limited Flows From" };
		}
		else if (selectionType == SelectByFlowPlugin.SELECT_ALL_FLOWS_FROM) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "All Flows From" };
		}
		else if (selectionType == SelectByFlowPlugin.SELECT_LIMITED_FLOWS_TO) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "Limited Flows To" };
		}
		else if (selectionType == SelectByFlowPlugin.SELECT_ALL_FLOWS_TO) {
			menuPath = new String[] { ToolConstants.MENU_SELECTION, "All Flows To" };
		}

		setMenuBarData(new MenuData(menuPath, null, "FlowSelection"));

		setHelpLocation(new HelpLocation(HelpTopics.SELECTION, getName()));
	}

	@Override
	public void actionPerformed(ListingActionContext context) {
		// Either select by following all flows or all flows except calls
		// depending on how this action was set up.
		selectByFlowPlugin.select(context, selectionType);
	}

	@Override
	protected boolean isEnabledForContext(ListingActionContext context) {
		if (context.hasSelection()) {
			return true;
		}
		Address address = context.getAddress();
		if (address == null) {
			return false;
		}
		CodeUnit cu = context.getCodeUnit();
		return cu != null;
	}
}
