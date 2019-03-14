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
package ghidra.app.plugin.core.select.programtree;

import javax.swing.JTree;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.programtree.ProgramNode;
import ghidra.app.services.ProgramTreeService;
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

/**
 * This plugin adds the 'Select Addresses' command to the ProgramTree pop-up
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.TREE,
	shortDescription = "Selects addresses from Program Tree",
	description = "Allows the user to select code in the code browser from a selection" +
			" of nodes (modules and fragments) in the Program Tree.",			
	servicesRequired = { ProgramTreeService.class }
)
//@formatter:on
public class ProgramTreeSelectionPlugin extends ProgramPlugin {

	private TreeSelectAction selectModuleAction;

	public ProgramTreeSelectionPlugin(PluginTool tool) {
		super(tool, true, true);
		createActions();
	}

	/**
	 * Method createActions.
	 */
	private void createActions() {
		selectModuleAction = new TreeSelectAction(getName());
		tool.addAction(selectModuleAction);
	}

	/**
	 * Method selectModule.
	 */
	private void selectModule(ActionContext context) {
		AddressSet addressSet = new AddressSet();
		ProgramNode node = (ProgramNode) context.getContextObject();

		JTree tree = node.getTree();
		int count = tree.getSelectionCount();
		TreePath paths[] = node.getTree().getSelectionPaths();
		for (int i = 0; i < count; i++) {
			TreePath path = paths[i];
			ProgramNode pNode = (ProgramNode) path.getLastPathComponent();
			getAddressSet(pNode.getGroup(), addressSet);
		}
		ProgramSelection selection = new ProgramSelection(addressSet);
		ProgramSelectionPluginEvent pspe =
			new ProgramSelectionPluginEvent("Selection", selection, node.getProgram());
		firePluginEvent(pspe);
	}

	/**
	 * Get the address set for the given group. If group is a Module, then
	 * recursively call this method for all descendants.
	 * @param group either a Fragment or a Module
	 * @param set address set to populate
	 */
	private void getAddressSet(Group group, AddressSet set) {
		if (group instanceof ProgramFragment) {
			set.add((ProgramFragment) group);
		}
		else {
			Group[] groups = ((ProgramModule) group).getChildren();
			for (Group group2 : groups) {
				getAddressSet(group2, set);
			}
		}
	}

	private class TreeSelectAction extends DockingAction {
		TreeSelectAction(String owner) {
			super("select addresses", owner);
			setPopupMenuData(new MenuData(new String[] { "Select Addresses" }, null, "select"));

			setEnabled(true);
			setHelpLocation(new HelpLocation(HelpTopics.PROGRAM_TREE, "SelectAddresses"));
		}

		/**
		 * Determine if the Module Select action should be visible within
		 * the popup menu for the specified active object.
		 * @param activeObj the object under the mouse location for the popup.
		 * @return true if action should be made visible in popup menu.
		 */
		@Override
		public boolean isEnabledForContext(ActionContext context) {
			Object activeObj = context.getContextObject();
			if (activeObj instanceof ProgramNode) {
				return ((ProgramNode) activeObj).getProgram() != null;
			}
			return false;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			selectModule(context);
		}
	}
}
