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
package ghidra.app.plugin.core.datamgr.actions;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.DataTypeNode;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.program.model.data.*;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskLauncher;

/*
 * Action to display a Composite data type as a graph from the Data Type Manager
 *
 * The graphing is done recursively in a separate task
 */
public class DisplayTypeAsGraphAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	/*
	 * Constructor
	 *
	 * @param plugin the plugin this action is contained in
	 */
	public DisplayTypeAsGraphAction(DataTypeManagerPlugin plugin) {
		super("Display Data Type as Graph", plugin.getName());
		this.plugin = plugin;

		String menuGroup = "ZVeryLast"; // it's own group; on the bottom
		setPopupMenuData(new MenuData(new String[] { "Display as Graph" }, null, menuGroup));
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "Type_Graph"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GraphDisplayBroker broker = plugin.getTool().getService(GraphDisplayBroker.class);
		if (broker == null) {
			Msg.showError(this, null, "Missing Plugin", "The Graph plugin is not installed.\n" +
				"Please add the plugin implementing this service.");
			return;
		}
		GraphDisplayProvider service = broker.getDefaultGraphDisplayProvider();

		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();

		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof DataTypeNode)) {
				continue;
			}
			DataTypeNode dataTypeNode = (DataTypeNode) node;
			DataType dt = dataTypeNode.getDataType();
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			if (dt instanceof Composite || dt instanceof Pointer) {
				TypeGraphTask task = new TypeGraphTask(dataTypeNode.getDataType(), service);
				new TaskLauncher(task, plugin.getTool().getToolFrame());
			}
		}

	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		boolean enabled = false;

		if (!(context instanceof DataTypesActionContext)) {
			return enabled;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();

		for (TreePath path : selectionPaths) {

			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof DataTypeNode)) {
				continue;
			}

			DataTypeNode dtNode = (DataTypeNode) node;
			DataType dt = dtNode.getDataType();
			if (dt instanceof TypeDef) {
				dt = ((TypeDef) dt).getBaseDataType();
			}
			if (dt instanceof Composite || dt instanceof Pointer) {
				enabled = true;
			}
		}
		return enabled;
	}

}
