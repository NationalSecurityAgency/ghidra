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

import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.cmd.function.ApplyFunctionDataTypesCmd;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

public class ApplyFunctionDataTypesAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public ApplyFunctionDataTypesAction(DataTypeManagerPlugin plugin) {
		super("Apply Function Data Types", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Apply Function Data Types" }, null,
			"VeryLast"));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (plugin.getProgram() == null) {
			return false;
		}

		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		return (node instanceof FileArchiveNode) || (node instanceof ProjectArchiveNode) ||
			(node instanceof ProgramArchiveNode);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath selectionPath = gTree.getSelectionPath();
		ArchiveNode node = (ArchiveNode) selectionPath.getLastPathComponent();

		Program program = plugin.getProgram();
		DataTypeManager manager = node.getArchive().getDataTypeManager();
		List<DataTypeManager> managerList = new ArrayList<DataTypeManager>();
		managerList.add(manager);
		ApplyFunctionDataTypesCmd cmd =
			new ApplyFunctionDataTypesCmd(managerList, null, SourceType.USER_DEFINED, true, true);
		PluginTool tool = plugin.getTool();
		tool.executeBackgroundCommand(cmd, program);
	}
}
