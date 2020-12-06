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
import ghidra.app.cmd.function.CaptureFunctionDataTypesCmd;
import ghidra.app.cmd.function.CaptureFunctionDataTypesListener;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class CaptureFunctionDataTypesAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public CaptureFunctionDataTypesAction(DataTypeManagerPlugin plugin) {
		super("Capture Function Data Types", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Capture Function Data Types" }, null,
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
//        if (node instanceof CategoryNode) {
//            setEnabled( ((CategoryNode)node).isModifiable() );
//        }

		return (node instanceof ProgramArchiveNode) || (node instanceof FileArchiveNode) ||
			(node instanceof ProjectArchiveNode);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath selectionPath = gTree.getSelectionPath();
		ArchiveNode node = (ArchiveNode) selectionPath.getLastPathComponent();
		if (!node.getArchive().isModifiable()) {
			informNotModifiable(node);
			return;
		}

		Program program = plugin.getProgram();
		AddressSetView currentSelection = plugin.getCurrentSelection();
		if (currentSelection == null || currentSelection.isEmpty()) {
			currentSelection = program.getMemory();
		}
		final DataTypeManager manager = node.getArchive().getDataTypeManager();
		final PluginTool tool = plugin.getTool();
		CaptureFunctionDataTypesCmd cmd =
			new CaptureFunctionDataTypesCmd(manager, currentSelection,
				new CaptureFunctionDataTypesListener() {

					@Override
					public void captureFunctionDataTypesCompleted(
							CaptureFunctionDataTypesCmd command) {
						tool.setStatusInfo("Captured function data types to \"" +
							manager.getName() + "\".");
					}
				});
		tool.executeBackgroundCommand(cmd, program);
	}

	private void informNotModifiable(ArchiveNode node) {
		String message;
		if (node instanceof ProgramArchiveNode) {
			message = "The program \"" + node.getName() + "\" isn't modifiable.";
		}
		else if (node instanceof ProjectArchiveNode) {
			message = "The data type archive \"" + node.getName() + "\" isn't checked out.";
		}
		else if (node instanceof ProjectArchiveNode) {
			message = "The data type archive \"" + node.getName() + "\" isn't open for editing.";
		}
		else {
			message = "The data type archive \"" + node.getName() + "\" isn't modifiable.";
		}
		Msg.showInfo(getClass(),
			plugin.getTool().getToolFrame(), "Cannot Capture Data Types", message);
	}
}
