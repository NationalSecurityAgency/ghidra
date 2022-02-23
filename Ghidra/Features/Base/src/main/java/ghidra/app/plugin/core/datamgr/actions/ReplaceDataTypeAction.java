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
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.archive.DataTypeManagerHandler;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

/**
 * Replace the selected data type with the chosen data type
 */
public class ReplaceDataTypeAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public ReplaceDataTypeAction(DataTypeManagerPlugin plugin) {
		super("Replace Data Type", plugin.getName());

		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Replace Data Type..." }, "Edit"));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		if (node instanceof BuiltInArchiveNode) {
			return false;
		}
		return (node != null);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);
		if (node == null) {
			return false;
		}

		if (!(node instanceof DataTypeNode)) {
			return false;
		}
		return node.isModifiable();
	}

	private DataTypeTreeNode getSelectedDataTypeTreeNode(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length == 0) {
			return null;
		}

		if (selectionPaths.length > 1) {
			return null;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		return node;
	}

	@Override
	public void actionPerformed(ActionContext context) {

		PluginTool tool = plugin.getTool();
		int noSizeRestriction = -1;
		DataTypeSelectionDialog selectionDialog = new DataTypeSelectionDialog(tool,
			plugin.getProgram().getDataTypeManager(), noSizeRestriction, AllowedDataTypes.ALL);
		tool.showDialog(selectionDialog);
		DataType newDt = selectionDialog.getUserChosenDataType();
		if (newDt == null) {
			return; // cancelled
		}

		DataTypeTreeNode node = getSelectedDataTypeTreeNode(context);

		DataTypeManagerHandler dtmHandler = plugin.getDataTypeManagerHandler();
		DataTypeManager dtm = newDt.getDataTypeManager();
		Archive sourceArchive = dtmHandler.getArchive(dtm);
		Archive destinationArchive = findArchive(node);

		DataType oldDt = ((DataTypeNode) node).getDataType();
		if (sourceArchive != destinationArchive) {
			oldDt = oldDt.clone(oldDt.getDataTypeManager());
		}

		int txId = dtm.startTransaction("Replace Data Type");
		try {
			dtm.replaceDataType(oldDt, newDt, true);
		}
		catch (DataTypeDependencyException e) {
			Msg.showError(this, null, "Replace Failed", "Replace failed.  Existing type " + newDt +
				"; replacment type " + oldDt + ". " + e.getMessage());
		}
		finally {
			dtm.endTransaction(txId, true);
		}
	}

	private Archive findArchive(GTreeNode node) {
		while (node != null) {
			if (node instanceof ArchiveNode) {
				return ((ArchiveNode) node).getArchive();
			}
			node = node.getParent();
		}
		return null;
	}
}
