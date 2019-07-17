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

import java.awt.Component;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.util.*;

public class CreatePointerAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public CreatePointerAction(DataTypeManagerPlugin plugin) {
		super("Create Pointer", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "New", "Pointer" }, null, "Create"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypeArchiveGTree gTree = (DataTypeArchiveGTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();
		DataType baseDataType = dataTypeNode.getDataType();

		DerivativeDataTypeInfo info =
			new DerivativeDataTypeInfo(plugin, gTree, dataTypeNode, baseDataType);
		CategoryPath categoryPath = info.getCategoryPath();
		PointerDataType pointerDataType = new PointerDataType(baseDataType);
		DataTypeManager dataTypeManager = info.getDataTypeManager();
		DataType newDataType =
			createNewDataType(gTree, pointerDataType, categoryPath, dataTypeManager);

		DataTypesProvider provider = plugin.getProvider();
		if (provider.isFilteringPointers()) {
			DataTypePath newPath = new DataTypePath(categoryPath, newDataType.getName());
			DataTypeManager newManager = newDataType.getDataTypeManager();
			Msg.showInfo(getClass(), gTree, "Pointers Filter Enabled",
				"<html>Newly created pointer is filtered out of view.<br><br>Toggle the " +
					"<b>Filter Pointers " + "Action</b> to view the pointer<br>Pointer: " +
					HTMLUtilities.escapeHTML(newManager.getName() + newPath));
			return;
		}

		GTreeNode parentNode = info.getParentNode();
		TreePath treePath = parentNode.getTreePath();
		String newNodeName = newDataType.getName();
		SystemUtilities.runSwingLater(() -> {
			TreePath newPath = treePath.pathByAddingChild(newNodeName);
			gTree.setSelectedNodeByPathName(newPath);
		});
	}

	private DataType createNewDataType(Component parentComponent, DataType dataType,
			CategoryPath categoryPath, DataTypeManager dataTypeManager) {
		int transactionID = dataTypeManager.startTransaction("Create Typedef");
		try {
			return dataTypeManager.addDataType(dataType, plugin.getConflictHandler());
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		DataTypeTreeNode node = getDataTypeNode(context);
		if (node == null) {
			return false;
		}

		ArchiveNode archiveNode = node.getArchiveNode();
		if (archiveNode == null) {
			// this can happen as the tree is changing
			return false;
		}

		boolean enabled = archiveNode.isModifiable();
		if (archiveNode instanceof BuiltInArchiveNode) {
			// these will be put into the program archive
			enabled = true;
		}

		// update the menu item to add the name of the item we are working on
		if (enabled) {
			String dtName = node.getName();
			dtName = StringUtilities.trim(dtName, 10);
			MenuData newMenuData =
				new MenuData(new String[] { "New", "Pointer to " + dtName }, null, "Create");
			setPopupMenuData(newMenuData);
		}

		return enabled;
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		DataTypeNode node = getDataTypeNode(context);
		if (node == null) {
			return false;
		}

		DataType dataType = node.getDataType();
		DataTypeManager dataTypeManager = dataType.getDataTypeManager();
		if (dataTypeManager instanceof BuiltInDataTypeManager) {
			DataTypeManager manager = plugin.getProgramDataTypeManager();
			if (manager == null) {
				return false; // no program open; can't work from the built-in in this case
			}
		}

		return true;
	}

	private DataTypeNode getDataTypeNode(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof DataTypeNode)) {
			return null;
		}
		return (DataTypeNode) node;
	}
}
