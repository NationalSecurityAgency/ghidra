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
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.util.StringUtilities;

public class CreateTypeDefAction extends AbstractTypeDefAction {

	private static final int MAX_DISPLAY_CHAR_LENGTH = 20;

	public CreateTypeDefAction(DataTypeManagerPlugin plugin) {
		super("Create Typedef", plugin);
		setPopupMenuData(new MenuData(new String[] { "New", "Typedef" }, null, "Create"));
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
			dtName = StringUtilities.trim(dtName, MAX_DISPLAY_CHAR_LENGTH);
			MenuData newMenuData =
				new MenuData(new String[] { "New", "Typedef on " + dtName }, null, "Create");
			setPopupMenuData(newMenuData);
		}

		return enabled;
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

	@Override
	public void actionPerformed(ActionContext context) {

		DataTypeArchiveGTree gTree = (DataTypeArchiveGTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		DataTypeNode dataTypeNode = (DataTypeNode) selectionPaths[0].getLastPathComponent();
		DataType dataType = dataTypeNode.getDataType();

		String baseName = getBaseName(dataType) + "Typedef";
		DerivativeDataTypeInfo info =
			new DerivativeDataTypeInfo(plugin, gTree, dataTypeNode, dataType);

		DataTypeManager dataTypeManager = info.getDataTypeManager();
		String name = dataTypeManager.getUniqueName(dataType.getCategoryPath(), baseName);

		CategoryPath categoryPath = info.getCategoryPath();
		DataType newTypeDef = createTypeDef(dataTypeManager, dataType, categoryPath, context,
			dataTypeNode.getParent(), name);
		if (newTypeDef == null) {
			return;
		}

		GTreeNode finalParentNode = info.getParentNode();
		String newNodeName = newTypeDef.getName();
		gTree.startEditing(finalParentNode, newNodeName);
	}

	private static String getBaseName(DataType dt) {
		if (dt instanceof Pointer) {
			DataType dataType = ((Pointer) dt).getDataType();
			if (dataType == null) {
				// must be a generic pointer type
				return dt.getName();
			}
			return getBaseName(dataType) + "Ptr";
		}
		return dt.getDisplayName();
	}
}
