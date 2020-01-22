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
import ghidra.util.HelpLocation;
import ghidra.util.Swing;

public class CreateTypeDefFromDialogAction extends AbstractTypeDefAction {

	private static final String NAME = "Create Typedef From Dialog";

	public CreateTypeDefFromDialogAction(DataTypeManagerPlugin plugin) {
		super(NAME, plugin);
		setPopupMenuData(new MenuData(new String[] { "New", "Typedef..." }, null, "Create"));
	}

	@Override
	public void actionPerformed(ActionContext context) {

		CategoryNode categoryNode = getCategoryNode(context);
		Category category = categoryNode.getCategory();
		CreateTypeDefDialog dialog =
			new CreateTypeDefDialog(plugin, category, categoryNode.getTreePath());
		dialog.setHelpLocation(new HelpLocation(plugin.getName(), NAME));
		plugin.getTool().showDialog(dialog);

		if (dialog.isCancelled()) {
			return;
		}

		String name = dialog.getTypeDefName();
		DataType dataType = dialog.getDataType();
		DataTypeManager dataTypeManager = dialog.getDataTypeManager();

		final DataTypeArchiveGTree gTree = (DataTypeArchiveGTree) context.getContextObject();
		CategoryPath categoryPath = category.getCategoryPath();
		DataType newTypeDef =
			createTypeDef(dataTypeManager, dataType, categoryPath, context, categoryNode, name);
		if (newTypeDef == null) {
			return;
		}

		dataTypeManager.flushEvents();

		final GTreeNode parentNode = categoryNode;
		final String newNodeName = newTypeDef.getName();
		Swing.runLater(() -> gTree.setSeletedNodeByName(parentNode, newNodeName));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		CategoryNode categoryNode = getCategoryNode(context);
		if (categoryNode instanceof BuiltInArchiveNode) {
			return false;
		}
		return categoryNode != null && categoryNode.isModifiable();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		CategoryNode categoryNode = getCategoryNode(context);
		if (categoryNode == null || !categoryNode.isEnabled()) {
			return false;
		}
		if (categoryNode instanceof BuiltInArchiveNode) {
			return false;
		}
		return true;
	}

	private CategoryNode getCategoryNode(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return null;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;

		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return null;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		return getCategoryForNode(node);
	}

	private CategoryNode getCategoryForNode(GTreeNode node) {
		while (!(node instanceof CategoryNode) && node != null) {
			node = node.getParent();
		}
		return (CategoryNode) node;
	}
}
