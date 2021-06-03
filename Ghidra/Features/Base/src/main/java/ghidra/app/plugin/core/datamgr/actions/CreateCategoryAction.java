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
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.InvalidNameException;

public class CreateCategoryAction extends DockingAction {

	private static final String NEW_CATEGORY = "New Category";

	public CreateCategoryAction(DataTypeManagerPlugin plugin) {
		super("New Category", plugin.getName());

		setPopupMenuData(new MenuData(new String[] { "New", "Category" }, null, "Create"));
		setDescription("Creates a new Category.");
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		CategoryNode categoryNode = getSelectedCategoryNode(context);
		if (categoryNode == null || !categoryNode.isEnabled()) {
			return false;
		}
		if (categoryNode instanceof BuiltInArchiveNode) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		CategoryNode categoryNode = getSelectedCategoryNode(context);
		return categoryNode != null && categoryNode.isModifiable();
	}

	private CategoryNode getSelectedCategoryNode(ActionContext context) {
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

		if (!(node instanceof CategoryNode)) {
			return null;
		}
		return (CategoryNode) node;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		final DataTypeArchiveGTree gtree = (DataTypeArchiveGTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		final CategoryNode node = (CategoryNode) selectionPaths[0].getLastPathComponent();
		Category category = node.getCategory();
		ArchiveNode archiveNode = node.getArchiveNode();
		Archive archive = archiveNode.getArchive();
		DataTypeManager dataTypeManager = archive.getDataTypeManager();

		String newNodeName = null;
		int transactionID = dataTypeManager.startTransaction("Create Category");
		try {
			newNodeName = getUniqueCategoryName(category);
			category.createCategory(newNodeName);
		}
		catch (InvalidNameException ie) {
			// can't happen since we created a unique valid name.
		}
		finally {
			dataTypeManager.endTransaction(transactionID, true);
		}

		dataTypeManager.flushEvents();
		gtree.startEditing(node, newNodeName);
	}

	private String getUniqueCategoryName(Category parent) {
		int index = 1;
		String name = NEW_CATEGORY;

		Category category = parent.getCategory(name);
		while (category != null) {
			name = NEW_CATEGORY + index;
			++index;
			category = parent.getCategory(name);
		}
		return name;
	}
}
