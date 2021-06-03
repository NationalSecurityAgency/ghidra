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
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.BuiltInArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.CategoryNode;
import ghidra.program.model.data.Category;

public abstract class CreateDataTypeAction extends DockingAction {
	protected final DataTypeManagerPlugin plugin;

	CreateDataTypeAction(DataTypeManagerPlugin plugin, String name) {
		super(name, plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "New", name + "..." }, "Create"));
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
		if (selectionPaths == null || selectionPaths.length != 1) {
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
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] paths = gTree.getSelectionPaths();
		CategoryNode node = (CategoryNode) paths[0].getLastPathComponent();
		Category category = node.getCategory();

		DataTypeEditorManager editorManager = plugin.getEditorManager();
		createNewDataType(editorManager, category);
	}

	protected abstract void createNewDataType(DataTypeEditorManager editorManager,
			Category category);
}
