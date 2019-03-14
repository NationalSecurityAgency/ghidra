/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.*;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class RenameAction extends DockingAction {

	public RenameAction(DataTypeManagerPlugin plugin) {
		super("Rename", plugin.getName());

		setPopupMenuData(new MenuData(new String[] { "Rename" }, null, "Edit"));
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		GTreeNode node = getSelectedNode(context);
		if (node == null || node instanceof ArchiveRootNode || node instanceof ArchiveNode) {
			return false;
		}
		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		GTreeNode node = getSelectedNode(context);
		return node != null && node.isEditable();
	}

	private GTreeNode getSelectedNode(ActionContext context) {
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
		return node;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DataTypeArchiveGTree gtree = (DataTypeArchiveGTree) context.getContextObject();
		rename(gtree);
	}

	void rename(final DataTypeArchiveGTree tree) {
		TreePath path = tree.getSelectionPath();
		final GTreeNode node = (GTreeNode) path.getLastPathComponent();
		tree.startEditing(node.getParent(), node.getName());
	}

}
