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

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.tree.ArchiveNode;
import ghidra.app.plugin.core.datamgr.tree.DataTypeTreeNode;
import ghidra.app.plugin.core.datamgr.util.DataTypeTreeDeleteTask;

public class DeleteAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public DeleteAction(DataTypeManagerPlugin plugin) {
		super("Delete", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Delete" }, null, "Edit"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		if (selectionPaths == null || selectionPaths.length == 0) {
			return false;
		}

		if (containsUndeletableNodes(selectionPaths)) {
			return false;
		}

		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		return canDelete(selectionPaths);
	}

	private TreePath[] getSelectionPaths(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		return selectionPaths;
	}

	private boolean containsUndeletableNodes(TreePath[] selectionPaths) {
		for (TreePath path : selectionPaths) {
			DataTypeTreeNode node = (DataTypeTreeNode) path.getLastPathComponent();
			if (!node.canDelete() || (node instanceof ArchiveNode)) {
				return true;
			}
		}
		return false;
	}

	private boolean canDelete(TreePath[] selectionPaths) {
		// only valid if all selected paths are of the correct type
		for (TreePath path : selectionPaths) {
			DataTypeTreeNode node = (DataTypeTreeNode) path.getLastPathComponent();
			if (!node.canCut()) {
				return false;
			}
		}
		return true;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		int choice = OptionDialog.showYesNoDialogWithNoAsDefaultButton(null,
			"Confirm Delete Operation", "Are you sure you want to delete selected\n categories " +
				"and/or dataTypes?\n(Note: There is no undo for archives.)");
		if (choice != OptionDialog.OPTION_ONE) {
			return;
		}

		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		List<GTreeNode> nodeList = new ArrayList<>(selectionPaths.length);
		for (TreePath path : selectionPaths) {
			nodeList.add((GTreeNode) path.getLastPathComponent());
		}
		plugin.getTool().execute(new DataTypeTreeDeleteTask(plugin, nodeList), 250);
	}
}
