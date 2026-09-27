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
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.dtarchive.PersistentDataTypeArchive;

/**
 * Actions for saving datatype archives that support saving.
 */
public class SaveArchiveAction extends DockingAction {
	private final DataTypeManagerPlugin plugin;

	public SaveArchiveAction(DataTypeManagerPlugin plugin) {
		super("Save", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Save Archive" }, null, "File"));

		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);

		if (selectionPaths.length == 0) {
			return false;
		}

		// only valid if all selected paths are file archives
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof FileArchiveNode) && !(node instanceof ProjectArchiveNode)) {
				return false;
			}
		}

		return true;
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		return shouldBeEnabled(selectionPaths);
	}

	private TreePath[] getSelectionPaths(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		return selectionPaths;
	}

	private boolean shouldBeEnabled(TreePath[] selectionPaths) {
		// only enabled if all can be locked
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (canSave(node)) {
				return true;
			}
		}
		return false;
	}

	private boolean canSave(GTreeNode node) {
		if (node instanceof ArchiveNode archiveNode) {
			PersistentDataTypeArchive archive = archiveNode.getArchive();
			return archive.isChanged();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gTree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			Object node = path.getLastPathComponent();
			if (node instanceof ArchiveNode archiveNode) {
				PersistentDataTypeArchive archive = archiveNode.getArchive();
				if (archive.isChanged()) {
					ArchiveManager archiveManager = plugin.getArchiveManager();
					archiveManager.save(archive);
				}
			}
		}
	}
}
