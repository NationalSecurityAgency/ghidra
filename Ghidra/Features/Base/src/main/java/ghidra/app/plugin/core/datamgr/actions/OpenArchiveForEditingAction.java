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
import docking.widgets.tree.*;
import ghidra.app.plugin.core.datamgr.*;
import ghidra.app.plugin.core.datamgr.tree.FileArchiveNode;
import ghidra.program.model.dtarchive.FileDataTypeArchive;

/**
 * Action to convert a read-only archive to be open for editing
 */
public class OpenArchiveForEditingAction extends DockingAction {
	public static final String ACTION_NAME = "Open Archive For Editing";
	private DataTypeManagerPlugin plugin;

	public OpenArchiveForEditingAction(DataTypeManagerPlugin plugin) {
		super(ACTION_NAME, plugin.getName());
		this.plugin = plugin;
		setPopupMenuData(new MenuData(new String[] { "Open For Editing" }, null, "FileEdit"));
		setEnabled(true);
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);

		return isOnlyFileArchivesSelected(selectionPaths);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		TreePath[] selectionPaths = getSelectionPaths(context);
		return isOnlyFileArchivesSelected(selectionPaths) &&
			isOneOrMoreSelectedFileArchivesLockable(selectionPaths);
	}

	private boolean isOnlyFileArchivesSelected(TreePath[] selectionPaths) {
		// only valid if all selected paths are file archives
		if (selectionPaths.length == 0) {
			return false;
		}
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (!(node instanceof FileArchiveNode)) {
				return false;
			}
		}

		return true;
	}

	private boolean isOneOrMoreSelectedFileArchivesLockable(TreePath[] selectionPaths) {
		// only valid if all selected paths are file archives
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (canOpenForEditing(node)) {
				return true;
			}
		}
		return false;
	}

	private TreePath[] getSelectionPaths(ActionContext context) {
		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		return selectionPaths;
	}

	private boolean canOpenForEditing(GTreeNode node) {
		FileArchiveNode fileNode = (FileArchiveNode) node;
		FileDataTypeArchive archive = fileNode.getArchive();
		String fname = archive.getFile().getName();
		if (!fname.endsWith(FileDataTypeArchive.SUFFIX)) {
			return false;
		}
		return !archive.isChangeable();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();

		GTreeState treeState = gTree.getTreeState();

		for (TreePath path : selectionPaths) {
			FileArchiveNode node = (FileArchiveNode) path.getLastPathComponent();
			FileDataTypeArchive archive = node.getArchive();
			if (!archive.isChangeable()) {
				ArchiveManager archiveManager = plugin.getArchiveManager();
				archiveManager.reopenFileArchive(archive, true);
			}
		}

		gTree.restoreTreeState(treeState);

	}
}
