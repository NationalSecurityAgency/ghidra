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
import ghidra.app.plugin.core.datamgr.archive.ArchiveUtils;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.FileArchiveNode;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.Msg;

import java.awt.Component;
import java.io.IOException;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.*;

public class UnlockArchiveAction extends DockingAction {
	public static final String ACTION_NAME = "Unlock Archive";

	private final DataTypeManagerPlugin plugin;

	public UnlockArchiveAction(DataTypeManagerPlugin plugin) {
		super(ACTION_NAME, plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Close For Editing" }, null, "FileEdit"));

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
			isOneOrMoreSelectedFileArchivesLocked(selectionPaths);
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

	private boolean isOneOrMoreSelectedFileArchivesLocked(TreePath[] selectionPaths) {
		// only valid if all selected paths are file archives
		for (TreePath path : selectionPaths) {
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (hasWriteLock((FileArchiveNode) node)) {
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

	private boolean hasWriteLock(FileArchiveNode fileArchiveNode) {
		FileArchive archive = (FileArchive) fileArchiveNode.getArchive();
		return archive.hasWriteLock();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gTree.getSelectionPaths();
		GTreeState treeState = gTree.getTreeState();

		DataTypeEditorManager editorManager = plugin.getEditorManager();
		for (TreePath path : selectionPaths) {
			FileArchiveNode node = (FileArchiveNode) path.getLastPathComponent();
			FileArchive archive = (FileArchive) node.getArchive();
			if (!canReleaseLock(archive, gTree)) {
				continue;
			}
			DataTypeManager dataTypeManager = archive.getDataTypeManager();
			if (!editorManager.checkEditors(dataTypeManager, true)) {
				return;
			}
			// check for changes and save if desired by user. If cancelled, get out.
			if (!ArchiveUtils.canClose(archive, gTree)) {
				return;
			}
			editorManager.dismissEditors(dataTypeManager);

			releaseLock(archive);
		}
		gTree.restoreTreeState(treeState);
	}

	private boolean canReleaseLock(FileArchive archive, Component parent) {
		if (archive.getFile() == null) {
			Msg.showInfo(getClass(), parent,
				"Unsaved Archive", "Unsaved Archives must first be saved.");
			return false;
		}
		return true;
	}

	private void releaseLock(FileArchive archive) {
		try {
			archive.releaseWriteLock();
		}
		catch (IOException ioe) {
			Msg.showError(this, plugin.getProvider().getComponent(),
				"Unable to Release Write Lock",
				"Problem attempting to release write lock for archive: " + archive.getName() +
					"\nMessage: " + ioe.getMessage(), ioe);
		}
	}
}
