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
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.util.Msg;

import java.io.IOException;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;

public class SaveArchiveAction extends DockingAction {
	private final DataTypeManagerPlugin plugin;

	public SaveArchiveAction(DataTypeManagerPlugin plugin) {
		super("Save", plugin.getName());
		this.plugin = plugin;

// ACTIONS - auto generated
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
		if ((node instanceof FileArchiveNode) || (node instanceof ProjectArchiveNode)) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			Archive archive = archiveNode.getArchive();
			return archive.isChanged() && archive.isSavable();
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gTree.getSelectionPaths();
		for (TreePath path : selectionPaths) {
			Object node = path.getLastPathComponent();
			if (node instanceof ArchiveNode) {
				ArchiveNode archiveNode = (ArchiveNode) node;
				Archive archive = archiveNode.getArchive();
				if (archive.isChanged()) {
					saveArchive(archive);
				}
			}
		}
	}

	private void saveFileArchive(FileArchive archive) {
		try {
			archive.save();
		}
		catch (IOException ioe) {
			Msg.showError(this, plugin.getProvider().getComponent(), "Unable to Save File",
				"Unexpected exception attempting to save archive: " + archive, ioe);
		}
	}

	private void saveProjectArchive(ProjectArchive archive) {
		DataTypeManagerHandler dtmHandler = plugin.getDataTypeManagerHandler();
		dtmHandler.save(archive.getDomainObject());
	}

	private void saveArchive(Archive archive) {
		if (archive instanceof ProjectArchive) {
			saveProjectArchive((ProjectArchive) archive);
		}
		else if (archive instanceof FileArchive) {
			saveFileArchive((FileArchive) archive);
		}
		else {
			throw new IllegalArgumentException(archive.getName() +
				" must be Project or File archive.");
		}
	}
}
