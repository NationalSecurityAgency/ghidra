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
import java.io.IOException;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.FileArchive;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;

public class DeleteArchiveAction extends DockingAction {

	public DeleteArchiveAction(DataTypeManagerPlugin plugin) {
		super("Delete Archive", plugin.getName());

// ACTIONS - auto generated
		setPopupMenuData(new MenuData(new String[] { "Delete Archive" }, null, "Edit"));

		setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));

		setEnabled(true);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return false;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof FileArchiveNode)) {
			return false;
		}
		return ((ArchiveNode) node).isModifiable();
	}

	@Override
	public boolean isAddToPopup(ActionContext context) {
		if (!(context instanceof DataTypesActionContext)) {
			return false;
		}

		Object contextObject = context.getContextObject();
		GTree gtree = (GTree) contextObject;
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return false;
		}

		DataTypeTreeNode node = (DataTypeTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof FileArchiveNode)) {
			return false;
		}
		return node instanceof FileArchiveNode;

	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		FileArchiveNode node = (FileArchiveNode) selectionPaths[0].getLastPathComponent();

		if (OptionDialog.showOptionDialogWithCancelAsDefaultButton(gTree,
			"Confirm Delete Operation",
			"<html><b>Are you sure you want to delete archive: " +
				HTMLUtilities.escapeHTML(node.getName()) + "?<br><br>" +
				"<font color=\"red\">(WARNING: This action will permanently " +
				"delete the file from disk.)</font></b>",
			"Yes", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
			return;
		}

		try {
			((FileArchive) node.getArchive()).delete();
		}
		catch (IOException e1) {
			Msg.showError(this, null, "Error", "Error deleting data type archive.", e1);
		}
	}
}
