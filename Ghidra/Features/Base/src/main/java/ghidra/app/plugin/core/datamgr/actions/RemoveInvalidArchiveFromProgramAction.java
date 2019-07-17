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
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.InvalidArchiveNode;
import ghidra.util.HTMLUtilities;

public class RemoveInvalidArchiveFromProgramAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public RemoveInvalidArchiveFromProgramAction(DataTypeManagerPlugin plugin) {
		super("Remove Invalid Archive", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(
			new MenuData(new String[] { "Remove Archive From Program" }, null, "File"));

		setDescription("Removes the archive from program and tool");
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
		if (selectionPaths.length != 1) {
			return false;
		}

		TreePath path = selectionPaths[0];
		GTreeNode node = (GTreeNode) path.getLastPathComponent();
		return node instanceof InvalidArchiveNode;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gtree = (GTree) context.getContextObject();

		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return;
		}
		Object pathComponent = selectionPaths[0].getLastPathComponent();

		// our isValidContext() ensures this cast is save
		InvalidArchiveNode invalidArchiveNode = (InvalidArchiveNode) pathComponent;

		if (OptionDialog.showOptionDialog(gtree, "Confirm Remove Invalid Archive(s)",
			"<html><b>Are you sure you want to delete archive: " +
				HTMLUtilities.escapeHTML(invalidArchiveNode.getName()) +
				" from the program?<br><br>" +
				"<font color=\"red\">(WARNING: This action will disassociate " +
				"all datatypes in the program from this archive.)</font></b>",
			"Yes", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
			return;
		}

		Archive archive = invalidArchiveNode.getArchive();
		DataTypeManagerHandler dataTypeManagerHandler = plugin.getDataTypeManagerHandler();
		dataTypeManagerHandler.removeInvalidArchive((InvalidFileArchive) archive);
	}
}
