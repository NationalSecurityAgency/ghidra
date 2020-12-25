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

import java.util.Iterator;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.Archive;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.program.model.data.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

public class AlignAllDataTypesAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public AlignAllDataTypesAction(DataTypeManagerPlugin plugin) {
		super("Align All Data Types", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Align All..." }, "Edit"));
		setHelpLocation(new HelpLocation(plugin.getName(), getName()));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof GTree)) {
			return false;
		}

		GTree gTree = (GTree) contextObject;
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		if (selectionPaths == null || selectionPaths.length != 1) {
			return false;
		}

		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if ((node instanceof ProgramArchiveNode) || (node instanceof ProjectArchiveNode) ||
			(node instanceof FileArchiveNode)) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			if (!archiveNode.isEnabled()) {
				return false;
			}
			return true;
		}
		return false;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gTree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gTree.getSelectionPaths();
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if ((node instanceof ProgramArchiveNode) || (node instanceof ProjectArchiveNode) ||
			(node instanceof FileArchiveNode)) {
			ArchiveNode archiveNode = (ArchiveNode) node;
			Archive archive = archiveNode.getArchive();
			if (archive.isModifiable()) {
				DataTypeManager dataTypeManager = archive.getDataTypeManager();
				DataOrganization dataOrganization = dataTypeManager.getDataOrganization();

				int result =
					OptionDialog.showOptionDialog(
						plugin.getTool().getToolFrame(),
						"Align Data Types",
						"Are you sure you want to align all of the data types in " +
							dataTypeManager.getName() +
							"?\nBoth structures and unions that are currently unaligned will become aligned.\n" +
							"This could cause component offsets to change and datatype sizes to change.\n" +
							"Do you want to continue?", "Continue", OptionDialog.WARNING_MESSAGE);
				if (result == OptionDialog.CANCEL_OPTION) {
					return;
				}
				alignDataTypes(dataTypeManager, dataOrganization);
			}
			else {
				Msg.showWarn(this, gTree, "Alignment Not Allowed",
					"The archive must be modifiable to align data types.");
			}
		}
	}

	private void alignDataTypes(DataTypeManager dataTypeManager, DataOrganization dataOrganization) {
		if (dataTypeManager == null) {
			Msg.error(this, "Can't align data types without a data type manager.");
			return;
		}
		int transactionID = -1;
		boolean commit = false;
		try {
			// start a transaction
			transactionID =
				dataTypeManager.startTransaction("Align all data types in " +
					dataTypeManager.getName());
			alignEachStructure(dataTypeManager, dataOrganization);
			commit = true;
		}
		finally {
			// commit the changes
			dataTypeManager.endTransaction(transactionID, commit);
		}
	}

	private void alignEachStructure(DataTypeManager dataTypeManager,
			DataOrganization dataOrganization) {
		Iterator<? extends Composite> allComposites = dataTypeManager.getAllComposites();
		while (allComposites.hasNext()) {
			Composite composite = allComposites.next();
			composite.setInternallyAligned(true);
		}
	}

}
