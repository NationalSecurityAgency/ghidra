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
import ghidra.util.Msg;

public class PackAllDataTypesAction extends DockingAction {

	private DataTypeManagerPlugin plugin;

	public PackAllDataTypesAction(DataTypeManagerPlugin plugin) {
		super("Pack All Composites", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Pack All..." }, "Edit"));
//		setHelpLocation(new HelpLocation(plugin.getName(), getName()));
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
						"Pack All Composites",
						"Are you sure you want to enable packing of all non-packed composites in " +
							dataTypeManager.getName() +
							"?\nAll structures and unions that are not currently packed will default packing enabled.\n" +
							"This could cause component offsets to change as well as size and alignment of these data types to change.\n" +
							"Do you want to continue?", "Continue", OptionDialog.WARNING_MESSAGE);
				if (result == OptionDialog.CANCEL_OPTION) {
					return;
				}
				packDataTypes(dataTypeManager, dataOrganization);
			}
			else {
				Msg.showWarn(this, gTree, "Modification Not Allowed",
					"The archive must be modifiable to pack data types.");
			}
		}
	}

	private void packDataTypes(DataTypeManager dataTypeManager, DataOrganization dataOrganization) {
		if (dataTypeManager == null) {
			Msg.error(this, "Can't pack data types without a data type manager.");
			return;
		}
		int transactionID = -1;
		boolean commit = false;
		try {
			// start a transaction
			transactionID =
				dataTypeManager.startTransaction("Pack Composite Types");
			packEachStructure(dataTypeManager, dataOrganization);
			commit = true;
		}
		finally {
			// commit the changes
			dataTypeManager.endTransaction(transactionID, commit);
		}
	}

	private void packEachStructure(DataTypeManager dataTypeManager,
			DataOrganization dataOrganization) {
		Iterator<? extends Composite> allComposites = dataTypeManager.getAllComposites();
		while (allComposites.hasNext()) {
			Composite composite = allComposites.next();
			if (!composite.isPackingEnabled()) {
				composite.setPackingEnabled(true);
			}
		}
	}

}
