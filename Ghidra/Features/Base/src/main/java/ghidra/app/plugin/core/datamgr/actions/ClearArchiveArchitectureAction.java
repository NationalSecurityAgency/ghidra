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

import java.io.IOException;

import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import docking.widgets.tree.GTree;
import docking.widgets.tree.GTreeNode;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.DataTypesActionContext;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.tree.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.LockException;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

public class ClearArchiveArchitectureAction extends DockingAction {

	private final DataTypeManagerPlugin plugin;

	public ClearArchiveArchitectureAction(DataTypeManagerPlugin plugin) {
		super("Clear Archive Architecture", plugin.getName());
		this.plugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Clear Architecture" }, null, "SetArch"));

		setDescription(
			"Clear program-architecture associated with a data type archive (existing custom storage details will be discarded)");

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
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof FileArchiveNode) && !(node instanceof ProjectArchiveNode)) {
			return false;
		}
		ArchiveNode archiveNode = (ArchiveNode) node;
		StandAloneDataTypeManager dtm =
			(StandAloneDataTypeManager) archiveNode.getArchive().getDataTypeManager();

		return dtm.getProgramArchitectureSummary() != null && dtm.isUpdatable();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		GTree gtree = (GTree) context.getContextObject();
		TreePath[] selectionPaths = gtree.getSelectionPaths();
		if (selectionPaths.length != 1) {
			return;
		}
		GTreeNode node = (GTreeNode) selectionPaths[0].getLastPathComponent();
		if (!(node instanceof FileArchiveNode) && !(node instanceof ProjectArchiveNode)) {
			return;
		}

		if (node instanceof ProjectArchiveNode) {
			ProjectArchiveNode paNode = (ProjectArchiveNode) node;
			ProjectArchive pa = (ProjectArchive) paNode.getArchive();
			if (!pa.hasExclusiveAccess()) {
				Msg.showError(this, null, "Clear Program Architecture Failed",
					"Clearing program-architecture on Project Archive requires exclusive checkout.");
				return;
			}
		}

		ArchiveNode archiveNode = (ArchiveNode) node;
		StandAloneDataTypeManager dtm =
			(StandAloneDataTypeManager) archiveNode.getArchive().getDataTypeManager();

		if (dtm.isChanged()) {
			if (OptionDialog.OPTION_ONE != OptionDialog.showOptionDialogWithCancelAsDefaultButton(
				null, "Save Archive Changes",
				"Archive has unsaved changes which must be saved before continuing." +
					"\nThis is required to allow for a reversion to the previous saved state.",
				"Save")) {
				return;
			}
			try {
				archiveNode.getArchive().save();
			}
			catch (IOException e) {
				Msg.showError(this, null, "Save Archive Failed",
					"Failed to save changes for Archive: " + dtm.getName() + "\n" + e.getMessage());
				return;
			}
		}

		// TODO: Update message indicating that custom storage specification will not be 
		// retained/permitted (once supported)
		String msg = "<html>Clear program-architecture for Archive?<BR><font color=\"" +
			Messages.NORMAL + "\">" + dtm.getPath() +
			"</font><BR> <BR>Archive will revert to using default data organization.";
		int response = OptionDialog.showOptionDialogWithCancelAsDefaultButton(null,
			"Confirm Clearing Archive Architecture", msg, "Clear Architecture",
			OptionDialog.WARNING_MESSAGE);
		if (response != OptionDialog.OPTION_ONE) {
			return;
		}

		new TaskLauncher(new ClearProgramArchitectureTask(archiveNode.getArchive(), dtm));
	}

	private class ClearProgramArchitectureTask extends Task {

		private final Archive archive;
		private final StandAloneDataTypeManager dtm;

		public ClearProgramArchitectureTask(Archive archive, StandAloneDataTypeManager dtm) {
			super("Clearing Program-Architecture for Archive", true, false, true, false);
			this.archive = archive;
			this.dtm = dtm;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			boolean success = false;
			try {
				dtm.clearProgramArchitecture(monitor);
				success = true;
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				Msg.showError(this, null, "Archive Update Failed",
					"Failed to clear program-architecture for Archive: " + dtm.getName() + "\n" +
						e.getMessage());
			}
			finally {
				if (!success) {
					if (archive instanceof FileArchive) {
						try {
							((FileArchive) archive).releaseWriteLock();
							((FileArchive) archive).acquireWriteLock();
						}
						catch (LockException | IOException e) {
							archive.close();
						}
					}
					else { // if (archive instanceof ProjectArchive) {
						archive.close();
						DomainFile df = ((ProjectArchive) archive).getDomainFile();
						plugin.openArchive(df);
					}
				}
			}
		}

	}

}
