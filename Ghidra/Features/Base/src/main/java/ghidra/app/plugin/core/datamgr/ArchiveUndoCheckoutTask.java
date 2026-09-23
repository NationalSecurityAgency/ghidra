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
package ghidra.app.plugin.core.datamgr;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.widgets.tree.GTreeState;
import generic.theme.GIcon;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.app.plugin.core.datamgr.tree.DataTypeArchiveGTree;
import ghidra.app.services.Recover;
import ghidra.app.services.Upgrade;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.SaveDataDialog;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.UndoActionDialog;
import ghidra.framework.main.projectdata.actions.VersionControlAction;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Action to undo checkouts for domain files in the repository.
 */
public class ArchiveUndoCheckoutTask extends VersionControlAction {

	private static final Icon ICON =
		new GIcon("icon.base.util.datatree.version.control.archive.dt.checkout.undo");

	private DataTypeManagerPlugin dtmPlugin;

	/**
	 * Creates an action to undo checkouts for domain files in the repository.
	 * @param plugin the plug-in that owns this action.
	 * @param provider provides a list of domain files to be affected by this action.
	 */
	public ArchiveUndoCheckoutTask(DataTypeManagerPlugin plugin) {
		super("UndoCheckOut", plugin.getName(), plugin.getTool());
		this.dtmPlugin = plugin;

		setPopupMenuData(new MenuData(new String[] { "Undo Checkout" }, ICON, GROUP));
		setDescription("Undo checkout");

	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		undoCheckOut((DataTypesActionContext) context);
	}

	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		if (!(context instanceof DataTypesActionContext dataTypesContext)) {
			return false;
		}
		if (isFileSystemBusy()) {
			return false; // don't block; we should get called again later
		}

		List<ProjectDataTypeArchive> archives = dataTypesContext.getSelectedProjectArchives();
		for (ProjectDataTypeArchive archive : archives) {
			if (archive.getDomainFile().isCheckedOut()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Gets the domain files from the provider and then undoes the checkout on any that are 
	 * checked out.
	 * @param context 
	 */
	protected void undoCheckOut(DataTypesActionContext context) {
		if (!checkRepositoryConnected()) {
			return;
		}

		List<ProjectDataTypeArchive> archives = context.getSelectedProjectArchives();
		closeEditorsForUndoCheckOut(archives);

		List<ProjectDataTypeArchive> unmodifiedCheckOutsList = new ArrayList<>();
		List<ProjectDataTypeArchive> modifiedCheckOutsList = new ArrayList<>();
		for (ProjectDataTypeArchive archive : archives) {
			DomainFile domainFile = archive.getDomainFile();
			if (domainFile.isCheckedOut()) {
				if (domainFile.modifiedSinceCheckout() || domainFile.isChanged()) {
					modifiedCheckOutsList.add(archive);
				}
				else {
					unmodifiedCheckOutsList.add(archive);
				}
			}
		}

		try {
			undoCheckOuts(unmodifiedCheckOutsList, modifiedCheckOutsList);
		}
		catch (CancelledException e) {
			tool.setStatusInfo("Undo checkouts was canceled");
			return;
		}
	}

	private void closeEditorsForUndoCheckOut(List<ProjectDataTypeArchive> archives) {
		DataTypeEditorManager editorManager = dtmPlugin.getEditorManager();
		for (ProjectDataTypeArchive archive : archives) {
			if (!editorManager.checkEditors(archive.getDataTypeManager(), true)) {
				continue;
			}
			editorManager.dismissEditors(archive.getDataTypeManager());
		}
	}

	/**
	 * Displays the undo checkout confirmation dialog for each checked out file and then 
	 * undoes the checkout while keeping a copy of the working version of the file if the 
	 * user chooses to do so.<br>
	 * All unmodified checkouts will be undone. Only modified checkouts the user chooses
	 * will be undone.
	 * @param unmodifiedArchivesList the list of unmodified archives
	 * @param modifiedArchivesList the list of archives that have been modified
	 * @throws CancelledException if cancelled
	 */
	protected void undoCheckOuts(List<ProjectDataTypeArchive> unmodifiedArchivesList,
			List<ProjectDataTypeArchive> modifiedArchivesList) throws CancelledException {
		boolean saveCopy = false;
		boolean undoWasCancelled = false;
		List<ProjectDataTypeArchive> selectedArchives = modifiedArchivesList;

		// Now confirm the modified ones and undo checkout for the ones the user indicates.
		if (modifiedArchivesList.size() > 0) {
			UndoActionDialog dialog = new UndoActionDialog("Confirm Undo Checkout",
				ICON, "UndoCheckOut", "checkout", getDomainFileList(modifiedArchivesList));
			int actionID = dialog.showDialog(tool);
			if (actionID != UndoActionDialog.CANCEL) {
				saveCopy = dialog.saveCopy();
				DomainFile[] selectedFiles = dialog.getSelectedDomainFiles();
				selectedArchives = getMatchingArchives(modifiedArchivesList, selectedFiles);
			}
			else {
				throw new CancelledException();
			}
		}
		if ((unmodifiedArchivesList.size() > 0) || (selectedArchives.size() > 0)) {
			tool.execute(new DataTypeArchiveUndoCheckOutTask(unmodifiedArchivesList,
				selectedArchives, saveCopy));
		}
		if (undoWasCancelled) {
			tool.setStatusInfo("Undo check out was canceled");
		}
	}

	private List<ProjectDataTypeArchive> getMatchingArchives(
			List<ProjectDataTypeArchive> archivesList, DomainFile[] selectedFiles) {

		List<ProjectDataTypeArchive> archiveList = new ArrayList<>(selectedFiles.length);
		for (DomainFile domainFile : selectedFiles) {
			ProjectDataTypeArchive archive = getArchiveForDomainFile(archivesList, domainFile);
			if (archive != null) {
				archiveList.add(archive);
			}
			else {
				// This shouldn't happen.
				throw new AssertException(
					"Can't find data type archive for domain file " + domainFile.getName());
			}
		}
		return archiveList;
	}

	private ProjectDataTypeArchive getArchiveForDomainFile(
			List<ProjectDataTypeArchive> archivesList, DomainFile domainFile) {
		for (ProjectDataTypeArchive domainFileArchive : archivesList) {
			if (domainFileArchive.getDomainFile() == domainFile) {
				return domainFileArchive;
			}
		}
		return null;
	}

	private List<DomainFile> getDomainFileList(List<ProjectDataTypeArchive> modifiedArchivesList) {
		List<DomainFile> dfList = new ArrayList<>(modifiedArchivesList.size());
		for (ProjectDataTypeArchive archive : modifiedArchivesList) {
			dfList.add(archive.getDomainFile());
		}
		return dfList;
	}

	/**
	 * Saves all checked out changes.
	 * @param changedList the list of changes
	 * @throws CancelledException if cancelled
	 */
	protected void saveCheckOutChanges(List<DomainFile> changedList) throws CancelledException {
		if (changedList.size() > 0) {
			SaveDataDialog dialog = new SaveDataDialog(tool);
			boolean cancelled = !dialog.showDialog(changedList);
			if (cancelled) {
				throw new CancelledException();
			}
		}
	}

	/**
	 * Task for undoing check out of files that are in version control.
	 */
	private class DataTypeArchiveUndoCheckOutTask extends Task {
		private List<ProjectDataTypeArchive> unmodifiedCheckOutsList;
		private List<ProjectDataTypeArchive> modifiedCheckedOutFiles;
		private boolean saveCopy;

		/**
		 * Creates a task for undoing checkouts of domain files.
		 * @param unmodifiedCheckOutsList the list of unmodified checked out files
		 * @param modifiedCheckedOutFiles the list of checked out files that have been modified
		 * @param saveCopy true indicates that copies of the modified files should be made 
		 * before undo of the checkout.
		 */
		DataTypeArchiveUndoCheckOutTask(List<ProjectDataTypeArchive> unmodifiedCheckOutsList,
				List<ProjectDataTypeArchive> modifiedCheckedOutFiles, boolean saveCopy) {
			super("Undo Check Out", true, true, true);

			this.unmodifiedCheckOutsList = unmodifiedCheckOutsList;
			this.modifiedCheckedOutFiles = modifiedCheckedOutFiles;
			this.saveCopy = saveCopy;
		}

		@Override
		public void run(TaskMonitor monitor) {
			DataTypeArchiveGTree gTree = dtmPlugin.getProvider().getGTree();
			GTreeState treeState = gTree.getTreeState();
			try {
				ArchiveManager archiveManager = dtmPlugin.getArchiveManager();
				for (ProjectDataTypeArchive archive : unmodifiedCheckOutsList) {
					DomainFile df = archive.getDomainFile();
					if (df.isCheckedOut() && (dtmPlugin != null)) {
						archiveManager.closeArchive(archive);
						df.undoCheckout(false);
						archiveManager.openProjectArchiveInTask(df, DomainFile.DEFAULT_VERSION,
							Upgrade.ASK, Recover.ASK, false);
					}
				}
				for (ProjectDataTypeArchive currentArchive : modifiedCheckedOutFiles) {
					monitor.checkCancelled();
					DomainFile currentDF = currentArchive.getDomainFile();

					if (saveCopy && currentDF.isChanged()) {
						monitor.setMessage("Saving " + currentDF.getName());
						currentDF.save(monitor);
					}

					monitor.setMessage("Undoing Check Out " + currentDF.getName());

					archiveManager.closeArchive(currentArchive);
					currentDF.undoCheckout(saveCopy);
					archiveManager.openProjectArchiveInTask(currentDF, DomainFile.DEFAULT_VERSION,
						Upgrade.ASK, Recover.ASK, true);
				}
			}
			catch (CancelledException e) {
				tool.setStatusInfo("Undo check out was canceled");
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Undo Check Out", tool.getToolFrame());
			}
			gTree.restoreTreeState(treeState);
		}

	}
}
