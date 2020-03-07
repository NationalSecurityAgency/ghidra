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
package ghidra.framework.main.datatree;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.ImageIcon;

import docking.action.MenuData;
import ghidra.app.plugin.core.datamgr.DataTypeManagerPlugin;
import ghidra.app.plugin.core.datamgr.archive.*;
import ghidra.app.plugin.core.datamgr.editor.DataTypeEditorManager;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.SaveDataDialog;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.projectdata.actions.VersionControlAction;
import ghidra.framework.model.DomainFile;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

/**
 * Action to undo checkouts for domain files in the repository.
 */
public class VersionControlDataTypeArchiveUndoCheckoutAction extends VersionControlAction {

	private DataTypeManagerPlugin dtmPlugin;
	private ArchiveProvider archiveProvider;

	/**
	 * Creates an action to undo checkouts for domain files in the repository.
	 * @param plugin the plug-in that owns this action.
	 * @param provider provides a list of domain files to be affected by this action.
	 */
	public VersionControlDataTypeArchiveUndoCheckoutAction(DataTypeManagerPlugin plugin,
			ArchiveProvider provider) {
		super("UndoCheckOut", plugin.getName(), plugin.getTool());
		this.dtmPlugin = plugin;
		this.archiveProvider = provider;
		ImageIcon icon = ResourceManager.loadImage("images/vcUndoCheckOut.png");
		setPopupMenuData(new MenuData(new String[] { "Undo Checkout" }, icon, GROUP));
		setDescription("Undo checkout");

	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		undoCheckOut();
	}

	/**
	 * Returns true if at least one of the provided domain files is checked out from the repository.
	 */
	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		List<DomainFile> domainFiles = context.getSelectedFiles();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.isCheckedOut()) {
				return true; // At least one checked out file selected.
			}
		}
		return false;
	}

	/**
	 * Gets the domain files from the provider and then undoes the checkout on any that are 
	 * checked out.
	 */
	protected void undoCheckOut() {
		if (!checkRepositoryConnected()) {
			return;
		}

		closeEditorsForUndoCheckOut();

		List<Archive> archiveList = archiveProvider.getArchives();
		List<DomainFileArchive> unmodifiedCheckOutsList = new ArrayList<DomainFileArchive>();
		List<DomainFileArchive> modifiedCheckOutsList = new ArrayList<DomainFileArchive>();
		for (Archive archive2 : archiveList) {
			ProjectArchive archive = (ProjectArchive) archive2;
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

	private void closeEditorsForUndoCheckOut() {
		DataTypeEditorManager editorManager = dtmPlugin.getEditorManager();
		List<Archive> archiveList = archiveProvider.getArchives();
		for (Archive archive : archiveList) {
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
	 * @throws CancelledException 
	 */
	protected void undoCheckOuts(List<DomainFileArchive> unmodifiedArchivesList,
			List<DomainFileArchive> modifiedArchivesList) throws CancelledException {
		boolean saveCopy = false;
		DomainFile[] selectedFiles = new DomainFile[0];
		boolean undoWasCancelled = false;
		List<DomainFileArchive> selectedArchives = modifiedArchivesList;
		// Now confirm the modified ones and undo checkout for the ones the user indicates.
		if (modifiedArchivesList.size() > 0) {
			UndoActionDialog dialog = new UndoActionDialog("Confirm Undo Checkout",
				resources.ResourceManager.loadImage("images/vcUndoCheckOut.png"), "UndoCheckOut",
				"checkout", getDomainFileList(modifiedArchivesList));
			int actionID = dialog.showDialog(tool);
			if (actionID != UndoActionDialog.CANCEL) {
				saveCopy = dialog.saveCopy();
				selectedFiles = dialog.getSelectedDomainFiles();
				selectedArchives = getMatchingArchives(modifiedArchivesList, selectedFiles);
			}
			else {
				throw new CancelledException();
			}
		}
		if ((unmodifiedArchivesList.size() > 0) || (selectedFiles.length > 0)) {
			tool.execute(new DataTypeArchiveUndoCheckOutTask(unmodifiedArchivesList,
				selectedArchives, saveCopy));
		}
		if (undoWasCancelled) {
			tool.setStatusInfo("Undo check out was canceled");
		}
	}

	private List<DomainFileArchive> getMatchingArchives(List<DomainFileArchive> archivesList,
			DomainFile[] selectedFiles) {
		List<DomainFileArchive> archiveList =
			new ArrayList<DomainFileArchive>(selectedFiles.length);
		for (DomainFile domainFile : selectedFiles) {
			DomainFileArchive archive = getArchiveForDomainFile(archivesList, domainFile);
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

	private DomainFileArchive getArchiveForDomainFile(List<DomainFileArchive> archivesList,
			DomainFile domainFile) {
		for (DomainFileArchive domainFileArchive : archivesList) {
			if (domainFileArchive.getDomainFile() == domainFile) {
				return domainFileArchive;
			}
		}
		return null;
	}

	private List<DomainFile> getDomainFileList(List<DomainFileArchive> modifiedArchivesList) {
		List<DomainFile> dfList = new ArrayList<DomainFile>(modifiedArchivesList.size());
		for (DomainFileArchive dfArchive : modifiedArchivesList) {
			dfList.add(dfArchive.getDomainFile());
		}
		return dfList;
	}

	/**
	 * Saves all checked out changes.
	 * @param changedList the list of changes
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
		private List<DomainFileArchive> unmodifiedCheckOutsList;
		private List<DomainFileArchive> modifiedCheckedOutFiles;
		private boolean saveCopy;

		/**
		 * Creates a task for undoing checkouts of domain files.
		 * @param unmodifiedCheckOutsList the list of unmodified checked out files
		 * @param modifiedCheckedOutFiles the list of checked out files that have been modified
		 * @param saveCopy true indicates that copies of the modified files should be made 
		 * before undo of the checkout.
		 */
		DataTypeArchiveUndoCheckOutTask(List<DomainFileArchive> unmodifiedCheckOutsList,
				List<DomainFileArchive> modifiedCheckedOutFiles, boolean saveCopy) {
			super("Undo Check Out", true, true, true);

			this.unmodifiedCheckOutsList = unmodifiedCheckOutsList;
			this.modifiedCheckedOutFiles = modifiedCheckedOutFiles;
			this.saveCopy = saveCopy;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				for (int i = 0; i < unmodifiedCheckOutsList.size(); i++) {
					DomainFileArchive archive = unmodifiedCheckOutsList.get(i);
					DomainFile df = archive.getDomainFile();
					if (df.isCheckedOut() && (dtmPlugin != null)) {
						// TODO Need to close archive here if it is open.
						archive.close();

						df.undoCheckout(false);

						// TODO Need to open the archive here if it got closed above.
						dtmPlugin.openArchive(df);

					}
				}
				for (DomainFileArchive currentArchive : modifiedCheckedOutFiles) {
					monitor.checkCanceled();
					DomainFile currentDF = currentArchive.getDomainFile();

					if (saveCopy && currentDF.isChanged()) {
						monitor.setMessage("Saving " + currentDF.getName());
						currentDF.save(monitor);
					}

					monitor.setMessage("Undoing Check Out " + currentDF.getName());

					// TODO Need to close archive here if it is open.
					currentArchive.close();

					currentDF.undoCheckout(saveCopy);

					// TODO Need to open the archive here if it got closed above.
					dtmPlugin.openArchive(currentDF);

				}
			}
			catch (CancelledException e) {
				tool.setStatusInfo("Undo check out was canceled");
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Undo Check Out", tool.getToolFrame());
			}
		}

	}
}
