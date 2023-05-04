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
package ghidra.framework.main.projectdata.actions;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.UndoActionDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.FileInUseException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Action to undo checkouts for domain files in the repository.
 */
public class VersionControlUndoCheckOutAction extends VersionControlAction {

	private static final Icon ICON = new GIcon("icon.version.control.check.out.undo");

	/**
	 * Creates an action to undo checkouts for domain files in the repository.
	 * @param plugin the plug-in that owns this action.
	 */
	public VersionControlUndoCheckOutAction(Plugin plugin) {
		super("UndoCheckOut", plugin.getName(), plugin.getTool());
		setPopupMenuData(new MenuData(new String[] { "Undo Checkout" }, ICON, GROUP));
		setToolBarData(new ToolBarData(ICON, GROUP));
		setDescription("Undo checkout");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		undoCheckOut(context.getSelectedFiles());
	}

	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		if (isFileSystemBusy()) {
			return false; // don't block; we should get called again later
		}

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
	private void undoCheckOut(List<DomainFile> domainFiles) {
		if (!checkRepositoryConnected()) {
			return;
		}
		List<DomainFile> unmodifiedCheckOutsList = new ArrayList<>();
		List<DomainFile> modifiedCheckOutsList = new ArrayList<>();
		for (DomainFile domainFile : domainFiles) {
			if (domainFile.isCheckedOut()) {
				if (domainFile.modifiedSinceCheckout()) {
					modifiedCheckOutsList.add(domainFile);
				}
				else {
					unmodifiedCheckOutsList.add(domainFile);
				}
			}
		}
		undoCheckOuts(unmodifiedCheckOutsList, modifiedCheckOutsList);
	}

	/**
	 * Displays the undo checkout confirmation dialog for each checked out file and then 
	 * undoes the checkout while keeping a copy of the working version of the file if the 
	 * user chooses to do so.<br>
	 * All unmodified checkouts will be undone. Only modified checkouts the user chooses
	 * will be undone.
	 * @param unmodifiedCheckOutsList the list of unmodified checked out files
	 * @param modifiedCheckOutsList the list of checked out files that have been modified
	 */
	private void undoCheckOuts(List<DomainFile> unmodifiedCheckOutsList,
			List<DomainFile> modifiedCheckOutsList) {
		boolean saveCopy = false;
		DomainFile[] files = new DomainFile[0];
		boolean undoWasCancelled = false;
		// Now confirm the modified ones and undo checkout for the ones the user indicates.
		if (modifiedCheckOutsList.size() > 0) {
			UndoActionDialog dialog = new UndoActionDialog("Confirm Undo Checkout",
				ICON, "UndoCheckOut", "checkout", modifiedCheckOutsList);
			int actionID = dialog.showDialog(tool);
			if (actionID != UndoActionDialog.CANCEL) {
				saveCopy = dialog.saveCopy();
				files = dialog.getSelectedDomainFiles();
			}
			else {
				undoWasCancelled = true;
			}
		}
		if ((unmodifiedCheckOutsList.size() > 0) || (files.length > 0)) {
			tool.execute(new UndoCheckOutTask(unmodifiedCheckOutsList, files, saveCopy));
		}
		if (undoWasCancelled) {
			tool.setStatusInfo("Undo check out was canceled");
		}
	}

	/**
	 * Task for undoing check out of files that are in version control.
	 */
	private class UndoCheckOutTask extends Task {
		private List<DomainFile> unmodifiedCheckOutsList;
		private DomainFile[] modifiedCheckedOutFiles;
		private boolean saveCopy;

		/**
		 * Creates a task for undoing checkouts of domain files.
		 * @param unmodifiedCheckOutsList the list of unmodified checked out files
		 * @param modifiedCheckedOutFiles the list of checked out files that have been modified
		 * @param saveCopy true indicates that copies of the modified files should be made 
		 * before undo of the checkout
		 */
		UndoCheckOutTask(List<DomainFile> unmodifiedCheckOutsList,
				DomainFile[] modifiedCheckedOutFiles, boolean saveCopy) {
			super("Undo Check Out", true, true, true);
			this.unmodifiedCheckOutsList = unmodifiedCheckOutsList;
			this.modifiedCheckedOutFiles = modifiedCheckedOutFiles;
			this.saveCopy = saveCopy;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				for (DomainFile df : unmodifiedCheckOutsList) {
					if (df.isCheckedOut()) {
						df.undoCheckout(false);
					}
				}
				for (DomainFile currentDF : modifiedCheckedOutFiles) {
					monitor.checkCancelled();
					monitor.setMessage("Undoing Check Out " + currentDF.getName());
					currentDF.undoCheckout(saveCopy);
				}
			}
			catch (CancelledException e) {
				tool.setStatusInfo("Undo check out was canceled");
			}
			catch (FileInUseException e) {
				Msg.showError(this, null, "Action Failed",
					"Unable to Undo Checkout while file(s) are open or in use");
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Undo Check Out", tool.getToolFrame());
			}
		}

	}
}
