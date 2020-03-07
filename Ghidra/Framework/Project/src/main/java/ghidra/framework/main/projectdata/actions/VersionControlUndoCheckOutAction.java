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

import javax.swing.ImageIcon;

import docking.action.MenuData;
import docking.action.ToolBarData;
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
import resources.ResourceManager;

/**
 * Action to undo checkouts for domain files in the repository.
 */
public class VersionControlUndoCheckOutAction extends VersionControlAction {

	/**
	 * Creates an action to undo checkouts for domain files in the repository.
	 * @param plugin the plug-in that owns this action.
	 */
	public VersionControlUndoCheckOutAction(Plugin plugin) {
		super("UndoCheckOut", plugin.getName(), plugin.getTool());
		ImageIcon icon = ResourceManager.loadImage("images/vcUndoCheckOut.png");
		setPopupMenuData(new MenuData(new String[] { "Undo Checkout" }, icon, GROUP));

		setToolBarData(new ToolBarData(icon, GROUP));

		setDescription("Undo checkout");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		undoCheckOut(context.getSelectedFiles());
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
	private void undoCheckOut(List<DomainFile> domainFiles) {
		if (!checkRepositoryConnected()) {
			return;
		}
		List<DomainFile> unmodifiedCheckOutsList = new ArrayList<DomainFile>();
		List<DomainFile> modifiedCheckOutsList = new ArrayList<DomainFile>();
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
				resources.ResourceManager.loadImage("images/vcUndoCheckOut.png"), "UndoCheckOut",
				"checkout", modifiedCheckOutsList);
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
		 * @param modifiedCheckOutsList the list of checked out files that have been modified
		 * @param saveCopy true indicates that copies of the modified files should be made 
		 * before undo of the checkout.
		 * @param listener the task listener to call when the task completes or is cancelled.
		 */
		UndoCheckOutTask(List<DomainFile> unmodifiedCheckOutsList,
				DomainFile[] modifiedCheckedOutFiles, boolean saveCopy) {
			super("Undo Check Out", true, true, true);
			this.unmodifiedCheckOutsList = unmodifiedCheckOutsList;
			this.modifiedCheckedOutFiles = modifiedCheckedOutFiles;
			this.saveCopy = saveCopy;
		}

		/* (non-Javadoc)
		 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
		 */
		@Override
		public void run(TaskMonitor monitor) {
			try {
				for (int i = 0; i < unmodifiedCheckOutsList.size(); i++) {
					DomainFile df = unmodifiedCheckOutsList.get(i);
					if (df.isCheckedOut()) {
						df.undoCheckout(false);
					}
				}
				for (DomainFile currentDF : modifiedCheckedOutFiles) {
					monitor.checkCanceled();
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
