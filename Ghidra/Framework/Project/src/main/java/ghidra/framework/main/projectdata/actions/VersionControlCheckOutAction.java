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
import java.util.*;

import javax.swing.ImageIcon;

import docking.action.MenuData;
import docking.action.ToolBarData;
import docking.widgets.OptionDialog;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.main.datatable.DomainFileContext;
import ghidra.framework.main.datatree.CheckoutDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.remote.User;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import resources.ResourceManager;

/**
 * Action to checkout domain files from the repository.
 */
public class VersionControlCheckOutAction extends VersionControlAction {

	/**
	 * Creates an action to checkout domain files from the repository
	 * @param plugin the plug-in that owns this action
	 */
	public VersionControlCheckOutAction(Plugin plugin) {
		this(plugin.getName(), plugin.getTool());
	}

	/*package*/ VersionControlCheckOutAction(String owner, PluginTool tool) {
		super("CheckOut", owner, tool);

		ImageIcon icon = ResourceManager.loadImage("images/vcCheckOut.png");
		setPopupMenuData(new MenuData(new String[] { "Check Out" }, icon, GROUP));
		setToolBarData(new ToolBarData(icon, GROUP));
		setDescription("Check out file");

		setEnabled(false);
	}

	@Override
	public void actionPerformed(DomainFileContext context) {
		checkOut(context.getSelectedFiles());
	}

	/**
	 * Returns true if at least one of the provided domain files can can be 
	 * checked out of the repository.
	 */
	@Override
	public boolean isEnabledForContext(DomainFileContext context) {
		List<DomainFile> providedList = context.getSelectedFiles();
		for (DomainFile domainFile : providedList) {
			if (domainFile.canCheckout()) {
				return true; // At least one version controlled, non-checked out file selected.
			}
		}
		return false;
	}

	private User getUser() {

		try {
			if (repository != null) {
				return repository.getUser();
			}
		}
		catch (IOException e) {
			ClientUtil.handleException(repository, e, "Check Out", tool.getToolFrame());
		}
		return null;
	}

	protected void checkOut(Collection<DomainFile> files) {

		if (!checkRepositoryConnected()) {
			return;
		}

		tool.execute(new CheckOutTask(files));
	}

	/**
	 * Task for checking out files that are in version control
	 */
	private class CheckOutTask extends Task {
		private Collection<DomainFile> files;
		private boolean exclusive = true;

		CheckOutTask(Collection<DomainFile> files) {
			super("Check Out", true, true, true);
			this.files = files;
		}

		private boolean gatherVersionedFiles(TaskMonitor monitor, List<DomainFile> results)
				throws CancelledException {

			monitor.setMessage("Examining Files...");
			monitor.setMaximum(files.size());

			for (DomainFile df : files) {
				monitor.checkCanceled();

				if (df.isVersioned() && !df.isCheckedOut()) {
					results.add(df);
				}
				monitor.incrementProgress(1);
			}

			int n = results.size();
			if (n == 0) {
				Msg.showError(this, tool.getToolFrame(), "Checkout Failed",
					"The specified files do not contain any versioned files available for " +
						"checkeout");
				return false;
			}

			//
			// Confirm checkout - prompt for exclusive checkout, if possible.  Otherwise, only
			//                    confirm a bulk checkout.
			//

			// note: a 'null' user means that we are using a local repository
			User user = getUser();
			if (user != null && user.hasWritePermission()) {
				CheckoutDialog checkout = new CheckoutDialog();
				if (checkout.showDialog(tool) != CheckoutDialog.OK) {
					return false;
				}
				exclusive = checkout.exclusiveCheckout();
				return true;
			}

			if (n == 1) {
				return true; // single file; no prompt needed
			}

			// more than one file
			int choice = OptionDialog.showYesNoDialogWithNoAsDefaultButton(tool.getToolFrame(),
				"Confirm Bulk Checkout",
				"Would you like to checkout " + results.size() + " files as specified?");
			return choice == OptionDialog.YES_OPTION;
		}

		@Override
		public void run(TaskMonitor monitor) {

			try {

				List<DomainFile> versionedFiles = new ArrayList<>();
				if (!gatherVersionedFiles(monitor, versionedFiles)) {
					return;
				}

				//
				// This task uses the monitor in a dual mode.  Each sub-task will control the 
				// progress such that each file goes from zero to complete.   This task will
				// control the message so that the user sees the overall progress (e.g., 
				// '1 of 10', etc...)
				// 
				monitor.setMaximum(0);
				monitor.setProgress(0);
				WrappingTaskMonitor wrappedMonitor = new WrappingTaskMonitor(monitor) {
					@Override
					public void setMessage(String message) {
						// do not let sub-tasks update the message, only this task
					}
				};

				List<DomainFile> failedCheckouts = new ArrayList<>();
				int progress = 0;
				for (DomainFile df : versionedFiles) {

					monitor.checkCanceled();
					monitor.setMessage("Checkout " + progress + " of " + versionedFiles.size() +
						": " + df.getName());

					if (!df.checkout(exclusive, wrappedMonitor)) {
						failedCheckouts.add(df);
					}
					++progress;
				}

				showResultsMessage(versionedFiles, failedCheckouts);
			}
			catch (CancelledException e) {
				tool.setStatusInfo("Checkout cancelled");
			}
			catch (IOException e) {
				ClientUtil.handleException(repository, e, "Check Out", tool.getToolFrame());
			}
		}

		private void showResultsMessage(List<DomainFile> allFiles, List<DomainFile> failedFiles) {

			int total = allFiles.size();
			if (failedFiles.isEmpty()) {
				String s = "Checkout completed for " + total + " file(s)";
				tool.setStatusInfo(s);
				Msg.info(this, s);
				return;
			}

			if (failedFiles.size() == 1) {
				DomainFile df = failedFiles.get(0);
				String s = "Exclusive checkout failed for: " + df.getName() +
					"\nOne or more users have file checked out!";
				Msg.showError(this, tool.getToolFrame(), "Checkout Failed", s);
				return;
			}

			String userMessage = "Multiple exclusive checkouts failed." +
				"\nOne or more users have file checked out!";
			StringBuilder buffy = new StringBuilder(userMessage + '\n');
			String message = "Exclusive checkout failed for: %s";
			for (DomainFile df : failedFiles) {
				String formatted = String.format(message, df.getName());
				buffy.append(formatted).append('\n');
			}

			Msg.showError(this, tool.getToolFrame(), "Checkout Failed",
				userMessage + "\n(see log for list of failed files)");
		}

	}

}
