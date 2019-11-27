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
package ghidra.app.util.task;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.OptionDialog;
import ghidra.app.util.dialog.CheckoutDialog;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.remote.User;
import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class OpenProgramTask extends Task {

	private final List<DomainFileInfo> domainFileInfoList = new ArrayList<>();
	private List<Program> programList = new ArrayList<>();

	private final Object consumer;
	private boolean silent; // if true operation does not permit interaction
	private boolean noCheckout; // if true operation should not perform optional checkout

	private String openPromptText = "Open";

	public OpenProgramTask(DomainFile domainFile, int version, boolean forceReadOnly,
			Object consumer) {
		super("Open Program(s)", true, false, true);
		this.consumer = consumer;
		domainFileInfoList.add(new DomainFileInfo(domainFile, version, forceReadOnly));
	}

	public OpenProgramTask(DomainFile domainFile, int version, Object consumer) {
		this(domainFile, version, false, consumer);
	}

	public OpenProgramTask(DomainFile domainFile, boolean forceReadOnly, Object consumer) {
		this(domainFile, DomainFile.DEFAULT_VERSION, forceReadOnly, consumer);
	}

	public OpenProgramTask(DomainFile domainFile, Object consumer) {
		this(domainFile, DomainFile.DEFAULT_VERSION, false, consumer);
	}

	public OpenProgramTask(List<DomainFile> domainFileList, boolean forceReadOnly,
			Object consumer) {
		super("Open Program(s)", true, domainFileList.size() > 1, true);
		this.consumer = consumer;
		for (DomainFile domainFile : domainFileList) {
			domainFileInfoList.add(new DomainFileInfo(domainFile, -1, forceReadOnly));
		}
	}

	public OpenProgramTask(List<DomainFile> domainFileList, Object consumer) {
		this(domainFileList, false, consumer);
	}

	public void setOpenPromptText(String text) {
		openPromptText = text;
	}

	public void addProgramToOpen(DomainFile domainFile, int version) {
		addProgramToOpen(domainFile, version, false);
	}

	public void addProgramToOpen(DomainFile domainFile, int version, boolean forceReadOnly) {
		setHasProgress(true);
		domainFileInfoList.add(new DomainFileInfo(domainFile, version, forceReadOnly));
	}

	/**
	 * Invoking this method prior to task execution will prevent
	 * any confirmation interaction with the user (e.g., 
	 * optional checkout, snapshot recovery, etc.).  Errors
	 * may still be displayed if they occur.
	 */
	public void setSilent() {
		this.silent = true;
	}

	/**
	 * Invoking this method prior to task execution will prevent
	 * the use of optional checkout which require prompting the
	 * user.
	 */
	public void setNoCheckout() {
		this.noCheckout = true;
	}

	public List<Program> getOpenPrograms() {
		return programList;
	}

	public Program getOpenProgram() {
		if (programList.isEmpty()) {
			return null;
		}
		return programList.get(0);
	}

	@Override
	public void run(TaskMonitor monitor) {

		taskMonitor.initialize(domainFileInfoList.size());

		for (DomainFileInfo domainFileInfo : domainFileInfoList) {
			if (taskMonitor.isCancelled()) {
				return;
			}
			openDomainFile(domainFileInfo);

			taskMonitor.incrementProgress(1);
		}
	}

	private void openDomainFile(DomainFileInfo domainFileInfo) {
		int version = domainFileInfo.getVersion();
		DomainFile domainFile = domainFileInfo.getDomainFile();
		if (version != DomainFile.DEFAULT_VERSION) {
			openVersionedFile(domainFile, version);
		}
		else if (domainFileInfo.isReadOnly()) {
			openReadOnlyFile(domainFile, version);
		}
		else {
			openUnversionedFile(domainFile);
		}
	}

	private void openReadOnlyFile(DomainFile domainFile, int version) {
		taskMonitor.setMessage("Opening " + domainFile.getName());
		openReadOnly(domainFile, version);
	}

	private void openVersionedFile(DomainFile domainFile, int version) {
		taskMonitor.setMessage("Getting Version " + version + " for " + domainFile.getName());
		openReadOnly(domainFile, version);
	}

	private void openReadOnly(DomainFile domainFile, int version) {
		String contentType = null;
		try {
			contentType = domainFile.getContentType();
			Program program =
				(Program) domainFile.getReadOnlyDomainObject(consumer, version, taskMonitor);

			if (program == null) {
				String errorMessage = "Can't open program - \"" + domainFile.getPathname() + "\"";
				if (version != DomainFile.DEFAULT_VERSION) {
					errorMessage += " version " + version;
				}

				Msg.showError(this, null, "DomainFile Not Found", errorMessage);
			}
			else {
				programList.add(program);
			}
		}
		catch (CancelledException e) {
			// we don't care, the task has been cancelled
		}
		catch (IOException e) {
			if (domainFile.isInWritableProject()) {
				ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e,
					"Get Versioned Object", null);
			}
			else {
				Msg.showError(this, null, "Error Getting Versioned Object",
					"Could not get version " + version + " for " + domainFile.getName(), e);
			}
		}
		catch (VersionException e) {
			VersionExceptionHandler.showVersionError(null, domainFile.getName(), contentType,
				"Open", e);
		}
	}

	private void openUnversionedFile(DomainFile domainFile) {
		String filename = domainFile.getName();
		taskMonitor.setMessage("Opening " + filename);
		performOptionalCheckout(domainFile);
		try {
			openFileMaybeUgrade(domainFile);
		}
		catch (VersionException e) {
			String contentType = domainFile.getContentType();
			VersionExceptionHandler.showVersionError(null, filename, contentType, "Open", e);
		}
		catch (CancelledException e) {
			// we don't care, the task has been cancelled
		}
		catch (LanguageNotFoundException e) {
			Msg.showError(this, null, "Error Opening " + filename,
				e.getMessage() + "\nPlease contact the Ghidra team for assistance.");
		}
		catch (Exception e) {
			if (domainFile.isInWritableProject() && (e instanceof IOException)) {
				RepositoryAdapter repo = domainFile.getParent().getProjectData().getRepository();
				ClientUtil.handleException(repo, e, "Open File", null);
			}
			else {
				Msg.showError(this, null, "Error Opening " + filename,
					"Getting domain object failed.\n" + e.getMessage(), e);
			}
		}
	}

	private void openFileMaybeUgrade(DomainFile domainFile)
			throws IOException, CancelledException, VersionException {

		boolean recoverFile = false;
		if (!silent && domainFile.isInWritableProject() && domainFile.canRecover()) {
			recoverFile = askRecoverFile(domainFile.getName());
		}

		try {
			Program program =
				(Program) domainFile.getDomainObject(consumer, false, recoverFile, taskMonitor);

			if (program != null) {
				programList.add(program);
			}

		}
		catch (VersionException e) {
			if (VersionExceptionHandler.isUpgradeOK(null, domainFile, openPromptText, e)) {
				Program program =
					(Program) domainFile.getDomainObject(consumer, true, recoverFile, taskMonitor);
				if (program != null) {
					programList.add(program);
				}
			}
		}
	}

	private boolean askRecoverFile(final String filename) {

		int option = OptionDialog.showYesNoDialog(null, "Crash Recovery Data Found",
			"<html>" + HTMLUtilities.escapeHTML(filename) + " has crash data.<br>" +
				"Would you like to recover unsaved changes?");
		return option == OptionDialog.OPTION_ONE;
	}

	private void performOptionalCheckout(DomainFile domainFile) {

		if (silent || noCheckout || !domainFile.canCheckout()) {
			return;
		}

		User user = domainFile.getParent().getProjectData().getUser();

		CheckoutDialog dialog = new CheckoutDialog(domainFile, user);
		if (dialog.showDialog() == CheckoutDialog.CHECKOUT) {
			try {
				taskMonitor.setMessage("Checking Out " + domainFile.getName());
				if (domainFile.checkout(dialog.exclusiveCheckout(), taskMonitor)) {
					return;
				}
				Msg.showError(this, null, "Checkout Failed", "Exclusive checkout failed for: " +
					domainFile.getName() + "\nOne or more users have file checked out!");
			}
			catch (CancelledException e) {
				// we don't care, the task has been cancelled
			}
			catch (ExclusiveCheckoutException e) {
				Msg.showError(this, null, "Checkout Failed", e.getMessage());
			}
			catch (IOException e) {
				Msg.showError(this, null, "Error on Check Out", e.getMessage(), e);
			}
		}
	}

	static class DomainFileInfo {
		private final DomainFile domainFile;
		private final int version;
		private boolean forceReadOnly;

		public DomainFileInfo(DomainFile domainFile, int version, boolean forceReadOnly) {
			this.domainFile = domainFile;
			this.version =
				(domainFile.isReadOnly() && domainFile.isVersioned()) ? domainFile.getVersion()
						: version;
			this.forceReadOnly = forceReadOnly;
		}

		public boolean isReadOnly() {
			return forceReadOnly || domainFile.isReadOnly() ||
				version != DomainFile.DEFAULT_VERSION;
		}

		public DomainFile getDomainFile() {
			return domainFile;
		}

		public int getVersion() {
			return version;
		}

	}

}
