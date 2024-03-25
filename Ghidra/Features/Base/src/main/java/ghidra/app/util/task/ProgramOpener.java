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
import java.net.URL;
import java.util.concurrent.atomic.AtomicReference;

import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.progmgr.ProgramLocator;
import ghidra.app.util.dialog.CheckoutDialog;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURLQuery;
import ghidra.framework.protocol.ghidra.GhidraURLResultHandlerAdapter;
import ghidra.framework.remote.User;
import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * Helper class that contains the logic for opening program for all the various program locations
 * and program states. It handles opening DomainFiles, URLs, versioned DomainFiles, and links
 * to DomainFiles. It also handles upgrades and checkouts.
 */
public class ProgramOpener {
	private final Object consumer;
	private String openPromptText = "Open";
	private boolean silent = SystemUtilities.isInHeadlessMode(); 	// if true operation does not permit interaction
	private boolean noCheckout = false; // if true operation should not perform optional checkout

	/**
	 * Constructs this class with a consumer to use when opening a program.
	 * @param consumer the consumer for opening a program
	 */
	public ProgramOpener(Object consumer) {
		this.consumer = consumer;
	}

	/**
	 * Sets the text to use for the base action type for various prompts that can appear
	 * when opening programs. (The default is "Open".) For example, you may want to override
	 * this so be something like "Open Source", or "Open target".
	 * @param text the text to use as the base action name.
	 */
	public void setPromptText(String text) {
		openPromptText = text;
	}

	/**
	 * Invoking this method prior to task execution will prevent any confirmation interaction with
	 * the user (e.g., optional checkout, snapshot recovery, etc.).  Errors may still be displayed
	 * if they occur.
	 */
	public void setSilent() {
		this.silent = true;
	}

	/**
	 * Invoking this method prior to task execution will prevent the use of optional checkout which
	 * require prompting the user.
	 */
	public void setNoCheckout() {
		this.noCheckout = true;
	}

	/**
	 * Opens the program for the given location.
	 * This method is intended to be invoked from within a {@link Task} or for headless operations. 
	 * @param locator the program location to open
	 * @param monitor the TaskMonitor used for status and cancelling
	 * @return the opened program or null if the operation failed or was cancelled
	 */
	public Program openProgram(ProgramLocator locator, TaskMonitor monitor) {
		if (locator.isURL()) {
			try {
				return openURL(locator, monitor);
			}
			catch (CancelledException e) {
				return null;
			}
			catch (IOException e) {
				Msg.showError(this, null, "Program Open Failed",
					"Failed to open Ghidra URL: " + locator.getURL(), e);
			}
		}
		return openProgram(locator, locator.getDomainFile(), monitor);
	}

	private Program openURL(ProgramLocator locator, TaskMonitor monitor)
			throws CancelledException, IOException {
		URL ghidraUrl = locator.getURL();

		AtomicReference<Program> openedProgram = new AtomicReference<>();
		GhidraURLQuery.queryUrl(ghidraUrl, new GhidraURLResultHandlerAdapter() {
			@Override
			public void processResult(DomainFile domainFile, URL url, TaskMonitor m) {
				Program p = openProgram(locator, domainFile, m);  // may return null
				openedProgram.set(p);
			}
		}, monitor);

		return openedProgram.get();
	}

	private Program openProgram(ProgramLocator locator, DomainFile domainFile,
			TaskMonitor monitor) {

		if (!Program.class.isAssignableFrom(domainFile.getDomainObjectClass())) {
			Msg.showError(this, null, "Error Opening Program",
				"File does not correspond to a Ghidra Program: " + locator);
			return null;
		}

		int version = locator.getVersion();
		if (version != DomainFile.DEFAULT_VERSION) {
			monitor.setMessage("Getting Version " + version + " for " + domainFile.getName());
			return openReadOnly(locator, domainFile, monitor);
		}
		monitor.setMessage("Opening " + locator);
		if (locator.isURL()) {
			return openReadOnly(locator, domainFile, monitor);
		}
		return openNormal(domainFile, monitor);

	}

	private Program openNormal(DomainFile domainFile, TaskMonitor monitor) {
		String filename = domainFile.getName();
		performOptionalCheckout(domainFile, monitor);
		try {
			return openFileMaybeUgrade(domainFile, monitor);
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
		return null;
	}

	private Program openReadOnly(ProgramLocator locator, DomainFile domainFile,
			TaskMonitor monitor) {
		String contentType = domainFile.getContentType();
		String path = locator.toString();
		try {
			return (Program) domainFile.getReadOnlyDomainObject(consumer, locator.getVersion(),
				monitor);
		}
		catch (CancelledException e) {
			// we don't care, the task has been cancelled
		}
		catch (IOException e) {
			if (locator.isDomainFile() && domainFile.isInWritableProject()) {
				ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e,
					"Get " + contentType, null);
			}
			else if (locator.getVersion() != DomainFile.DEFAULT_VERSION) {
				Msg.showError(this, null, "Error Getting Versioned Program",
					"Could not get version " + locator.getVersion() + " for " + path, e);
			}
			else {
				Msg.showError(this, null, "Error Getting Program",
					"Open program failed for " + path, e);
			}
		}
		catch (VersionException e) {
			VersionExceptionHandler.showVersionError(null, domainFile.getName(), contentType,
				"Open", e);
		}
		return null;
	}

	private void performOptionalCheckout(DomainFile domainFile, TaskMonitor monitor) {

		if (silent || noCheckout || !domainFile.canCheckout()) {
			return;
		}

		User user = domainFile.getParent().getProjectData().getUser();

		CheckoutDialog dialog = new CheckoutDialog(domainFile, user);
		if (dialog.showDialog() == CheckoutDialog.CHECKOUT) {
			try {
				monitor.setMessage("Checking Out " + domainFile.getName());
				if (domainFile.checkout(dialog.exclusiveCheckout(), monitor)) {
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

	private Program openFileMaybeUgrade(DomainFile domainFile, TaskMonitor monitor)
			throws IOException, CancelledException, VersionException {

		boolean recoverFile = false;
		if (!silent && domainFile.isInWritableProject() && domainFile.canRecover()) {
			recoverFile = askRecoverFile(domainFile.getName());
		}

		Program program = null;
		try {
			program = (Program) domainFile.getDomainObject(consumer, false, recoverFile, monitor);
		}
		catch (VersionException e) {
			if (VersionExceptionHandler.isUpgradeOK(null, domainFile, openPromptText, e)) {
				program =
					(Program) domainFile.getDomainObject(consumer, true, recoverFile, monitor);
			}
		}
		return program;
	}

	private boolean askRecoverFile(final String filename) {

		int option = OptionDialog.showYesNoDialog(null, "Crash Recovery Data Found",
			"<html>" + HTMLUtilities.escapeHTML(filename) + " has crash data.<br>" +
				"Would you like to recover unsaved changes?");
		return option == OptionDialog.OPTION_ONE;
	}

}
