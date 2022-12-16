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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.app.util.dialog.CheckoutDialog;
import ghidra.framework.client.ClientUtil;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.main.AppInfo;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.*;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.framework.remote.User;
import ghidra.framework.store.ExclusiveCheckoutException;
import ghidra.program.database.ProgramLinkContentHandler;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public class OpenProgramTask extends Task {

	private final List<OpenProgramRequest> openProgramRequests = new ArrayList<>();
	private List<OpenProgramRequest> openedProgramList = new ArrayList<>();

	private final Object consumer;
	private boolean silent; // if true operation does not permit interaction
	private boolean noCheckout; // if true operation should not perform optional checkout

	private String openPromptText = "Open";

	public OpenProgramTask(Object consumer) {
		super("Open Program(s)", true, false, true);
		this.consumer = consumer;
	}

	public OpenProgramTask(DomainFile domainFile, int version, boolean forceReadOnly,
			Object consumer) {
		super("Open Program(s)", true, false, true);
		this.consumer = consumer;
		openProgramRequests.add(new OpenProgramRequest(domainFile, version, forceReadOnly));
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

	public OpenProgramTask(URL ghidraURL, Object consumer) {
		super("Open Program(s)", true, false, true);
		this.consumer = consumer;
		openProgramRequests.add(new OpenProgramRequest(ghidraURL));
	}

	public void setOpenPromptText(String text) {
		openPromptText = text;
	}

	public void addProgramToOpen(DomainFile domainFile, int version) {
		addProgramToOpen(domainFile, version, false);
	}

	public void addProgramToOpen(DomainFile domainFile, int version, boolean forceReadOnly) {
		setHasProgress(true);
		openProgramRequests.add(new OpenProgramRequest(domainFile, version, forceReadOnly));
	}

	public void addProgramToOpen(URL ghidraURL) {
		setHasProgress(true);
		openProgramRequests.add(new OpenProgramRequest(ghidraURL));
	}

	public boolean hasOpenProgramRequests() {
		return !openProgramRequests.isEmpty();
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

	/**
	 * Get all successful open program requests
	 * @return all successful open program requests
	 */
	public List<OpenProgramRequest> getOpenPrograms() {
		return Collections.unmodifiableList(openedProgramList);
	}

	/**
	 * Get the first successful open program request
	 * @return first successful open program request or null if none
	 */
	public OpenProgramRequest getOpenProgram() {
		if (openedProgramList.isEmpty()) {
			return null;
		}
		return openedProgramList.get(0);
	}

	@Override
	public void run(TaskMonitor monitor) {

		taskMonitor.initialize(openProgramRequests.size());

		for (OpenProgramRequest domainFileInfo : openProgramRequests) {
			if (taskMonitor.isCancelled()) {
				return;
			}
			domainFileInfo.open();
			taskMonitor.incrementProgress(1);
		}
	}

	private Object openReadOnlyFile(DomainFile domainFile, URL url, int version) {
		taskMonitor.setMessage("Opening " + domainFile.getName());
		return openReadOnly(domainFile, url, version);
	}

	private Object openVersionedFile(DomainFile domainFile, URL url, int version) {
		taskMonitor.setMessage("Getting Version " + version + " for " + domainFile.getName());
		return openReadOnly(domainFile, url, version);
	}

	private Object openReadOnly(DomainFile domainFile, URL url, int version) {
		String contentType = domainFile.getContentType();
		String path = url != null ? url.toString() : domainFile.getPathname();
		Object obj = null;
		try {
			obj = domainFile.getReadOnlyDomainObject(consumer, version, taskMonitor);
		}
		catch (CancelledException e) {
			// we don't care, the task has been cancelled
		}
		catch (IOException e) {
			if (url == null && domainFile.isInWritableProject()) {
				ClientUtil.handleException(AppInfo.getActiveProject().getRepository(), e,
					"Get " + contentType, null);
			}
			else if (version != DomainFile.DEFAULT_VERSION) {
				Msg.showError(this, null, "Error Getting Versioned Program",
					"Could not get version " + version + " for " + path, e);
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
		return obj;
	}

	private Program openUnversionedFile(DomainFile domainFile) {
		String filename = domainFile.getName();
		taskMonitor.setMessage("Opening " + filename);
		performOptionalCheckout(domainFile);
		try {
			return openFileMaybeUgrade(domainFile);
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

	private Program openFileMaybeUgrade(DomainFile domainFile)
			throws IOException, CancelledException, VersionException {

		boolean recoverFile = false;
		if (!silent && domainFile.isInWritableProject() && domainFile.canRecover()) {
			recoverFile = askRecoverFile(domainFile.getName());
		}

		Program program = null;
		try {
			program =
				(Program) domainFile.getDomainObject(consumer, false, recoverFile, taskMonitor);
		}
		catch (VersionException e) {
			if (VersionExceptionHandler.isUpgradeOK(null, domainFile, openPromptText, e)) {
				program =
					(Program) domainFile.getDomainObject(consumer, true, recoverFile, taskMonitor);
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

	public class OpenProgramRequest {

		// ghidraURL and domainFile use are mutually exclusive
		private final URL ghidraURL;
		private final DomainFile domainFile;

		private URL linkURL; // link URL read from domainFile

		private final int version;
		private final boolean forceReadOnly;
		private Program program;

		public OpenProgramRequest(URL ghidraURL) {
			if (!GhidraURL.PROTOCOL.equals(ghidraURL.getProtocol())) {
				throw new IllegalArgumentException(
					"unsupported protocol: " + ghidraURL.getProtocol());
			}
			this.ghidraURL = ghidraURL;
			this.domainFile = null;
			this.version = -1;
			this.forceReadOnly = true;
		}

		public OpenProgramRequest(DomainFile domainFile, int version, boolean forceReadOnly) {
			this.domainFile = domainFile;
			this.ghidraURL = null;
			this.version =
				(domainFile.isReadOnly() && domainFile.isVersioned()) ? domainFile.getVersion()
						: version;
			this.forceReadOnly = forceReadOnly;
		}

		/**
		 * Get the {@link DomainFile} which corresponds to program open request.  This will be
		 * null for all URL-based open requests.
		 * @return {@link DomainFile} which corresponds to program open request or null.
		 */
		public DomainFile getDomainFile() {
			return domainFile;
		}

		/**
		 * Get the {@link URL} which corresponds to program open request.  This will be
		 * null for all non-URL-based open requests.  URL will be a {@link GhidraURL}.
		 * @return {@link URL} which corresponds to program open request or null.
		 */
		public URL getGhidraURL() {
			return ghidraURL;
		}

		/**
		 * Get the {@link URL} which corresponds to the link domainFile used to open a program.
		 * @return {@link URL} which corresponds to the link domainFile used to open a program.
		 */
		public URL getLinkURL() {
			return linkURL;
		}

		/**
		 * Get the open Program instance which corresponds to this open request.
		 * @return program instance or null if never opened.
		 */
		public Program getProgram() {
			return program;
		}

		/**
		 * Release opened program.  This must be done once, and only once, on a successful 
		 * open request.  If handing ownership off to another consumer, they should be added
		 * as a program consumer prior to invoking this method.  Releasing the last consumer
		 * will close the program instance.
		 */
		public void release() {
			if (program != null) {
				program.release(consumer);
			}
		}

		private Program openProgram(DomainFile df, URL url) {
			if (version != DomainFile.DEFAULT_VERSION) {
				return (Program) openVersionedFile(df, url, version);
			}
			if (forceReadOnly) {
				return (Program) openReadOnlyFile(df, url, version);
			}
			return openUnversionedFile(df);
		}

		void open() {
			DomainFile df = domainFile;
			URL url = ghidraURL;
			GhidraURLWrappedContent wrappedContent = null;
			Object content = null;
			try {
				if (df == null && url != null) {
					GhidraURLConnection c = (GhidraURLConnection) url.openConnection();
					Object obj = c.getContent(); // read-only access
					if (c.getStatusCode() == StatusCode.UNAUTHORIZED) {
						return; // assume user already notified
					}
					if (!(obj instanceof GhidraURLWrappedContent)) {
						messageBadProgramURL(url);
						return;
					}
					wrappedContent = (GhidraURLWrappedContent) obj;
					content = wrappedContent.getContent(this);
					if (!(content instanceof DomainFile)) {
						messageBadProgramURL(url);
						return;
					}
					df = (DomainFile) content;

					if (ProgramLinkContentHandler.PROGRAM_LINK_CONTENT_TYPE
							.equals(df.getContentType())) {
						Msg.showError(this, null, "Program Multi-Link Error",
							"Multi-link Program access not supported: " + url);
						return;
					}
				}

				if (!Program.class.isAssignableFrom(df.getDomainObjectClass())) {
					Msg.showError(this, null, "Error Opening Program",
						"File does not correspond to a Ghidra Program: " + df.getPathname());
					return;
				}

				program = openProgram(df, url);

			}
			catch (MalformedURLException e) {
				Msg.showError(this, null, "Invalid Ghidra URL",
					"Improperly formed Ghidra URL: " + url);
			}
			catch (IOException e) {
				Msg.showError(this, null, "Program Open Failed",
					"Failed to open Ghidra URL: " + e.getMessage());
			}
			finally {
				if (content != null) {
					wrappedContent.release(content, this);
				}
			}

			if (program != null) {
				openedProgramList.add(this);
			}
		}

		private void messageBadProgramURL(URL url) {
			Msg.error("Invalid Ghidra URL",
				"Ghidra URL does not reference a Ghidra Program: " + url);
		}
	}

}
