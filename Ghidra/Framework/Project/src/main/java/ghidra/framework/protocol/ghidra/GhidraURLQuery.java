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
package ghidra.framework.protocol.ghidra;

import java.io.IOException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.framework.data.LinkHandler;
import ghidra.framework.data.LinkHandler.LinkStatus;
import ghidra.framework.data.NullFolderDomainObject;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GhidraURLQuery} performs remote Ghidra repository and read-only local project
 * queries for processing either a {@link DomainFile} or {@link DomainFolder} that a 
 * Ghidra URL may reference.
 */
public class GhidraURLQuery {

	/**
	 * {@link LinkFileControl} setting control how link-files will be followed.
	 */
	public enum LinkFileControl {

		/**
		 * No links are followed and only a single file/folder which corresponds to the URL 
		 * will be queried.
		 */
		NO_FOLLOW,

		/**
		 * All links will be followed to arrive at an end-point
		 */

		FOLLOW_EXTERNAL,
		/**
		 * Beyond the initial URL only internal links local to the corresponding project or 
		 * repository will be followed.
		 */
		FOLLOW_INTERNAL;
	}

	/**
	 * When recuring through link-files we must keep track of URLs considered and ensure
	 * we don't encounter a link cycle.
	 */
	private static final ThreadLocal<Set<URL>> linkedUrlSet = ThreadLocal.withInitial(() -> null);

	private final URL ghidraUrl;
	private final boolean readOnly;
	private final GhidraURLResultHandler resultHandler;
	private final LinkFileControl linkFileControl;

	private Class<? extends DomainObject> contentClass;

	private boolean cleanupUrlSetUponReturn = false;

	private GhidraURLQuery(URL ghidraUrl, Class<? extends DomainObject> contentClass,
			boolean readOnly, LinkFileControl linkFileControl,
			GhidraURLResultHandler resultHandler) {
		this.ghidraUrl = ghidraUrl;
		this.contentClass = contentClass;
		this.readOnly = readOnly;
		this.resultHandler = resultHandler;
		this.linkFileControl = linkFileControl;
	}

	/**
	 * Perform read-only query using specified GhidraURL and process result.
	 * Both local project and remote repository URLs are supported.
	 * This method is intended to be invoked from within a {@link Task} or for headless operations. 
	 * @param ghidraUrl local or remote Ghidra URL
	 * @param contentClass expected content class or null.  If a folder is expected 
	 * {@link NullFolderDomainObject} class should be specified.
	 * @param resultHandler query result handler
	 * @param linkFileControl controls how or if link files will be followed
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs which was re-thrown by {@code resultHandler}
	 * @throws CancelledException if task is cancelled
	 */
	public static void queryUrl(URL ghidraUrl, Class<? extends DomainObject> contentClass,
			GhidraURLResultHandler resultHandler, LinkFileControl linkFileControl,
			TaskMonitor monitor) throws IOException, CancelledException {
		GhidraURLQuery ghidraUrlQuery =
			new GhidraURLQuery(ghidraUrl, contentClass, true, linkFileControl, resultHandler);
		ghidraUrlQuery.query(monitor);
	}

	/**
	 * Perform query using specified GhidraURL and process result.
	 * Both local project and remote repository URLs are supported.
	 * This method is intended to be invoked from within a {@link Task} or for headless operations.
	 * @param ghidraUrl local or remote folder-level Ghidra URL
	 * @param readOnly allows update/commit (false) or read-only (true) access.
	 * @param resultHandler query result handler
	 * @param linkFileControl controls how or if link files will be followed
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs which was re-thrown by {@code resultHandler}
	 * @throws CancelledException if task is cancelled
	 */
	public static void queryRepositoryUrl(URL ghidraUrl, boolean readOnly,
			GhidraURLResultHandler resultHandler, LinkFileControl linkFileControl,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (!GhidraURL.isServerRepositoryURL(ghidraUrl)) {
			throw new IllegalArgumentException("Unsupported repository URL: " + ghidraUrl);
		}
		GhidraURLQuery ghidraUrlQuery = new GhidraURLQuery(ghidraUrl, NullFolderDomainObject.class,
			readOnly, linkFileControl, resultHandler);
		ghidraUrlQuery.query(monitor);
	}

	private void query(TaskMonitor monitor) throws IOException, CancelledException {

		try {
			doQuery(monitor);
		}
		finally {
			if (cleanupUrlSetUponReturn) {
				// cleanup thread local URL set
				linkedUrlSet.set(null);
			}
			cleanupUrlSetUponReturn = false;
		}
	}

	private void doQuery(TaskMonitor monitor) throws IOException, CancelledException {

		URL normalizedUrl = GhidraURL.getNormalizedURL(ghidraUrl);

		Set<URL> urls = linkedUrlSet.get();
		if (urls == null) {
			urls = new HashSet<>();
			linkedUrlSet.set(urls);
			cleanupUrlSetUponReturn = true;
		}
		if (!urls.add(normalizedUrl)) {
			throw new IOException("Circular link reference detected: " + ghidraUrl);
		}

		GhidraURLConnection c;
		Object obj = null;
		StatusCode status = null;
		try {
			c = (GhidraURLConnection) ghidraUrl.openConnection();
			c.setReadOnly(readOnly); // writable repository connection
			obj = c.getContent(); // read-only access
			status = c.getStatusCode();
		}
		catch (IOException e) {
			resultHandler.handleError("URL Connection Error", e.getMessage(), ghidraUrl, e);
		}

		GhidraURLWrappedContent wrappedContent = null;
		Object content = null;
		try {
			IOException generatedErr = null;
			switch (status) {
				case OK:
					break;

				case UNAUTHORIZED:
					resultHandler.handleUnauthorizedAccess(ghidraUrl);
					return;

				case NOT_FOUND:
					generatedErr = new IOException("Project or repository not found");
					break;

				case LOCKED:
					// Local projects are only accessed read-only, this condition should not occur
					throw new AssertionError("Unexpected local project lock condition");

				case UNAVAILABLE:
					generatedErr =
						new IOException("Server connection error occured (see log files)");
					break;

				default:
			}

			if (generatedErr != null) {
				resultHandler.handleError("Content Not Found", generatedErr.getMessage(), ghidraUrl,
					generatedErr);
				return;
			}

			if (!(obj instanceof GhidraURLWrappedContent)) {
				resultHandler.handleError("Unsupported Content",
					"URL does not correspond to a file or folder", null, null);
				return;
			}

			wrappedContent = (GhidraURLWrappedContent) obj;
			try {
				content = wrappedContent.getContent(resultHandler);
			}
			catch (IOException e) {
				resultHandler.handleError("Content Not Found", e.getMessage(), ghidraUrl, e);
				return;
			}

			// NOTE: We cannot handle ambiguous folder vs folder URL.  A folder-link
			// may refer to another folder-link or a folder.  If duplicate name exists
			// a failure may occur.  

			monitor.checkCancelled();
			processContent(content, monitor);
		}
		finally {
			if (content != null) {
				wrappedContent.release(content, resultHandler);
			}
			monitor.checkCancelled();
		}
	}

	private void processContent(Object content, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (content instanceof DomainFile file) {

			if (!checkContentClass(file)) {
				return;
			}

			if (linkFileControl != LinkFileControl.NO_FOLLOW && file.isLink()) {

				// Establish content class if not specified to pickup on link inconsistencies
				if (contentClass == null) {
					contentClass = file.getDomainObjectClass();
				}

				// Following link may return null on error or if external link already handled
				file = followLink(file, monitor);
				if (file == null) {
					return;
				}

				LinkFileInfo linkInfo = file.getLinkInfo();
				if (linkInfo != null && linkInfo.isFolderLink()) {
					// Handle folder link as folder
					DomainFolder folder = linkInfo.getLinkedFolder();
					if (folder == null) {
						resultHandler.handleError("Link Resolution Failed",
							"Unable to follow invalid folder-link", ghidraUrl, null);
					}
					else {
						resultHandler.processResult(folder, ghidraUrl, monitor);
					}
					return;
				}
			}

			// process file result
			resultHandler.processResult(file, ghidraUrl, monitor);
		}
		else if (content instanceof DomainFolder folder) {
			if (contentClass != null && contentClass != NullFolderDomainObject.class) {
				URL url = folder.getLocalProjectURL();
				if (url == null) {
					url = folder.getSharedProjectURL();
				}
				resultHandler.handleError("Unexpected Content", "Unexpected folder", url, null);
			}
			else {
				// process folder result
				resultHandler.processResult(folder, ghidraUrl, monitor);
			}
		}
		else {
			// unexpected condition
			resultHandler.handleError("Unsupported Content",
				"Content class: " + content.getClass().getName(), ghidraUrl, null);
		}
	}

	private boolean checkContentClass(DomainFile file) throws IOException {
		Class<? extends DomainObject> domainObjectClass = file.getDomainObjectClass();
		if (contentClass != null && !contentClass.isAssignableFrom(file.getDomainObjectClass())) {
			URL url = file.getLocalProjectURL(null);
			if (url == null) {
				url = file.getSharedProjectURL(null);
			}
			resultHandler.handleError("Unexpected Content",
				"File content is " + domainObjectClass.getSimpleName(), url, null);
			return false;
		}
		return true;
	}

	private DomainFile followLink(DomainFile file, TaskMonitor monitor)
			throws CancelledException, IOException {

		AtomicReference<LinkStatus> linkStatus = new AtomicReference<>();
		AtomicReference<String> errMsg = new AtomicReference<>();

		// Following internal linkage will catch circular internal linkage
		file =
			LinkHandler.followInternalLinkage(file, s -> linkStatus.set(s), err -> errMsg.set(err));

		LinkStatus s = linkStatus.get();
		if (s == LinkStatus.BROKEN) {
			String msg = errMsg.get();
			if (msg == null) {
				msg = "Unable to follow broken link";
			}
			resultHandler.handleError("Link Resolution Failed", msg, ghidraUrl, null);
			return null;
		}

		if (s == LinkStatus.EXTERNAL) {
			// file is expected to be an external link-file
			if (linkFileControl == LinkFileControl.FOLLOW_EXTERNAL) {
				URL linkURL = LinkHandler.getLinkURL(file);
				// continue recursion with external link
				queryUrl(linkURL, contentClass, resultHandler, linkFileControl, monitor);
				return null;
			}

			// cannot follow external link
			resultHandler.externalLinkIgnored(ghidraUrl);
			return null;
		}

		return file;
	}

}
