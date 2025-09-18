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
import java.io.InterruptedIOException;
import java.net.URL;

import ghidra.framework.data.NullFolderDomainObject;
import ghidra.framework.model.*;
import ghidra.framework.protocol.ghidra.GhidraURLQuery.LinkFileControl;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * {@link GhidraURLQueryTask} provides an abstract Task which performs remote Ghidra 
 * repository and read-only local project queries for processing either a {@link DomainFile} 
 * or {@link DomainFolder} that a Ghidra URL may reference.
 * <P>
 * All implementations of this Task should override one or
 * both of the processing methods {@link #processResult(DomainFile, URL, TaskMonitor)}
 * and {@link #processResult(DomainFolder, URL, TaskMonitor)}.  For any process method
 * not overriden the default behavior is reporting <I>Unsupported Content</I>.
 * <P>
 * If {@link #handleError(String, String, URL, IOException)}
 * is not overriden all errors are reported via 
 * {@link Msg#showError(Object, java.awt.Component, String, Object)}.
 */
public abstract class GhidraURLQueryTask extends Task implements GhidraURLResultHandler {

	private final URL ghidraUrl;
	private final Class<? extends DomainObject> contentClass;
	private final LinkFileControl linkFileControl;

	private boolean done = false;

	/**
	 * Construct a Ghidra URL read-only query task.
	 * @param title task dialog title
	 * @param ghidraUrl Ghidra URL (local or remote)
	 * @param contentClass expected content class or null.  If a folder is expected 
	 * {@link NullFolderDomainObject} class should be specified.
	 * @param linkFileControl controls how or if link files will be followed 
	 * @throws IllegalArgumentException if specified URL is not a Ghidra URL
	 * (see {@link GhidraURL}).
	 */
	protected GhidraURLQueryTask(String title, URL ghidraUrl,
			Class<? extends DomainObject> contentClass, LinkFileControl linkFileControl) {
		super(title, true, false, true);
		if (!GhidraURL.isLocalProjectURL(ghidraUrl) &&
			!GhidraURL.isServerRepositoryURL(ghidraUrl)) {
			throw new IllegalArgumentException("Unsupported URL: " + ghidraUrl);
		}
		this.ghidraUrl = ghidraUrl;
		this.contentClass = contentClass;
		this.linkFileControl = linkFileControl;
	}

	/**
	 * Determine if the task has completed its execution
	 * @return true if done executing else false
	 */
	protected boolean isDone() {
		return done;
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {

		final Thread t = Thread.currentThread();
		CancelledListener cancelledListener = () -> t.interrupt();
		monitor.addCancelledListener(cancelledListener);

		try {
			GhidraURLQuery.queryUrl(ghidraUrl, contentClass, this, linkFileControl, monitor);
		}
		catch (InterruptedIOException e) {
			// ignore - assume cancelled
		}
		catch (IOException e) {
			handleError("URL Access Failure", e.getMessage(), ghidraUrl, e);
		}
		finally {
			monitor.removeCancelledListener(cancelledListener);
			monitor.checkCancelled();
			done = true;
		}
	}

	@Override
	public void handleError(String title, String message, URL url, IOException cause) {
		Msg.showError(GhidraURLQuery.class, null, title, message + ":\n" + url);
	}

	@Override
	public void processResult(DomainFile domainFile, URL url, TaskMonitor monitor)
			throws IOException {
		handleError("Unsupported Content", "File URL: " + url, null, null);
	}

	@Override
	public void processResult(DomainFolder domainFolder, URL url, TaskMonitor monitor)
			throws IOException {
		handleError("Unsupported Content", "Folder URL: " + url, null, null);
	}
}
