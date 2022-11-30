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

import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;

import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * A blocking/modal Ghidra URL content type discovery task
 */
public class GetUrlContentTypeTask extends Task {

	private final URL ghidraUrl;

	private String contentType;
	private boolean done = false;

	/**
	 * Construct a Ghidra URL content type discovery task
	 * @param ghidraUrl Ghidra URL (local or remote)
	 * @throws IllegalArgumentException if specified URL is not a Ghidra URL
	 * (see {@link GhidraURL}).
	 */
	public GetUrlContentTypeTask(URL ghidraUrl) {
		super("Checking URL Content Type", true, false, true);
		if (!GhidraURL.isLocalProjectURL(ghidraUrl) &&
			!GhidraURL.isServerRepositoryURL(ghidraUrl)) {
			throw new IllegalArgumentException("unsupported URL");
		}
		this.ghidraUrl = ghidraUrl;
	}

	/**
	 * Get the discovered content type (e.g., "Program")
	 * @return content type or null if error occured or unsupported URL content
	 * @throws IllegalStateException if task has not completed execution
	 */
	public String getContentType() {
		if (!done) {
			throw new IllegalStateException("task has not completed");
		}
		return contentType;
	}

	@Override
	public void run(TaskMonitor monitor) {
		final Thread t = Thread.currentThread();
		monitor.addCancelledListener(() -> {
			t.interrupt();
		});
		GhidraURLWrappedContent wrappedContent = null;
		Object content = null;
		try {
			GhidraURLConnection c = (GhidraURLConnection) ghidraUrl.openConnection();
			Object obj = c.getContent(); // read-only access
			if (c.getStatusCode() == StatusCode.UNAUTHORIZED) {
				return; // assume user already notified
			}
			if (obj instanceof GhidraURLWrappedContent) {
				wrappedContent = (GhidraURLWrappedContent) obj;
				content = wrappedContent.getContent(this);
			}
			if (!(content instanceof DomainFile)) {
				Msg.showError(this, null, "Unsupported Content",
					"Invalid project file URL: " + ghidraUrl);
				return;
			}
			contentType = ((DomainFile) content).getContentType();
		}
		catch (FileNotFoundException e) {
			Msg.showError(this, null, "Content Not Found", e.getMessage());
		}
		catch (MalformedURLException e) {
			Msg.showError(this, null, "Invalid Ghidra URL",
				"Improperly formed Ghidra URL: " + ghidraUrl);
		}
		catch (InterruptedIOException e) {
			// ignore - assume cancelled
		}
		catch (IOException e) {
			Msg.showError(this, null, "URL Access Failure",
				"Failed to open Ghidra URL: " + e.getMessage());
		}
		finally {
			if (content != null) {
				wrappedContent.release(content, this);
			}
			done = true;
		}
	}


}
