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

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GhidraURLQuery} performs remote Ghidra repository and read-only local project
 * queries for processing either a {@link DomainFile} or {@link DomainFolder} that a 
 * Ghidra URL may reference.
 */
public abstract class GhidraURLQuery {

	/**
	 * Perform read-only query using specified GhidraURL and process result.
	 * Both local project and remote repository URLs are supported.
	 * This method is intended to be invoked from within a {@link Task} or for headless operations. 
	 * @param ghidraUrl local or remote Ghidra URL
	 * @param resultHandler query result handler
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs which was re-thrown by {@code resultHandler}
	 * @throws CancelledException if task is cancelled
	 */
	public static void queryUrl(URL ghidraUrl, GhidraURLResultHandler resultHandler,
			TaskMonitor monitor) throws IOException, CancelledException {
		doQueryUrl(ghidraUrl, true, resultHandler, monitor);
	}

	/**
	 * Perform query using specified GhidraURL and process result.
	 * Both local project and remote repository URLs are supported.
	 * This method is intended to be invoked from within a {@link Task} or for headless operations. 
	 * @param ghidraUrl local or remote Ghidra URL
	 * @param readOnly allows update/commit (false) or read-only (true) access.
	 * @param resultHandler query result handler
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs which was re-thrown by {@code resultHandler}
	 * @throws CancelledException if task is cancelled
	 */
	public static void queryRepositoryUrl(URL ghidraUrl, boolean readOnly,
			GhidraURLResultHandler resultHandler, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (!GhidraURL.isServerRepositoryURL(ghidraUrl)) {
			throw new IllegalArgumentException("Unsupported repository URL: " + ghidraUrl);
		}
		doQueryUrl(ghidraUrl, readOnly, resultHandler, monitor);
	}

	private static void doQueryUrl(URL ghidraUrl, boolean readOnly,
			GhidraURLResultHandler resultHandler, TaskMonitor monitor)
			throws IOException, CancelledException {

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
				resultHandler.handleError("Content Not Found", e.getMessage(), null, e);
				return;
			}

			monitor.checkCancelled();
			if (content instanceof DomainFile file) {
				resultHandler.processResult(file, ghidraUrl, monitor);
			}
			else if (content instanceof DomainFolder folder) {
				resultHandler.processResult(folder, ghidraUrl, monitor);
			}
			else {
				// unexpected condition
				resultHandler.handleError("Unsupported Content",
					"Content class: " + content.getClass().getName(), ghidraUrl, null);
			}
		}
		finally {
			if (content != null) {
				wrappedContent.release(content, resultHandler);
			}
			monitor.checkCancelled();
		}
	}

}
