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
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GhidraURLResultHandlerAdapter} provides a basic result handler for 
 * {@link GhidraURLQuery}.  All uses of this adapter should override one or
 * both of the processing methods {@link #processResult(DomainFile, URL, TaskMonitor)}
 * and {@link #processResult(DomainFolder, URL, TaskMonitor)}.  For any process method
 * not overriden the default behavior is reporting <I>Unsupported Content</I>.
 */
public class GhidraURLResultHandlerAdapter implements GhidraURLResultHandler {

	private final boolean throwErrorByDefault;

	/**
	 * Construct adapter.  If {@link #handleError(String, String, URL, IOException)}
	 * is not overriden all errors are reported via 
	 * {@link Msg#showError(Object, java.awt.Component, String, Object)}.
	 */
	public GhidraURLResultHandlerAdapter() {
		throwErrorByDefault = false;
	}

	/**
	 * Construct adapter with preferred error handling.  There is no need to use this constructor
	 * if {@link #handleError(String, String, URL, IOException)} is override.
	 * @param throwErrorByDefault if true all errors will be thrown as an {@link IOException},
	 * otherwise error is reported via {@link Msg#showError(Object, java.awt.Component, String, Object)}.
	 */
	public GhidraURLResultHandlerAdapter(boolean throwErrorByDefault) {
		this.throwErrorByDefault = throwErrorByDefault;
	}

	@Override
	public void processResult(DomainFile domainFile, URL url, TaskMonitor monitor)
			throws IOException, CancelledException {
		handleError("Unsupported Content", "File URL: " + url, null, null);
	}

	@Override
	public void processResult(DomainFolder domainFolder, URL url, TaskMonitor monitor)
			throws IOException, CancelledException {
		handleError("Unsupported Content", "Folder URL: " + url, null, null);
	}

	@Override
	public void handleError(String title, String message, URL url, IOException cause)
			throws IOException {
		if (!throwErrorByDefault) {
			Msg.showError(GhidraURLQuery.class, null, title, message + ":\n" + url);
		}
		if (cause != null) {
			throw cause;
		}
		throw new IOException(title + ": " + message);
	}

}
