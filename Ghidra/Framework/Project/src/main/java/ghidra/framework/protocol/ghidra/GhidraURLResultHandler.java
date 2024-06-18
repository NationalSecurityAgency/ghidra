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
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface GhidraURLResultHandler {

	/**
	 * Process the specified {@code domainFile} query result. 
	 * Dissemination of the {@code domainFile} instance should be restricted and any use of it 
	 * completed before the call to this method returns.  Upon return from this method call the 
	 * underlying connection will be closed and at which time the {@code domainFile} instance 
	 * will become invalid.
	 * @param domainFile {@link DomainFile} to which the URL refers.
	 * @param url URL which was used to retrieve the specified {@code domainFile}
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if task is cancelled
	 */
	void processResult(DomainFile domainFile, URL url, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Process the specified {@code domainFolder} query result.
	 * Dissemination of the {@code domainFolder} instance should be restricted and any use of it 
	 * completed before the call to this method returns.  Upon return from this method call the 
	 * underlying connection will be closed and at which time the {@code domainFolder} instance 
	 * will become invalid.
	 * @param domainFolder {@link DomainFolder} to which the URL refers.
	 * @param url URL which was used to retrieve the specified {@code domainFolder}
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs
	 * @throws CancelledException if task is cancelled
	 */
	void processResult(DomainFolder domainFolder, URL url, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Handle error which occurs during query operation.
	 * @param title error title
	 * @param message error detail
	 * @param url URL which was used for query
	 * @param cause cause of error (may be null)
	 * @throws IOException may be thrown if handler decides to propogate error
	 */
	void handleError(String title, String message, URL url, IOException cause) throws IOException;

	/**
	 * Handle authorization error. 
	 * This condition is generally logged and user notified via GUI during connection processing.
	 * This method does not do anything by default but is provided to flag failure if needed since
	 * {@link #handleError(String, String, URL, IOException)} will not be invoked.
	 * @param url connection URL
	 * @throws IOException may be thrown if handler decides to propogate error
	 */
	default void handleUnauthorizedAccess(URL url) throws IOException {
		// do nothing - assume user has already been notified or issue has been logged
	}
}
