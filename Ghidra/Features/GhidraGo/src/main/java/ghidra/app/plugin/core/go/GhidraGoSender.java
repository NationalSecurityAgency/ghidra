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
package ghidra.app.plugin.core.go;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.core.go.exception.*;
import ghidra.app.plugin.core.go.ipc.*;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.util.Msg;
import ghidra.util.Swing;

public class GhidraGoSender extends GhidraGoIPC {

	public GhidraGoSender() throws IOException {
		super();
	}

	@Override
	public void dispose() {
		// empty
	}

	/**
	 * performs the given action once the sender lock has been acquired. Using this method ensures
	 * only one sender will perform the given action.
	 * @param waitForLock whether to block until the lock is available
	 * @param action the action to be performed once a lock is acquired. Returns true if successful.
	 * @return true if action was successfully performed; false otherwise.
	 * @throws UnableToGetLockException if the lock was unobtainable
	 */
	public boolean doLockedAction(boolean waitForLock, Supplier<Boolean> action)
			throws UnableToGetLockException {
		return GhidraGoIPC.doLockedAction(senderLockPath, waitForLock, action);
	}

	/**
	 * Send the url to an existing, listening Ghidra
	 * @param url a valid {@link GhidraURL} in string form for a remote Ghidra program. An error is 
	 * displayed if the url is null.
	 * @throws StopWaitingException in the event the stop waiting dialog is shown and answered No.
	 */
	public void send(String url) throws StopWaitingException {
		if (StringUtils.isEmpty(url)) {
			Swing.runNow(() -> Msg.showError(this, null, "GhidraGo Empty URL Error",
				"An empty GhidraURL cannot be sent."));
			return;
		}
		// create a random file and write the url in it
		String fileName = UUID.randomUUID().toString();
		Path randomFilePath = channelPath.resolve(fileName);
		Path writtenFilePath = urlFilesPath.resolve(fileName);

		try (FileOutputStream fos = new FileOutputStream(randomFilePath.toFile());) {
			fos.write(url.getBytes());
			// need to close the file so that it can be moved on window's host
			fos.close();
			Files.move(randomFilePath, writtenFilePath);
		}
		catch (IOException e) {
			randomFilePath.toFile().delete();
			Swing.runNow(() -> Msg.showError(this, null, "GhidraGo Error Sending URL",
				"There was a file system error preventing the url from being sent.", e));
		}

		Msg.info(this, "Wrote " + url + " to random file " + writtenFilePath);
		if (writtenFilePath.toFile().exists()) {
			waitForFileToBeProcessed(writtenFilePath);
		}

	}

	/**
	 * waits for the file located at the given file path to be deleted.
	 * @param filePath the path to the file to wait for deletion of
	 * @throws StopWaitingException in the event the stop waiting dialog is shown and answered No.
	 */
	private void waitForFileToBeProcessed(Path filePath) throws StopWaitingException {
		// check without dialogs every 100 milliseconds
		if (filePath.toFile().exists()) {

			// set up periodic check for file
			CheckForFileProcessedRunnable checkForFile =
				new CheckForFileProcessedRunnable(filePath, 100, TimeUnit.MILLISECONDS);

			// start checking for file
			checkForFile.startChecking(100, TimeUnit.MILLISECONDS);

			// block until file has been processed or user answers dialog with No.
			checkForFile.awaitTermination();
		}
	}

	/**
	 * wait for a Ghidra to be listening and ready.
	 * @throws StopWaitingException in the event waiting for a listener was stopped
	 */
	public void waitForListener() throws StopWaitingException {
		try {
			waitForListener(null);
		}
		catch (StartedGhidraProcessExitedException e) {
			// this will never happen when the process sent is null
		}
	}

	/**
	 * wait for a Ghidra to be listening and ready.
	 * @param p ghidraRun process that is being waited for in the event that GhidraGo
	 * started Ghidra
	 * @throws StopWaitingException in the event waiting for a listener was stopped
	 * @throws StartedGhidraProcessExitedException in the event a Ghidra was started and exited
	 * unexpectedly.
	 */
	public void waitForListener(Process p)
			throws StopWaitingException, StartedGhidraProcessExitedException {
		if (!isGhidraListening()) {
			// set up periodic check for listener
			CheckForListenerRunnable checkForListener = new CheckForListenerRunnable(p, 100,
				TimeUnit.MILLISECONDS,
				() -> !isGhidraListening());

			// start checking for listener
			checkForListener.startChecking(100, TimeUnit.MILLISECONDS);

			// block until listener has been processed or user answers dialog with No.
			checkForListener.awaitTermination();
		}
	}
}
