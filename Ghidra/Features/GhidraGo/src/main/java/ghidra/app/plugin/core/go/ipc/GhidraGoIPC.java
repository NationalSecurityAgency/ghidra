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
package ghidra.app.plugin.core.go.ipc;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.*;
import java.nio.file.Path;
import java.util.function.Supplier;

import ghidra.app.plugin.core.go.exception.UnableToGetLockException;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.Swing;
import utilities.util.FileUtilities;

/**
 * Ghidra Go Inter-Process Communication
 */
public abstract class GhidraGoIPC {

	protected final Path channelPath =
		Path.of(Application.getUserTempDirectory().getPath(), "ghidraGo");
	protected final Path urlFilesPath = channelPath.resolve("urls");

	protected final Path listenerLockPath = channelPath.resolve("listenerLock");
	protected final Path listenerReadyLockPath = channelPath.resolve("listenerReadyLock");
	protected final Path senderLockPath = channelPath.resolve("senderLock");

	protected GhidraGoIPC() throws IOException {
		// make the directories that will be needed
		try {
			FileUtilities.checkedMkdir(channelPath.toFile());
			FileUtilities.checkedMkdir(urlFilesPath.toFile());
		}
		catch (IOException e) {
			Msg.error(this, "Unable to create IPC directories.");
			throw e;
		}
	}

	public abstract void dispose();

	/**
	 * @return true if a Ghidra is listening and ready. false otherwise
	 */
	public boolean isGhidraListening() {
		if (listenerLockPath.toFile().exists() && listenerReadyLockPath.toFile().exists()) {
			return isFileLocked(listenerLockPath) && isFileLocked(listenerReadyLockPath);
		}
		return false;
	}

	private boolean isFileLocked(Path lockPath) {
		try {
			return !doLockedAction(lockPath, false, () -> true);
		}
		catch (OverlappingFileLockException | UnableToGetLockException e) {
			return true;
		}
	}

	/**
	 * perform the given action after acquiring the client lock successfully. This method is used
	 * to ensure that only one actor for the given lock path is performing the action.
	 * @param lockPath the path of the file to lock
	 * @param action the action taken after acquiring the lock.
	 * @param waitForLock if true blocks until the lock is acquired. otherwise, if the lock can't be 
	 * acquired, the method returns false and does not do any blocking actions
	 * @return true if the action succeeded. false otherwise.
	 * @throws OverlappingFileLockException if another process currently controls the lock
	 * @throws UnableToGetLockException if the lock was unobtainable
	 */
	public static boolean doLockedAction(Path lockPath, boolean waitForLock,
			Supplier<Boolean> action)
			throws OverlappingFileLockException, UnableToGetLockException {
		try (FileOutputStream fos = new FileOutputStream(lockPath.toFile());
				FileChannel channel = fos.getChannel();
				FileLock lock = waitForLock ? channel.lock() : channel.tryLock();) {
			if (lock == null) {
				throw new UnableToGetLockException();
			}
			return action.get();
		}
		catch (FileLockInterruptionException e) {
			// this is okay, user interrupted locking action
		}
		catch (IOException e) {
			Swing.runNow(
				() -> Msg.showError(GhidraGoIPC.class, null, "Could not perform exclusive action",
					"Another process is currently holding the lock at " + lockPath, e));
		}
		return false;
	}

}
