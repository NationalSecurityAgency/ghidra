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

import generic.timer.GhidraSwinglessTimer;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.data.ProjectFileManager;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.remote.RepositoryHandle;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

public class TransientProjectData extends ProjectFileManager {

	private TransientProjectManager dataMgr;
	final RepositoryInfo repositoryInfo;
	private int instanceUseCount = 0;
	private boolean readyForCleanup = false;
	private boolean timerInitiatedDisposal = false;
	private boolean disposed = false;

	private GhidraSwinglessTimer cleanupTimer;

	TransientProjectData(TransientProjectManager dataMgr, ProjectLocator tmpProjectLocation,
			RepositoryInfo repositoryInfo, RepositoryAdapter repository) throws IOException {
		// Resulting data is read-only in GUI mode, read-write in Headless mode
		// Allowing more control will cause issues for caching of transient project data -
		// although we could use two caches one for each mode
		super(tmpProjectLocation, repository, !repositoryInfo.readOnly);
		this.dataMgr = dataMgr;
		this.repositoryInfo = repositoryInfo;

		cleanupTimer =
			new GhidraSwinglessTimer(RepositoryHandle.CLIENT_CHECK_PERIOD, () -> cleanup());
		cleanupTimer.start();

		Msg.debug(this, "Created transient project (" + repositoryInfo.toShortString() + "): " +
			tmpProjectLocation.getProjectDir());
	}

	private void cleanup() {
		synchronized (cleanupTimer) {
			if (!isValid() || !cleanupTimer.isRunning()) {
				return; // already disposed or timer suspended
			}
			RepositoryAdapter repository = getRepository();
			int handleCount = repository.getOpenFileHandleCount();
			if (instanceUseCount != 0 || handleCount != 0) {
				// project data is in-use
				readyForCleanup = false;
				if (SystemUtilities.isInTestingMode()) {
					Msg.debug(this,
						"Transient project cleanup (" + repositoryInfo.toShortString() +
							"): Not ready: use-count=" + instanceUseCount + " open-handles=" +
							handleCount);
				}
			}
			else if (!readyForCleanup) {
				// project not in-use
				// it takes two idle firings to know we are ready
				readyForCleanup = true;
				if (SystemUtilities.isInTestingMode()) {
					Msg.debug(this, "Transient project cleanup (" + repositoryInfo.toShortString() +
						"): Ready");
				}
			}
			else {
				// project not in-use - do cleanup
				if (SystemUtilities.isInTestingMode()) {
					Msg.debug(this, "Transient project cleanup (" + repositoryInfo.toShortString() +
						"): Dispose");
				}
				timerInitiatedDisposal = true;
				stopCleanupTimer();
			}
		}
		if (timerInitiatedDisposal) {
			forcedDispose();
		}
	}

	boolean isValid() {
		synchronized (cleanupTimer) {
			return !disposed && !timerInitiatedDisposal;
		}
	}

	/**
	 * @return true if timer was running and has been stopped
	 */
	boolean stopCleanupTimer() {
		synchronized (cleanupTimer) {
			if (!isValid()) {
				return false;
			}
			readyForCleanup = false;
			cleanupTimer.stop();
			return true;
		}
	}

	void startCleanupTimer() {
		synchronized (cleanupTimer) {
			readyForCleanup = false;
			cleanupTimer.start();
		}
	}

	public void incrementInstanceUseCount() throws IOException {
		synchronized (cleanupTimer) {
			if (disposed) {
				throw new IOException("Remote transient project has been disposed");
			}
			readyForCleanup = false;
			cleanupTimer.stop();
			++instanceUseCount;
			Msg.debug(this, "Increased instance count (" + repositoryInfo.toShortString() + "): " +
				instanceUseCount);
			cleanupTimer.start();
		}
	}

	void forcedDispose() {

		synchronized (cleanupTimer) {
			if (disposed) {
				return;
			}
			stopCleanupTimer();
			disposed = true;
		}

		Msg.debug(this, "Removing transient project (" + repositoryInfo.toShortString() + "): " +
			getProjectLocator().getProjectDir());

		dataMgr.cleanupProjectData(repositoryInfo, this);

		super.dispose(); // disconnects repository

		// TODO: There could still be open files if they have not been properly released/closed !!
		ProjectLocator locator = getProjectLocator();
		FileUtilities.deleteDir(locator.getProjectDir());
		locator.getMarkerFile().delete();
	}

	@Override
	public void dispose() {
		// prevent normal disposal - rely on finalizer and shutdown hook
		synchronized (cleanupTimer) {
			if (instanceUseCount == 0) {
				Msg.error(this, "Transient project (" + repositoryInfo.toShortString() +
					") use count has gone negative");
			}
			else {
				--instanceUseCount;
				Msg.debug(this, "Reduced instance count on dispose (" +
					repositoryInfo.toShortString() + "): " + instanceUseCount);
			}
		}
	}

	@Override
	protected void finalize() throws Throwable {
		try {
			forcedDispose();
		}
		catch (Throwable t) {
			// ignore errors during finalize
		}
		super.finalize();
	}
}
