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

import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import ghidra.framework.Application;
import ghidra.framework.client.NotConnectedException;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.protocol.ghidra.GhidraURLConnection.StatusCode;
import ghidra.framework.store.LockException;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakValueHashMap;

public class TransientProjectManager {

	// TODO: not sure how safe it is to keep lots of connections open ??
	// We could close a connection if not used within a certain amount of time.
	// Callback responses could be cached and reused during a reconnect.
	// In normal use this could result in stale folder data.  We could disable the
	// time-based disconnect for the primary project or if a remote file is open.
	// There is already an existing problem when a client goes to sleep and the
	// server forces a disconnect due to non-responsiveness.  We should allow
	// for an auto-reconnect using the cached callback responses.

	/**
	 * Map of existing transient project data.  Weak value references
	 * are used to allow project data to be finalized and disposed
	 * automatically when all references are dropped.
	 */
	private Map<RepositoryInfo, TransientProjectData> repositoryMap = new WeakValueHashMap<>();

	private static TransientProjectManager transientProjectManager = null;

	/**
	 * Get the <code>TransientProjectManager</code> singleton instance for the JVM
	 * @return <code>TransientProjectManager</code> singleton instance
	 */
	public static synchronized TransientProjectManager getTransientProjectManager() {
		if (transientProjectManager == null) {
			transientProjectManager = new TransientProjectManager();
		}
		return transientProjectManager;
	}

	/**
	 * Get the number of active transient project data instances
	 * @return number of active transient project data instances
	 */
	public synchronized int getActiveProjectCount() {
		return repositoryMap.size();
	}

	private TransientProjectManager() {
		Runtime.getRuntime()
				.addShutdownHook(new Thread((Runnable) () -> dispose(),
					"TransientProjectManager Shutdown Hook"));
	}

	/**
	 * Force disposal of all transient projects associated with remote Ghidra URL
	 * connections. WARNING: This method intended for testing only.
	 */
	public synchronized void dispose() {
		TransientProjectData[] projectDataArray =
			repositoryMap.values().toArray(new TransientProjectData[repositoryMap.size()]);
		for (TransientProjectData projectData : projectDataArray) {
			projectData.forcedDispose();
		}
		repositoryMap.clear();
	}

	/**
	 * Get the transient project associated with a specific Ghidra protocol 
	 * connector.  This method will establish a connection if needed.
	 * @param protocolConnector Ghidra protocol connector
	 * @param readOnly true if project data should be treated as read-only
	 * @return transient project data
	 * @throws IOException if an IO error occurs
	 */
	synchronized TransientProjectData getTransientProject(GhidraProtocolConnector protocolConnector,
			boolean readOnly) throws IOException {

		String repoName = protocolConnector.getRepositoryName();
		if (repoName == null) {
			throw new IllegalArgumentException(
				"specified protocol connector does not correspond to a repository");
		}

		RepositoryInfo repositoryInfo =
			new RepositoryInfo(protocolConnector.getRepositoryRootGhidraURL(), repoName, readOnly);

		TransientProjectData projectData = repositoryMap.get(repositoryInfo);

		if (projectData == null || !projectData.stopCleanupTimer()) { // cleanup suspended

			StatusCode statusCode = protocolConnector.connect(readOnly);
			if (statusCode != StatusCode.OK) {
				throw new NotConnectedException(statusCode.getDescription());
			}

			RepositoryAdapter repositoryAdapter = protocolConnector.getRepositoryAdapter();
			if (repositoryAdapter == null || !repositoryAdapter.isConnected()) {
				throw new NotConnectedException("Not connected to repository");
			}

			projectData = createTransientProject(repositoryAdapter, repositoryInfo);
			if (projectData != null) {
				repositoryMap.put(repositoryInfo, projectData);
			}
		}
		else {

			Msg.debug(this, "Reusing existing TransientProjectData: " + projectData.repositoryInfo);

			try {
				RepositoryAdapter repository = projectData.getRepository();
				repository.connect();
				protocolConnector.connect(repository);
			}
			finally {
				projectData.startCleanupTimer(); // resume cleanup timer
			}

		}

		Msg.debug(this, "Number of active TransientProjectData instances: " + repositoryMap.size());

		return projectData;
	}

	/**
	 * Remove a transient project data from this manager's instance map
	 * @param repositoryInfo repository info for tracking transient project data
	 * @param projectData transient project data
	 */
	synchronized void cleanupProjectData(RepositoryInfo repositoryInfo,
			TransientProjectData projectData) {
		if (repositoryMap.get(repositoryInfo) != projectData) {
			return;
		}
		repositoryMap.remove(repositoryInfo);
		if (SystemUtilities.isInTestingMode()) {
			Msg.debug(this,
				"Number of active TransientProjectData instances: " + repositoryMap.size());
			Set<Entry<RepositoryInfo, TransientProjectData>> entrySet = repositoryMap.entrySet();
			for (Entry<RepositoryInfo, TransientProjectData> entry : entrySet) {
				Msg.debug(this, "  " + entry.getKey() + " -> " + entry.getValue());
			}
		}
	}

	private TransientProjectData createTransientProject(RepositoryAdapter repository,
			RepositoryInfo repositoryInfo) throws IOException {

		File tmp = Application.createTempFile("ghidraPrj", "");
		tmp.delete();

		ProjectLocator tmpProjectLocation = new TransientProjectStorageLocator(
			tmp.getParentFile().getAbsolutePath(), tmp.getName(), repositoryInfo);

		try {
			return new TransientProjectData(this, tmpProjectLocation, repositoryInfo, repository);
		}
		catch (LockException e) {
			throw new IOException(e); // unexpected for transient project storage
		}
	}

	private static class TransientProjectStorageLocator extends ProjectLocator {

		private final RepositoryInfo repositoryInfo;

		TransientProjectStorageLocator(String path, String name, RepositoryInfo repositoryInfo) {
			super(path, name, repositoryInfo.repositoryURL);
			this.repositoryInfo = repositoryInfo;
		}

		@Override
		public String getName() {
			return repositoryInfo.repositoryURL.toExternalForm();
		}

		@Override
		public boolean isTransient() {
			return true;
		}

		@Override
		public String toString() {
			return repositoryInfo.repositoryURL.toExternalForm();
		}
	}

}
