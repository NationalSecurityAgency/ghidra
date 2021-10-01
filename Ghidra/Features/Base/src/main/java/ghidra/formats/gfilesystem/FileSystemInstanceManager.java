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
package ghidra.formats.gfilesystem;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import ghidra.util.Msg;

/**
 * A threadsafe cache of {@link GFileSystem} instances (organized by their {@link FSRLRoot})
 * <p>
 * Any filesystems that are not referenced by outside users (via a {@link FileSystemRef}) will
 * be closed and removed from the cache when the next {@link #cacheMaint()} is performed.
 */
class FileSystemInstanceManager implements FileSystemEventListener {
	private static class FSCacheInfo {
		FileSystemRef ref;

		FSCacheInfo(GFileSystem fs) {
			ref = fs.getRefManager().create();
		}
	}

	private static final int filesystemPurgeDelayMS = 60 * 1000;// 60 seconds
	private Map<FSRLRoot, FSCacheInfo> filesystems = new HashMap<>();
	private GFileSystem rootFS;
	private FSRLRoot rootFSRL;

	/**
	 * Creates a new FileSystemCache object.
	 *
	 * @param rootFS reference to the global root file system, which is a special case
	 * file system that is not subject to eviction.
	 */
	public FileSystemInstanceManager(GFileSystem rootFS) {
		this.rootFS = rootFS;
		this.rootFSRL = rootFS.getFSRL();
	}

	/**
	 * Forcefully closes any filesystems in the cache, then clears the list of
	 * cached filesystems.
	 */
	public synchronized void clear() {
		for (Entry<FSRLRoot, FSCacheInfo> entry : filesystems.entrySet()) {
			try {
				FSCacheInfo fci = entry.getValue();
				FileSystemRef ref = fci.ref;
				GFileSystem fs = ref.getFilesystem();
				if (!ref.getFilesystem().getRefManager().canClose(ref)) {
					Msg.warn(this, "Forcing filesystem closed: " + fs);
				}
				fs.close();
			}
			catch (IOException e) {
				Msg.warn(this, "Error closing filesystem: " + e);
			}
		}
		filesystems.clear();
	}

	/**
	 * Removes any unused filesystems in the cache.
	 */
	public synchronized void closeAllUnused() {
		List<FSCacheInfo> recsToPurge = getUnusedFSes();
		if (!recsToPurge.isEmpty()) {
			Msg.info(this, "Removing " + recsToPurge.size() + " unused filesystems from cache");
		}
		for (FSCacheInfo fsci : recsToPurge) {
			release(fsci);
		}
	}

	/**
	 * Returns a list of mounted file systems.
	 * <p>
	 * @return {@link List} of {@link FSRLRoot} of filesystems that are currently mounted.
	 */
	public synchronized List<FSRLRoot> getMountedFilesystems() {
		return new ArrayList<>(filesystems.keySet());
	}

	/**
	 * Adds a new {@link GFileSystem} to the cache.
	 *
	 * @param fs {@link GFileSystem} to add to this cache.
	 */
	public synchronized void add(GFileSystem fs) {
		FSCacheInfo fsci = new FSCacheInfo(fs);
		fs.getRefManager().addListener(this);
		if (filesystems.put(fs.getFSRL(), fsci) != null) {
			Msg.warn(this, "Added second instance of same filesystem!  " + fs.getFSRL());
		}
	}

	/**
	 * Returns a new {@link FileSystemRef} to an existing, already open {@link GFileSystem filesystem}.
	 * Caller is responsible for {@link FileSystemRef#close() closing} it.
	 * <p>
	 * Returns NULL if the requested filesystem isn't already open and mounted in the cache.
	 *
	 * @param fsrl {@link FSRLRoot} of the desired filesystem.
	 * @return a new {@link FileSystemRef} or null if the filesystem is not currently mounted.
	 */
	public synchronized FileSystemRef getRef(FSRLRoot fsrl) {
		if (rootFSRL.equals(fsrl)) {
			return rootFS.getRefManager().create();
		}
		FSCacheInfo fsci = filesystems.get(fsrl);
		if (fsci != null) {
			return fsci.ref.dup();
		}
		// If the query FSRL doesn't have a MD5, do a slow scan 
		// for filesystems that match by equiv.
		if (fsrl.getMD5() == null) {
			for (Entry<FSRLRoot, FSCacheInfo> entry : filesystems.entrySet()) {
				if (entry.getKey().isEquivalent(fsrl)) {
					return entry.getValue().ref.dup();
				}
			}
		}
		return null;
	}

	/**
	 * Returns true if there is a filesystem in the cache that has a containerFSRL that
	 * is {@link FSRL#isEquivalent(FSRL) equiv} to the specified FSRL.
	 * <p>
	 *
	 * @param containerFSRL {@link FSRL} location to query for currently mounted filesystem.
	 * @return true if there is a filesystem mounted using that containerFSRL.
	 */
	public synchronized boolean isFilesystemMountedAt(FSRL containerFSRL) {
		for (Entry<FSRLRoot, FSCacheInfo> entry : filesystems.entrySet()) {
			FSRLRoot fsFSRL = entry.getKey();
			FSRL fsContainer = fsFSRL.getContainer();

			FileSystemRef ref = entry.getValue().ref;
			GFileSystem fs = ref.getFilesystem();
			if (fs == null || fsContainer == null) {
				continue;
			}

			if (fsContainer.isEquivalent(containerFSRL)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a new {@link FileSystemRef} to a already mounted {@link GFileSystem filesystem}
	 * (keeping the filesystem pinned in memory without the risk of it being closed during
	 * a race condition).
	 * <p>
	 * The caller is responsible for {@link FileSystemRef#close() closing} it when done.
	 * <p>
	 * Returns null if there is no filesystem mounted at the requested container fsrl.
	 *
	 * @param containerFSRL {@link FSRL} location where a filesystem is already mounted
	 * @return new {@link FileSystemRef} to the already mounted filesystem, or null
	 */
	public synchronized FileSystemRef getFilesystemRefMountedAt(FSRL containerFSRL) {

		// Iterate the entire set of mounted filesystems searching for a match
		// (because there is no index of container-to-filesystems)
		for (Entry<FSRLRoot, FSCacheInfo> entry : filesystems.entrySet()) {
			FSRLRoot fsFSRL = entry.getKey();
			FSRL fsContainer = fsFSRL.getContainer();

			FileSystemRef ref = entry.getValue().ref;
			GFileSystem fs = ref.getFilesystem();
			if (fs == null || fsContainer == null) {
				continue;
			}

			if (containerFSRL.isEquivalent(fsContainer)) {
				return ref.dup();
			}
		}
		return null;
	}

	@Override
	public synchronized void onFilesystemClose(GFileSystem fs) {
		FSRLRoot fsFSRL = fs.getFSRL();
		filesystems.remove(fsFSRL);
		Msg.warn(this, "Filesystem " + fs.getFSRL() + " was closed outside of cache");
	}

	@Override
	public synchronized void onFilesystemRefChange(GFileSystem fs,
			FileSystemRefManager refManager) {
		//Msg.info(this, "Filesystem " + fs.getFSRL() + " ref changed");
		// TODO: could move unused filesystems to their own waiting-to-be-purged list
		// if its too much work to walk the entire list of current filesystems.
	}

	/**
	 * Performs maintainence on the filesystem cache, closing() any filesystems
	 * that are not used anymore.
	 */
	public synchronized void cacheMaint() {
		//Msg.info(this, "Performing filesystem cache maint");
		List<FSCacheInfo> recsToPurge = getExpired(getUnusedFSes());
		if (!recsToPurge.isEmpty()) {
			Msg.info(this, "Evicting " + recsToPurge.size() + " filesystems from cache");
		}
		for (FSCacheInfo fsci : recsToPurge) {
			release(fsci);
		}
	}

	private List<FSCacheInfo> getExpired(List<FSCacheInfo> recs) {
		long lastUsedCutoffMS = System.currentTimeMillis() - filesystemPurgeDelayMS;
		List<FSCacheInfo> results = new ArrayList<>();
		for (FSCacheInfo fsci : recs) {
			FileSystemRefManager refManager = fsci.ref.getFilesystem().getRefManager();
			long lastUsedTS = refManager.getLastUsedTimestamp();
			if (lastUsedTS < lastUsedCutoffMS) {
				results.add(fsci);
			}
		}
		return results;
	}

	private List<FSCacheInfo> getUnusedFSes() {
		List<FSCacheInfo> results = new ArrayList<>();
		for (Entry<FSRLRoot, FSCacheInfo> entry : filesystems.entrySet()) {
			FSCacheInfo fsci = entry.getValue();
			FileSystemRefManager refManager = fsci.ref.getFilesystem().getRefManager();
			if (refManager.canClose(fsci.ref)) {
				results.add(fsci);
			}
		}
		return results;
	}

	private void release(FSCacheInfo fsci) {
		try {
			GFileSystem fs = fsci.ref.getFilesystem();
			FSRLRoot fsFSRL = fs.getFSRL();

			filesystems.remove(fsFSRL);
			fs.getRefManager().removeListener(this);
			fsci.ref.close();
			fs.close();
			Msg.debug(this, "Closing unused filesystem [" + fsFSRL.getContainer() + "]");
		}
		catch (IOException e) {
			Msg.error(this, "Error closing filesystem", e);
		}
	}

	/**
	 * Closes the specified ref, and if no other refs to the file system remain, closes the file system.
	 *  
	 * @param ref {@link FileSystemRef} to close
	 */
	public synchronized void releaseImmediate(FileSystemRef ref) {
		FSCacheInfo fsci = filesystems.get(ref.getFilesystem().getFSRL());
		ref.close();
		if (fsci == null) {
			Msg.warn(this, "Unknown file system reference: " + ref.getFilesystem().getFSRL());
			return;
		}
		FileSystemRefManager refManager = fsci.ref.getFilesystem().getRefManager();
		if (refManager.canClose(fsci.ref)) {
			release(fsci);
		}

	}
}
