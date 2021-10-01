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

import java.util.ArrayList;
import java.util.List;

import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * A threadsafe helper class that manages creating and releasing {@link FileSystemRef} instances
 * and broadcasting events to {@link FileSystemEventListener} listeners.
 * <p>
 */
public class FileSystemRefManager {
	private GFileSystem fs;
	private List<FileSystemRef> refs = new ArrayList<>();
	private WeakSet<FileSystemEventListener> listeners =
		WeakDataStructureFactory.createCopyOnReadWeakSet();
	private long lastUsedTS;

	/**
	 * Creates a new {@link FileSystemRefManager} pointing at the specified {@link GFileSystem}.
	 *
	 * @param fs {@link GFileSystem} to manage.
	 */
	public FileSystemRefManager(GFileSystem fs) {
		this.fs = fs;
		touch();
	}

	private void touch() {
		lastUsedTS = System.currentTimeMillis();
	}

	/**
	 * Adds a {@link FileSystemEventListener listener} that will be called when
	 * this filesystem is {@link FileSystemEventListener#onFilesystemClose(GFileSystem) closed}
	 * or when {@link FileSystemEventListener#onFilesystemRefChange(GFileSystem, FileSystemRefManager) refs change}.
	 *
	 * @param listener {@link FileSystemEventListener} to receive callbacks, weakly refd and
	 * automagically removed if a reference isn't held to the listener somewhere else.
	 */
	public void addListener(FileSystemEventListener listener) {
		listeners.add(listener);
	}

	/**
	 * Removes a previously added {@link FileSystemEventListener listener}.
	 *
	 * @param listener {@link FileSystemEventListener} to remove.
	 */
	public void removeListener(FileSystemEventListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Creates a new {@link FileSystemRef} that points at the owning {@link GFileSystem filesystem}.
	 * <p>
	 *
	 * @return new {@link FileSystemRef} pointing at the filesystem, never null.
	 */
	public FileSystemRef create() {

		FileSystemRef ref = null;
		synchronized (this) {
			if (fs.isClosed()) {
				throw new IllegalArgumentException("File system already closed: " + fs);
			}

			ref = new FileSystemRef(fs);
			refs.add(ref);
			touch();
		}
		for (FileSystemEventListener listener : listeners) {
			listener.onFilesystemRefChange(fs, this);
		}

		return ref;
	}

	/**
	 * Releases an existing {@link FileSystemRef} and broadcasts
	 * {@link FileSystemEventListener#onFilesystemRefChange(GFileSystem, FileSystemRefManager)}
	 * to listeners.
	 * <p>
	 * @param ref the {@link FileSystemRef} to release.
	 */
	public void release(FileSystemRef ref) {
		synchronized (this) {
			// search the refs list backwards (using identity compare) because the most
			// recently added ref is the mostly likely to be removed.
			for (int i = refs.size() - 1; i >= 0; i--) {
				FileSystemRef tmp = refs.get(i);
				if (tmp == ref) {
					refs.remove(i);
					touch();
					ref = null;
					break;
				}
			}
		}
		if (ref != null) {
			throw new IllegalArgumentException("Tried to remove unknown reference to " + fs);
		}
		for (FileSystemEventListener listener : listeners) {
			listener.onFilesystemRefChange(fs, this);
		}
	}

	/**
	 * Returns true if the only {@link FileSystemRef} pinning this filesystem is the
	 * caller's ref.
	 *
	 * @param callersRef {@link FileSystemRef} to test
	 * @return boolean true if the tested {@link FileSystemRef} is the only ref pinning
	 * the filesystem.
	 */
	public synchronized boolean canClose(FileSystemRef callersRef) {
		return refs.size() == 1 && refs.get(0) == callersRef;
	}

	/**
	 * Called from the {@link GFileSystem#close()} before any destructive changes have
	 * been made to gracefully shutdown the ref manager.
	 * <p>
	 * Broadcasts {@link FileSystemEventListener#onFilesystemClose(GFileSystem)}.
	 */
	public void onClose() {
		GFileSystem fsCopy;
		synchronized (this) {
			if (fs == null) {
				throw new IllegalArgumentException("FileSystemRefManager already closed!");
			}
			if (!refs.isEmpty()) {
				Msg.warn(this, "Closing filesystem even though it has active handles open: " + fs);
			}
			fsCopy = fs;
			fs = null;
			refs.clear();
			refs = null;
		}
		for (FileSystemEventListener listener : listeners) {
			listener.onFilesystemClose(fsCopy);
		}
	}

	@Override
	public void finalize() {
		// Don't log warning for GFileSystemBase instances since they have a different lifecycle
		// where instances are created and thrown away without a close() to probe
		// filesystem container files.
		if (fs != null && !(fs instanceof GFileSystemBase)) {
			Msg.warn(this, "Unclosed FilesytemRefManager for filesystem: " + fs.getClass() + ", " +
				fs.getName());
		}
	}

	public synchronized long getLastUsedTimestamp() {
		return lastUsedTS;
	}
}
