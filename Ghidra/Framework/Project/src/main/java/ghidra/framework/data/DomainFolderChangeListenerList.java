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
package ghidra.framework.data;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import ghidra.framework.model.*;
import ghidra.util.SystemUtilities;

class DomainFolderChangeListenerList implements DomainFolderChangeListener {

	private DomainFileIndex fileIndex;

	/** CopyOnWriteArrayList prevents the need for synchronization */
	private List<DomainFolderChangeListener> list =
		new CopyOnWriteArrayList<>();

	DomainFolderChangeListenerList(DomainFileIndex fileIndex) {
		this.fileIndex = fileIndex;
	}

	void addListener(DomainFolderChangeListener listener) {
		list.add(listener);
	}

	void removeListener(DomainFolderChangeListener listener) {
		list.remove(listener);
	}

	@Override
	public void domainFolderAdded(final DomainFolder folder) {
		fileIndex.domainFolderAdded(folder);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFolderAdded(folder);
			}
		});
	}

	@Override
	public void domainFileAdded(final DomainFile file) {
		fileIndex.domainFileAdded(file);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileAdded(file);
			}
		});
	}

	@Override
	public void domainFolderRemoved(final DomainFolder parent, final String name) {
		fileIndex.domainFolderRemoved(parent, name);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFolderRemoved(parent, name);
			}
		});
	}

	@Override
	public void domainFileRemoved(final DomainFolder parent, final String name,
			final String fileID) {
		fileIndex.domainFileRemoved(parent, name, fileID);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileRemoved(parent, name, fileID);
			}
		});
	}

	@Override
	public void domainFolderRenamed(final DomainFolder folder, final String oldName) {
		fileIndex.domainFolderRenamed(folder, oldName);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFolderRenamed(folder, oldName);
			}
		});
	}

	@Override
	public void domainFileRenamed(final DomainFile file, final String oldName) {
		fileIndex.domainFileRenamed(file, oldName);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileRenamed(file, oldName);
			}
		});
	}

	@Override
	public void domainFolderMoved(final DomainFolder folder, final DomainFolder oldParent) {
		fileIndex.domainFolderMoved(folder, oldParent);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFolderMoved(folder, oldParent);
			}
		});
	}

	@Override
	public void domainFileMoved(final DomainFile file, final DomainFolder oldParent,
			final String oldName) {
		fileIndex.domainFileMoved(file, oldParent, oldName);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileMoved(file, oldParent, oldName);
			}
		});
	}

	@Override
	public void domainFolderSetActive(final DomainFolder folder) {
		fileIndex.domainFolderSetActive(folder);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFolderSetActive(folder);
			}
		});
	}

	@Override
	public void domainFileStatusChanged(final DomainFile file, final boolean fileIDset) {
		fileIndex.domainFileStatusChanged(file, fileIDset);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileStatusChanged(file, fileIDset);
			}
		});
	}

	@Override
	public void domainFileObjectOpenedForUpdate(final DomainFile file, final DomainObject object) {
		fileIndex.domainFileObjectOpenedForUpdate(file, object);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileObjectOpenedForUpdate(file, object);
			}
		});
	}

	@Override
	public void domainFileObjectClosed(final DomainFile file, final DomainObject object) {
		fileIndex.domainFileObjectClosed(file, object);
		if (list.isEmpty()) {
			return;
		}
		SystemUtilities.runSwingLater(() -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileObjectClosed(file, object);
			}
		});
	}

	@Override
	public void domainFileObjectReplaced(final DomainFile file, final DomainObject oldObject) {
		fileIndex.domainFileObjectReplaced(file, oldObject);
		if (list.isEmpty()) {
			return;
		}
		Runnable r = () -> {
			for (DomainFolderChangeListener listener : list) {
				listener.domainFileObjectReplaced(file, oldObject);
			}
		};
		SystemUtilities.runSwingNow(r);
	}

	public void clearAll() {
		list.clear();
	}
}
