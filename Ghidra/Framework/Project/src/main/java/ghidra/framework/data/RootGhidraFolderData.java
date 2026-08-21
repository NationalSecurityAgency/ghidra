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

import java.io.IOException;
import java.util.HashMap;

import ghidra.framework.model.DomainFolderChangeListener;
import ghidra.framework.store.FileSystem;
import ghidra.util.task.TaskMonitor;

public class RootGhidraFolderData extends GhidraFolderData {

	// Folder path reference counts, associated with discovered file-links and folder-links,
	// are tracked to ensure that such folders are visited immediately or upon their
	// creation to ensure that the folder change listener is properly notified of all changes 
	// related to the folder paths contained within this map. 
	private HashMap<String, Integer> folderReferenceCounts = new HashMap<>();

	/**
	 * Constructor for project data root folder.
	 * @param projectData project data
	 * @param listener folder change listener
	 */
	RootGhidraFolderData(DefaultProjectData projectData, DomainFolderChangeListener listener) {
		super(projectData, listener);
	}

	@Override
	GhidraFolder getDomainFolder() {
		return new RootGhidraFolder(getProjectData(), getChangeListener());
	}

	/**
	 * Provided for testing use only
	 * @param fs versioned file system
	 */
	void setVersionedFileSystem(FileSystem fs) {
		versionedFileSystem = fs;
	}

	@Override
	boolean privateExists() {
		return true;
	}

	/**
	 * used for testing
	 */
	@Override
	boolean sharedExists() {
		return true;
	}

	/**
	 * Determine if the specified folder path must be visited due to
	 * possible link references to the folder or one of its children.
	 * @param folderPathname folder pathname (not ending with '/') 
	 * @return true if folder should be visited to ensure that changes are properly tracked
	 * with proper change notifications sent.
	 */
	public boolean mustVisit(String folderPathname) {
		return folderReferenceCounts.containsKey(folderPathname);
	}

	/**
	 * Register internal file/folder-link to ensure we do not ignore change events which affect
	 * the referenced file/folder.
	 * @param absoluteLinkPath absolute internal path referenced by a link-file
	 */
	void registerInternalLinkPath(String absoluteLinkPath) {
		if (!absoluteLinkPath.startsWith(FileSystem.SEPARATOR)) {
			throw new IllegalArgumentException();
		}

		// Register path elements upto parent of absoluteLinkPath
		String[] pathSplit = absoluteLinkPath.split(FileSystem.SEPARATOR);
		int folderElementCount = pathSplit.length - 1;

		// Start at 1 since element 0 corresponds to root and will be empty 
		GhidraFolderData folderData = this;
		StringBuilder pathBuilder = new StringBuilder();
		for (int i = 1; i < folderElementCount; i++) {
			String folderName = pathSplit[i];
			if (folderName.length() == 0) {
				// ignore blank names
				continue;
			}
			if (folderData != null) {
				folderData = folderData.getFolderData(folderName, false);
				if (folderData != null && !folderData.visited()) {
					try {
						folderData.refresh(false, true, TaskMonitor.DUMMY);
					}
					catch (IOException e) {
						// ignore - things may get out-of-sync
						folderData = null;
					}
				}
			}

			// Increment folder reference count for all folders leading up to referenced folder
			pathBuilder.append(FileSystem.SEPARATOR);
			pathBuilder.append(folderName);
			folderReferenceCounts.compute(pathBuilder.toString(),
				(path, count) -> (count == null) ? 1 : ++count);
		}
	}

	/**
	 * Unregister internal file/folder-link to ensure we do not ignore change events which affect
	 * the referenced file/folder.
	 * @param absoluteLinkPath absolute internal path referenced by a link-file
	 */
	void unregisterInternalLinkPath(String absoluteLinkPath) {
		if (!absoluteLinkPath.startsWith(FileSystem.SEPARATOR)) {
			throw new IllegalArgumentException();
		}

		// Register path elements upto parent of absoluteLinkPath
		String[] pathSplit = absoluteLinkPath.split(FileSystem.SEPARATOR);
		int folderElementCount = pathSplit.length - 1;

		// Start at 1 since element 0 corresponds to root and will be empty 
		StringBuilder pathBuilder = new StringBuilder();
		for (int i = 1; i < folderElementCount; i++) {
			String folderName = pathSplit[i];
			if (folderName.length() == 0) {
				// ignore blank names
				continue;
			}
			// Increment folder reference count for all folders leading up to referenced folder
			pathBuilder.append(FileSystem.SEPARATOR);
			pathBuilder.append(folderName);
			String path = pathBuilder.toString();
			Integer count = folderReferenceCounts.get(path);
			if (count != null) {
				if (count == 1) {
					folderReferenceCounts.remove(path);
				}
				else {
					folderReferenceCounts.put(path, count - 1);
				}
			}
		}
	}

}
