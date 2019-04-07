/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.model.*;
import ghidra.framework.store.FolderItem;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;
import java.util.HashMap;

/**
 * Helper class to maintain mapping of fileID's to DomainFile's.
 */
class DomainFileIndex implements DomainFolderChangeListener {

	private ProjectFileManager projectData;
	private HashMap<String, String> fileIdToPathIndex = new HashMap<String, String>();

	DomainFileIndex(ProjectFileManager projectData) {
		this.projectData = projectData;
	}

	// NOTE: file index map will generally be incomplete since it will only be a partial map
	// based upon "visited" domain folders.  If an ID is not found within the map, a scan of the 
	// domain folders may be required

	private void updateFileEntry(GhidraFile df) {
		updateFileEntry(df, df.getFileID(), df.getPathname());
	}

	void updateFileEntry(GhidraFileData dfd) {
		updateFileEntry(dfd.getDomainFile(), dfd.getFileID(), dfd.getPathname());
	}

	void removeFileEntry(String fileID) {
		fileIdToPathIndex.remove(fileID);
	}

	private void updateFileEntry(GhidraFile df, String id, String newPath) {
		if (id != null) {
			String oldPath = fileIdToPathIndex.get(id);
			if (oldPath == null) {
				fileIdToPathIndex.put(id, newPath);
			}
			else if (oldPath.equals(newPath)) {
				return;
			}
			else {
				GhidraFile oldDf = (GhidraFile) projectData.getFile(oldPath);
				if (oldDf == null) {
					fileIdToPathIndex.put(id, newPath);
				}
				else {
					reconcileFileIDConflict(df, oldDf);
				}
			}
		}
	}

	private void reconcileFileIDConflict(GhidraFile df1, GhidraFile df2) {
		try {
			String path1 = df1.getPathname();
			String path2 = df2.getPathname();
			if (!df1.isCheckedOut() && !df1.isVersioned()) {
				Msg.warn(this, "WARNING! changing file-ID for " + path1);
				df1.resetFileID();
			}
			else if (!df2.isCheckedOut() && !df2.isVersioned()) {
				Msg.warn(this, "WARNING! changing file-ID for " + path2);
				df2.resetFileID();
			}
			else {
				// Unable to resolve conflict
				Msg.error(this, "The following project files have conflicting file-IDs!\n" + path1 +
					"\n" + path2);
			}
			fileIdToPathIndex.put(df1.getFileID(), path1);
			fileIdToPathIndex.put(df2.getFileID(), path2);
		}
		catch (IOException e) {
			Msg.error(this, "Error while resolving file IDs", e);
			e.printStackTrace();
		}
	}

	DomainFile getFileByID(String fileID) {
		TaskMonitor monitor = projectData.getProjectDisposalMonitor();
		String filePath = fileIdToPathIndex.get(fileID);
		if (filePath != null) {
			return projectData.getFile(filePath);
		}

		boolean unsupportedOperation = false;

		IOException exc = null;
		try {
			FolderItem item = projectData.getPrivateFileSystem().getItem(fileID);
			if (item != null) {
				return projectData.getFile(item.getPathName());
			}
		}
		catch (UnsupportedOperationException e) {
			unsupportedOperation = true;
		}
		catch (IOException e) {
			exc = e;
		}

		try {
			FolderItem item = projectData.getVersionedFileSystem().getItem(fileID);
			if (item != null) {
				return projectData.getFile(item.getPathName());
			}
			return null;
		}
		catch (UnsupportedOperationException e) {
			unsupportedOperation = true;
		}
		catch (IOException e) {
			exc = e;
		}

		if (unsupportedOperation) {
			// if file-system get item by File-ID unsupported use brute force search
			try {
				return findFileByID(projectData.getRootFolderData(), fileID, monitor);
			}
			catch (IOException e) {
				exc = e;
			}
		}

		if (exc != null) {
			Msg.error(this, "File index lookup failed due to error: " + exc.getMessage());
		}
		return null;
	}

	private DomainFile findFileByID(GhidraFolderData folderData, String fileID, TaskMonitor monitor)
			throws IOException {
		if (!folderData.visited()) {
			// force files to be added to index and check index map
			folderData.refresh(false, true, monitor);
			String filePath = fileIdToPathIndex.get(fileID);
			if (filePath != null) {
				return projectData.getFile(filePath);
			}
		}
		for (String name : folderData.getFolderNames()) {
			if (monitor.isCancelled()) {
				return null;
			}
			GhidraFolderData subfolderData = folderData.getFolderData(name, true);
			if (subfolderData != null) {
				DomainFile df = findFileByID(subfolderData, fileID, monitor);
				if (df != null) {
					return df;
				}
			}
		}
		// perform extra check to handle potential race condition
		String filePath = fileIdToPathIndex.get(fileID);
		if (filePath != null) {
			return projectData.getFile(filePath);
		}
		return null;
	}

	public void domainFileAdded(DomainFile file) {
		updateFileEntry((GhidraFile) file);
	}

	public void domainFileMoved(DomainFile file, DomainFolder oldParent, String oldName) {
		updateFileEntry((GhidraFile) file);
	}

	public void domainFileObjectClosed(DomainFile file, DomainObject object) {
		// no-op
	}

	public void domainFileObjectOpenedForUpdate(DomainFile file, DomainObject object) {
		// no-op
	}

	public void domainFileObjectReplaced(DomainFile file, DomainObject oldObject) {
		// no-op
	}

	public void domainFileRemoved(DomainFolder parent, String name, String fileID) {
		fileIdToPathIndex.remove(fileID);
	}

	public void domainFileRenamed(DomainFile file, String oldName) {
		updateFileEntry((GhidraFile) file);
	}

	public void domainFileStatusChanged(DomainFile file, boolean fileIDset) {
		if (fileIDset) {
			updateFileEntry((GhidraFile) file);
		}
	}

	public void domainFolderAdded(DomainFolder folder) {
		// no-op
	}

	public void domainFolderMoved(DomainFolder folder, DomainFolder oldParent) {
		// no-op
	}

	public void domainFolderRemoved(DomainFolder parent, String name) {
		// no-op
	}

	public void domainFolderRenamed(DomainFolder folder, String oldName) {
		// no-op
	}

	public void domainFolderSetActive(DomainFolder folder) {
		// no-op
	}
}
