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
package ghidra.server.store;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import db.buffers.LocalManagedBufferFile;
import ghidra.framework.store.*;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.local.LocalFolderItem;
import ghidra.server.Repository;
import ghidra.server.RepositoryManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.FileInUseException;

/**
 * <code>RepositoryFolder</code> provides a persistent wrapper for a folder path
 * which may contain other sub-folders or FolderItem's stored within a Repository.  
 * This folder is associated with a parent RepositoryFolder
 * and facilitates caching of the underlying FolderItem.
 * The root folder within the file-system will have a null parent.
 */
public class RepositoryFolder {
	static final Logger log = LogManager.getLogger(RepositoryFolder.class);

	private Repository repository;
	private LocalFileSystem fileSystem;
	private RepositoryFolder parent;
	private String name;
	private Map<String, RepositoryFolder> folderMap = new HashMap<>();
	private Map<String, RepositoryFile> fileMap = new HashMap<>();

	/**
	 * RepositoryFile name comparator
	 */
	private static Comparator<RepositoryFile> FILE_NAME_COMPARATOR =
		(f1, f2) -> f1.getName().compareTo(f2.getName());

	/**
	 * RepositoryFolder name comparator
	 */
	private static Comparator<RepositoryFolder> FOLDER_NAME_COMPARATOR =
		(f1, f2) -> f1.getName().compareTo(f2.getName());

	/**
	 * Constructor for non-root folders
	 * @param repository shared repository
	 * @param fileSystem local file system for storing version controlled items
	 * @param parent parent folder
	 * @param name name of this folder
	 * @throws IOException if an IO error occurs
	 */
	private RepositoryFolder(Repository repository, LocalFileSystem fileSystem,
			RepositoryFolder parent, String name) throws IOException {
		this.repository = repository;
		this.fileSystem = fileSystem;
		this.parent = parent;
		this.name = name;
		init();
	}

	/**
	 * Constructor for the root folder
	 * @param repository shared repository
	 * @param fileSystem local file system for storing version controlled items
	 * @throws IOException if an IO error occurs
	 */
	public RepositoryFolder(Repository repository, LocalFileSystem fileSystem) throws IOException {
		this.repository = repository;
		this.fileSystem = fileSystem;
		this.name = "";
		init();
	}

	private void init() throws IOException {
		String path = getPathname();
		String[] names = fileSystem.getFolderNames(path);
		for (String name2 : names) {
			RepositoryFolder subfolder = new RepositoryFolder(repository, fileSystem, this, name2);
			folderMap.put(name2, subfolder);
		}
		names = fileSystem.getItemNames(path);
		int badItemCount = 0;
		for (String name2 : names) {
			LocalFolderItem item = fileSystem.getItem(path, name2);
			if (item == null || !(item instanceof DatabaseItem)) {
				++badItemCount;
				continue;
			}
			RepositoryFile rf = new RepositoryFile(repository, fileSystem, this, name2);
			fileMap.put(name2, rf);
		}
		if (badItemCount != 0) {
			log.error("Repository '" + repository.getName() + "' contains " + badItemCount +
				" bad items: " + getPathname());
		}
	}

	/**
	 * Returns folder name
	 * @return folder name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns parent folder or null if this is the root folder.
	 * @return parent folder or null
	 */
	public RepositoryFolder getParent() {
		return parent;
	}

	/**
	 * Returns folder path within repository
	 * @return folder path
	 */
	public String getPathname() {
		synchronized (fileSystem) {
			StringBuffer buf = new StringBuffer(parent != null ? parent.getPathname() : "");
			if (buf.length() != 1) {
				buf.append(FileSystem.SEPARATOR_CHAR);
			}
			buf.append(name);
			return buf.toString();
		}
	}

	/**
	 * Returns all sub-folders contained within this folder
	 * @return all sub-folders
	 */
	public RepositoryFolder[] getFolders() {
		synchronized (fileSystem) {
			RepositoryFolder[] folders = new RepositoryFolder[folderMap.size()];
			folders = folderMap.values().toArray(folders);
			Arrays.sort(folders, FOLDER_NAME_COMPARATOR);
			return folders;
		}
	}

	/**
	 * Returns sub-folders with the specified name or null 
	 * if sub-folder not found within this folder.
	 * @param folderName sub-folder name
	 * @return specified sub-folder or null if not found
	 */
	public RepositoryFolder getFolder(String folderName) {
		synchronized (fileSystem) {
			RepositoryFolder rf = folderMap.get(folderName);
			if (rf != null) {
				return rf;
			}
// TODO: Could be a problem for root folder whose pathname is '/'
			String path = makePathname(getPathname(), folderName);
			if (fileSystem.folderExists(path)) {
				try {
					rf = new RepositoryFolder(repository, fileSystem, this, folderName);
					folderMap.put(folderName, rf);
					return rf;
				}
				catch (IOException e) {
					log.error("Repository error: " + repository.getName() + ": " + e.getMessage());
				}
			}
			return null;
		}
	}

	/**
	 * Returns all files/items contained within this folder
	 * @return all files/items contained within this folder
	 */
	public RepositoryFile[] getFiles() {
		synchronized (fileSystem) {
			RepositoryFile[] files = new RepositoryFile[fileMap.size()];
			files = fileMap.values().toArray(files);
			Arrays.sort(files, FILE_NAME_COMPARATOR);
			return files;
		}
	}

	/**
	 * Returns files/items with the specified name or null 
	 * if file/item not found within this folder.
	 * @param fileName sub-folder name
	 * @return named file or null if not found
	 */
	public RepositoryFile getFile(String fileName) {
		synchronized (fileSystem) {
			RepositoryFile rf = fileMap.get(fileName);
			if (rf != null) {
				return rf;
			}
			// NOTE: Uncertain what condition would lead to exiting file not already
			// existing in fileMap
			if (fileSystem.fileExists(getPathname(), fileName)) {
				try {
					LocalFolderItem item = fileSystem.getItem(getPathname(), fileName);
					if (item == null || !(item instanceof DatabaseItem)) {
						log.error("Repository '" + repository.getName() + "' contains bad item: " +
							makePathname(getPathname(), fileName));
						return null;
					}
					rf = new RepositoryFile(repository, fileSystem, this, fileName);
					fileMap.put(fileName, rf);
					return rf;
				}
				catch (IOException e) {
					log.error("Repository '" + repository.getName() + "' file error: " +
						e.getMessage() + "\n    " + makePathname(getPathname(), fileName));
				}
			}
			return null;
		}
	}

	/**
	 * Create a new sub-folder within this folder and the associated directory on the local file-system.
	 * @param folderName new sub-folder name
	 * @param user user who is initiating request
	 * @return new folder
	 * @throws InvalidNameException if folder name is invalid
	 * @throws DuplicateFileException if folder already exists with specified name
	 * @throws IOException if an IO error occurs
	 */
	public RepositoryFolder createFolder(String folderName, String user)
			throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			repository.validate();
			repository.validateWritePrivilege(user);
			if (getFolder(folderName) != null) {
				throw new DuplicateFileException(folderName + " already exists");
			}
			fileSystem.createFolder(getPathname(), folderName);

			// Folder created notification causes RepositoryFolder instance to be added

			RepositoryFolder rf = getFolder(folderName);
			RepositoryManager.log(repository.getName(), rf.getPathname(), "folder created", user);
			return rf;
		}
	}

	/**
	 * Create a new database file/item within this folder.
	 * @param itemName name of new database
	 * @param fileID file ID
	 * @param bufferSize preferred database buffer size
	 * @param contentType application content type
	 * @param user user who is initiating request
	 * @param projectPath file path within repository
	 * @return buffer file (contains checkoutId as checkinId)
	 * @throws InvalidNameException if itemName is invalid
	 * @throws DuplicateFileException if file already exists with specified name
	 * @throws IOException if an IO error occurs
	 */
	public LocalManagedBufferFile createDatabase(String itemName, String fileID, int bufferSize,
			String contentType, String user, String projectPath)
			throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			repository.validate();
			repository.validateWritePrivilege(user);
			if (getFile(itemName) != null) {
				throw new DuplicateFileException(itemName + " already exists");
			}

			// Buffer file does not yet exist - too early to get folder item needed for RepositoryFile
			LocalManagedBufferFile bf = fileSystem.createDatabase(getPathname(), itemName, fileID,
				contentType, bufferSize, user, projectPath);
			RepositoryManager.log(repository.getName(), makePathname(getPathname(), itemName),
				"file created", user);
			return bf;
		}
	}

	/**
	 * Delete this empty folder.
	 * @throws FolderNotEmptyException Thrown if the folder is not empty.
	 * @throws FileNotFoundException if there is no folder with the given path name.
	 * @throws IOException if error occurred during delete.
	 */
	public void delete() throws IOException {
		synchronized (fileSystem) {
			repository.validate();
			if (parent == null) {
				throw new IOException("Root folder may not be deleted");
			}
			fileSystem.deleteFolder(getPathname());
			parent.folderMap.remove(name);
		}
	}

	/**
	 * Returns true if any file/item contained within this folder
	 * or its descendants is checked-out.
	 */
	private boolean containsCheckout() throws IOException {

		// Check files
		for (RepositoryFile rf : fileMap.values()) {
			if (rf.hasCheckouts()) {
				return true;
			}
		}

		// Check sub-folders
		for (RepositoryFolder subfolder : folderMap.values()) {
			if (subfolder.containsCheckout()) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Remove child RepositoryFile which has already been deleted.
	 * @param rf child RepositoryFile
	 */
	void fileDeleted(RepositoryFile rf) {
		synchronized (fileSystem) {
			fileMap.remove(rf.getName());
		}
	}

	/**
	 * Move child RepositoryItem into its new parent folder
	 * after the underlying item has already been moved.
	 * @param rf child RepositoryItem
	 * @param oldName old file name
	 * @param newFolder new parent folder for rf
	 */
	void fileMoved(RepositoryFile rf, String oldName, RepositoryFolder newFolder) {
		synchronized (fileSystem) {
			fileMap.remove(oldName);
			newFolder.fileMap.put(rf.getName(), rf);
		}
	}

	/**
	 * Move this folder to a new parent folder and optionally change its name.
	 * @param newParent new parent folder
	 * @param newFolderName new name for this folder
	 * @param user user who is initiating request
	 * @throws InvalidNameException if newFolderName is invalid
	 * @throws IOException if operation fails
	 */
	public void moveTo(RepositoryFolder newParent, String newFolderName, String user)
			throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			repository.suspendEventDispatching();
			try {
				repository.validate();
				repository.validateWritePrivilege(user);
				if (parent == null) {
					throw new IOException("Root folder may not be moved");
				}
				if (newParent.isDescendantOf(this)) {
					throw new IOException("New folder must not be descendant");
				}
				if (containsCheckout()) {
					throw new FileInUseException(
						getPathname() + " contains one or more checked-out files");
				}
				String oldPath = getPathname();
				if (name.equals(newFolderName)) {
					// Handle move - name does not change
					fileSystem.moveFolder(parent.getPathname(), name, newParent.getPathname());
					parent.folderMap.remove(newFolderName);
					newParent.folderMap.put(newFolderName, this);
					parent = newParent;
				}
				else if (parent.equals(newParent)) {
					// Handle rename
					fileSystem.renameFolder(parent.getPathname(), name, newFolderName);
					parent.folderMap.remove(name);
					name = newFolderName;
					parent.folderMap.put(newFolderName, this);
				}
				else {
					throw new IOException("Folder can not be renamed and moved");
				}
				pathChanged();
				RepositoryManager.log(repository.getName(), oldPath,
					"folder moved to " + getPathname(), user);
			}
			finally {
				repository.flushChangeEvents();
			}
		}
	}

	/**
	 * Clear cached data.  Delayed refresh will occur when needed.
	 */
	public void pathChanged() {
		synchronized (fileSystem) {
			for (RepositoryFile rf : fileMap.values()) {
				rf.pathChanged();
			}
			for (RepositoryFolder subfolder : folderMap.values()) {
				subfolder.pathChanged();
			}
		}
	}

	/**
	 * Returns true if this folder is a descendant of the specified folder
	 */
	private boolean isDescendantOf(RepositoryFolder folder) {
		RepositoryFolder rf = parent;
		while (rf != null) {
			if (rf == folder) {
				return true;
			}
			rf = rf.parent;
		}
		return false;
	}

	public static String makePathname(String parentPath, String childName) {
		String path = parentPath.endsWith(FileSystem.SEPARATOR)
				? parentPath.substring(0, parentPath.length() - FileSystem.SEPARATOR.length())
				: parentPath;
		return path + FileSystem.SEPARATOR + childName;
	}
}
