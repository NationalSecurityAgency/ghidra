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

import db.buffers.LocalManagedBufferFile;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.remote.User;
import ghidra.framework.store.*;
import ghidra.framework.store.local.*;
import ghidra.server.Repository;
import ghidra.server.RepositoryManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.UserAccessException;

/**
 * <code>RepositoryFile</code> provides a persistent wrapper for a FolderItem
 * stored within a Repository.  This file is associated with a parent RepositoryFolder
 * and facilitates caching of the underlying FolderItem.
 */
public class RepositoryFile {

	private Repository repository;
	private LocalFileSystem fileSystem;
	private RepositoryFolder parent;
	private String name;
	private LocalDatabaseItem databaseItem;
	private RepositoryItem repositoryItem;
	private boolean deleted = false;

	/**
	 * Constructor for an existing folder item within a repository.
	 * @param repository repository which contains item.
	 * @param fileSystem local file-system which corresponds to repository.
	 * @param parent parent repository folder
	 * @param name item/file name
	 * @throws IOException
	 */
	RepositoryFile(Repository repository, LocalFileSystem fileSystem, RepositoryFolder parent,
			String name) throws IOException {
		this.repository = repository;
		this.fileSystem = fileSystem;
		this.parent = parent;
		this.name = name;
//		LocalFolderItem folderItem = fileSystem.getItem(parent.getPathname(), name);
//		if (folderItem == null || !folderItem.isVersioned() ||
//			!(folderItem instanceof LocalDatabaseItem)) {
//			// must build pathname just in case folderItem does not exist
//			String pathname = parent.getPathname();
//			if (pathname.length() != 1) {
//				pathname += "/";
//			}
//			pathname += name;
//			RepositoryManager.log(repository.getName(), pathname, "file is corrupt", null);
//			throw new FileNotFoundException(pathname + " is corrupt");
//		}
//		this.databaseItem = (LocalDatabaseItem) folderItem;
	}

	/**
	 * Validate this repository file.
	 * @throws IOException if the underlying item is not found or 
	 * associated repository is not valid
	 */
	private void validate() throws IOException {
		synchronized (fileSystem) {
			repository.validate();
			if (deleted) {
				throw new FileNotFoundException(getPathname() + " not found");
			}
			if (databaseItem == null) {
				repositoryItem = null;
				LocalFolderItem folderItem = fileSystem.getItem(parent.getPathname(), name);
				if (folderItem == null || !folderItem.isVersioned() ||
					!(folderItem instanceof LocalDatabaseItem)) {
					// must build pathname just in case folderItem does not exist
					String pathname = parent.getPathname();
					if (pathname.length() != 1) {
						pathname += "/";
					}
					pathname += name;
					RepositoryManager.log(repository.getName(), pathname, "file is corrupt", null);
					throw new FileNotFoundException(pathname + " is corrupt");
				}
				this.databaseItem = (LocalDatabaseItem) folderItem;
			}
		}
	}

	/**
	 * Returns item/file name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns parent folder
	 */
	public RepositoryFolder getParent() {
		return parent;
	}

	/**
	 * Returns file/item path within repository.
	 */
	public String getPathname() {
		synchronized (fileSystem) {
			String parentPath = parent.getPathname();
			if (parentPath.length() == 1) {
				return parentPath + name;
			}
			return parentPath + FileSystem.SEPARATOR_CHAR + name;
		}
	}

	/**
	 * Returns data pertaining to this file.
	 * @throws IOException
	 */
	public RepositoryItem getItem() {
		synchronized (fileSystem) {
			try {
				validate();
				if (repositoryItem == null) {
					repositoryItem =
						new RepositoryItem(parent.getPathname(), name, databaseItem.getFileID(),
							RepositoryItem.DATABASE, databaseItem.getContentType(),
							databaseItem.getCurrentVersion(), databaseItem.lastModified());
				}
			}
			catch (IOException e) {
				repositoryItem = new RepositoryItem(parent.getPathname(), name, null,
					RepositoryItem.DATABASE, "INVALID", 0, 0);
			}
			return repositoryItem;
		}
	}

	/**
	 * Open a specific database version for read-only use.
	 * This method is only valid for an underlying FolderItem of type database.
	 * @param version requested version or -1 for current version
	 * @param minChangeDataVer minimum version to include within change data or -1 if not applicable.
	 * @param user 
	 * @return open BufferFile for read-only use.
	 * @throws IOException
	 */
	public LocalManagedBufferFile openDatabase(int version, int minChangeDataVer, String user)
			throws IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateReadPrivilege(user);
			LocalManagedBufferFile bf = databaseItem.open(version, minChangeDataVer);
			repository.log(getPathname(), "version " +
				(version < 0 ? databaseItem.getCurrentVersion() : version) + " opened read-only",
				user);
			return bf;
		}
	}

	/**
	 * Open the current version for checkin use.
	 * @param checkoutId checkout ID
	 * @param user
	 * @return open BufferFile for update/checkin use
	 */
	public LocalManagedBufferFile openDatabase(long checkoutId, String user) throws IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateWritePrivilege(user);
			ItemCheckoutStatus coStatus = databaseItem.getCheckout(checkoutId);
			if (coStatus == null) {
				throw new IOException("Illegal checkin");
			}
			if (!coStatus.getUser().equals(user)) {
				throw new IOException(
					"Checkin not permitted, checkout was made by " + coStatus.getUser());
			}
			LocalManagedBufferFile bf = databaseItem.openForUpdate(checkoutId);
			repository.log(getPathname(), "check-in started", user);
			return bf;
		}
	}

	/**
	 * Returns list of all available versions.
	 */
	public Version[] getVersions(String user) throws IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateReadPrivilege(user);
			return databaseItem.getVersions();
		}
	}

	/**
	 * Returns the length of this domain file.  This size is the minimum disk space
	 * used for storing this file, but does not account for additional storage space
	 * used to tracks changes, etc. 
	 * @return file length
	 * @throws IOException thrown if IO or access error occurs
	 */
	public long length() throws IOException {
		synchronized (fileSystem) {
			validate();
			return databaseItem.length();
		}
	}

	/**
	 * Delete oldest or current version of this file/item.
	 * @param version oldest or current version, or -1 to remove
	 * all versions.
	 * @param user
	 * @throws IOException
	 */
	public void delete(int version, String user) throws IOException {
		synchronized (fileSystem) {
			validate();
			User userObj = repository.validateWritePrivilege(user);

			if (!userObj.isAdmin()) {
				Version[] versions = databaseItem.getVersions();
				if (version == -1) {
					for (int i = 0; i < versions.length; i++) {
						if (!user.equals(versions[i].getUser())) {
							throw new UserAccessException(getName() + " version " +
								versions[i].getVersion() + " owned by " + versions[i].getUser());
						}
					}
				}
				else if (version == versions[0].getVersion()) {
					if (!user.equals(versions[0].getUser())) {
						throw new UserAccessException(getName() + " version " + version +
							" owned by " + versions[0].getUser());
					}
				}
				else if (version == versions[versions.length - 1].getVersion()) {
					if (!user.equals(versions[versions.length - 1].getUser())) {
						throw new UserAccessException(getName() + " version " + version +
							" owned by " + versions[versions.length - 1].getUser());
					}
				}
				else {
					throw new IOException("Only the oldest or latest version may be deleted");
				}
			}
			String oldPath = getPathname();
			if (databaseItem == null) {
				// forced removal by repo Admin

			}
			else {
				databaseItem.delete(version, user);
			}
			deleted = true;
			repositoryItem = null;
			parent.fileDeleted(this);
			RepositoryFile newRf = parent.getFile(name);
			if (newRf == null) {
				RepositoryManager.log(repository.getName(), oldPath, "file deleted", user);
			}
			parent = null;
		}
	}

	/**
	 * Move this file/item to a new folder and optionally change its name.
	 * @param newParent new parent folder
	 * @param newItemName new file/item name
	 * @param user
	 * @throws InvalidNameException if name is invalid
	 * @throws IOException
	 */
	public void moveTo(RepositoryFolder newParent, String newItemName, String user)
			throws InvalidNameException, IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateWritePrivilege(user);
			String oldName = name;
			String oldPath = getPathname();
			String newFolderPath = newParent.getPathname();
			fileSystem.moveItem(parent.getPathname(), getName(), newFolderPath, newItemName);
			name = newItemName;
			parent.fileMoved(this, oldName, newParent);
			parent = newParent;
			pathChanged();
			RepositoryManager.log(repository.getName(), oldPath, "file moved to " + getPathname(),
				user);
		}
	}

	/**
	 * Request a checkout of the underlying item.
	 * @param checkoutType checkout type requested
	 * @param user
	 * @return checkout data if successful.  Null is returned if exclusive checkout
	 * failed due to existing checkout(s).
	 * @throws IOException
	 */
	public ItemCheckoutStatus checkout(CheckoutType checkoutType, String user, String projectPath)
			throws IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateWritePrivilege(user); // don't allow checkout if read-only 
			ItemCheckoutStatus coStatus = databaseItem.checkout(checkoutType, user, projectPath);
			if (coStatus != null && checkoutType != CheckoutType.NORMAL && repositoryItem != null &&
				repositoryItem.getFileID() == null) {
				repositoryItem = null; // force refresh since fileID should get reset
			}
			return coStatus;
		}
	}

	/**
	 * Update checkout version for an existing checkout.
	 * @param checkoutId existing checkout ID
	 * @param checkoutVersion newer version now associated with checkout
	 * @param user
	 * @throws IOException
	 */
	public void updateCheckoutVersion(long checkoutId, int checkoutVersion, String user)
			throws IOException {
		synchronized (fileSystem) {
			validate();
			databaseItem.updateCheckoutVersion(checkoutId, checkoutVersion, user);
		}
	}

	/**
	 * Terminate an existing checkout
	 * @param checkoutId existing checkout ID
	 * @param user
	 * @param notify if true notify listeners of item change.
	 * @throws IOException
	 */
	public void terminateCheckout(long checkoutId, String user, boolean notify) throws IOException {
		synchronized (fileSystem) {
			validate();
			ItemCheckoutStatus coStatus = databaseItem.getCheckout(checkoutId);
			if (coStatus != null) {
				User userObj = repository.getUser(user);
				if (!userObj.isAdmin() && !coStatus.getUser().equals(user)) {
					throw new IOException(
						"Undo-checkout not permitted, checkout was made by " + coStatus.getUser());
				}
				databaseItem.terminateCheckout(checkoutId, notify);
			}
		}
	}

	/**
	 * Returns checkout data for a specified checkout ID.
	 * @param checkoutId existing checkout ID
	 * @param user
	 * @throws IOException
	 */
	public ItemCheckoutStatus getCheckout(long checkoutId, String user) throws IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateReadPrivilege(user);
			return databaseItem.getCheckout(checkoutId);
		}
	}

	/**
	 * Returns a list of all checkouts for this file/item.
	 * @param user
	 * @throws IOException
	 */
	public ItemCheckoutStatus[] getCheckouts(String user) throws IOException {
		synchronized (fileSystem) {
			validate();
			repository.validateReadPrivilege(user);
			return databaseItem.getCheckouts();
		}
	}

	/**
	 * Returns true if one or more checkouts exist for this file/item.
	 * @throws IOException
	 */
	public boolean hasCheckouts() throws IOException {
		synchronized (fileSystem) {
			validate();
			return databaseItem.hasCheckouts();
		}
	}

	/**
	 * Returns true if checkin is currently in process.
	 * @throws IOException
	 */
	public boolean isCheckinActive() throws IOException {
		synchronized (fileSystem) {
			validate();
			return databaseItem.isCheckinActive();
		}
	}

	/**
	 * Clear cached data as a result of an item changed callback from the filesystem
	 */
	public void itemChanged() {
		synchronized (fileSystem) {
			// Nulling the repositoryItem deletes the cache information & gets new version info.
			repositoryItem = null;
		}
	}

	/**
	 * Reaquire associated folder item following a folder move or name change.
	 * @param newName items new name (which may be unchanged if path change was
	 * the result of a moved or renamed folder).
	 */
	void pathChanged() {
		synchronized (fileSystem) {
			repositoryItem = null;
			databaseItem = null;
		}
	}

}
