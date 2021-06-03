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
package ghidra.framework.store.local;

import java.io.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import ghidra.framework.store.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

/**
 * <code>LocalFolderItem</code> provides an abstract implementation of a folder
 * item which resides on a local file-system.  An item is defined by a property file
 * and generally has a hidden data directory which contains the actual data file(s).
 *<p>
 * An item may be either private or shared (i.e., versioned) as defined by the
 * associated file-system.  A shared item utilizes a CheckoutManager and HistoryManager
 * for tracking version control data related to this item.
 */
public abstract class LocalFolderItem implements FolderItem {
	static final Logger log = LogManager.getLogger(LocalFolderItem.class);

	static final String FILE_TYPE = "FILE_TYPE";
	static final String READ_ONLY = "READ_ONLY";
	static final String CONTENT_TYPE = "CONTENT_TYPE";
	static final String CHECKOUT_ID = "CHECKOUT_ID";
	static final String EXCLUSIVE_CHECKOUT = "EXCLUSIVE";
	static final String CHECKOUT_VERSION = "CHECKOUT_VERSION";
	static final String LOCAL_CHECKOUT_VERSION = "LOCAL_CHECKOUT_VERSION";
	static final String CONTENT_TYPE_VERSION = "CONTENT_TYPE_VERSION";

	static final String DATA_DIR_EXTENSION = ".db";

	final PropertyFile propertyFile;
	final CheckoutManager checkoutMgr;
	final HistoryManager historyMgr;
	final LocalFileSystem fileSystem;
	final boolean isVersioned;
	final boolean useDataDir;

	String repositoryName;

	long lastModified;

	long checkinId = DEFAULT_CHECKOUT_ID;

	/**
	 * Construct an existing item which corresponds to the specified 
	 * property file.  If a data directory is found it will be 
	 * associated with this item.
	 * @param fileSystem file system
	 * @param propertyFile property file
	 */
	LocalFolderItem(LocalFileSystem fileSystem, PropertyFile propertyFile) {
		this.fileSystem = fileSystem;
		this.propertyFile = propertyFile;
		this.isVersioned = fileSystem.isVersioned();
		File dataDir = getDataDir();
		this.useDataDir = dataDir.exists();
		this.checkoutMgr = null;
		this.historyMgr = null;
		lastModified = propertyFile.lastModified();
	}

	/**
	 * Constructor for a new or existing item which corresponds to the specified 
	 * property file.  
	 * @param fileSystem file system
	 * @param propertyFile property file
	 * @param useDataDir if true the getDataDir() method must return an appropriate 
	 * directory for data storage.
	 * @param create if true the data directory will be created
	 * @throws IOException
	 */
	LocalFolderItem(LocalFileSystem fileSystem, PropertyFile propertyFile, boolean useDataDir,
			boolean create) throws IOException {
		this.fileSystem = fileSystem;
		this.propertyFile = propertyFile;
		this.isVersioned = fileSystem.isVersioned();
		this.useDataDir = useDataDir || isVersioned;

		boolean success = false;
		try {
			if (create) {
				if (fileSystem.isReadOnly()) {
					throw new ReadOnlyException();
				}
				if (propertyFile.exists()) {
					throw new DuplicateFileException(getName() + " already exists.");
				}
				if (useDataDir) {
					File dir = getDataDir();
					if (dir.exists()) {
						throw new DataDirectoryException("Data directory already exists", dir);
					}
					if (!dir.mkdir()) {
						throw new IOException("Failed to create " + getName());
					}
				}
				propertyFile.writeState();
			}
			else if ((useDataDir && !getDataDir().exists()) || !propertyFile.exists()) {
				throw new FileNotFoundException(getName() + " not found");
			}

			if (isVersioned) {
				checkoutMgr = new CheckoutManager(this, create);
				historyMgr = new HistoryManager(this, create);
			}
			else {
				checkoutMgr = null;
				historyMgr = null;
			}

			success = true;
		}
		finally {
			if (!success && create) {
				abortCreate();
			}
		}
		lastModified = propertyFile.lastModified();
	}

	void log(String msg, String user) {
		fileSystem.log(this, msg, user);
	}

	@Override
	public LocalFolderItem refresh() throws IOException {
		if ((useDataDir && !getDataDir().exists()) || !propertyFile.exists()) {
			return null;
		}
		propertyFile.readState();
		return this;
	}

	/**
	 * Returns hidden database directory
	 */
	File getDataDir() {
		synchronized (fileSystem) {
			// Use hidden DB directory
			return new File(propertyFile.getFolder(), LocalFileSystem.HIDDEN_DIR_PREFIX +
				LocalFileSystem.escapeHiddenDirPrefixChars(propertyFile.getStorageName()) +
				DATA_DIR_EXTENSION);
		}
	}

	/**
	 * Return the oldest/minimum version.
	 * @throws IOException thrown if an IO error occurs.
	 */
	abstract int getMinimumVersion() throws IOException;

	/**
	 * Verify that the specified version of this item is not in use.
	 * @param version the specific version to check for versioned items.
	 * @throws FileInUseException
	 */
	void checkInUse(int version) throws FileInUseException {
		synchronized (fileSystem) {
			if (checkoutMgr != null) {
				boolean isCheckedOut;
				try {
					isCheckedOut = checkoutMgr.isCheckedOut(version);
				}
				catch (IOException e) {
					throw new FileInUseException(getName() + " versioning error", e);
				}
				if (isCheckedOut) {
					throw new FileInUseException(getName() + " version " + version +
						" is checked out");
				}
			}
			else if (!isVersioned && getCheckoutId() != DEFAULT_CHECKOUT_ID) {
				throw new FileInUseException(getName() + " is checked out");
			}
		}
	}

	/**
	 * Verify that this item is not in use.
	 * @throws FileInUseException
	 */
	void checkInUse() throws FileInUseException {
		synchronized (fileSystem) {
			if (fileSystem.migrationInProgress()) {
				return; // migration not affected by checkouts
			}
			if (checkoutMgr != null) {
				boolean isCheckedOut;
				try {
					isCheckedOut = checkoutMgr.isCheckedOut();
				}
				catch (IOException e) {
					throw new FileInUseException(getName() + " versioning error", e);
				}
				if (isCheckedOut) {
					throw new FileInUseException(getName() + " is checked out");
				}
			}
			else if (!isVersioned && getCheckoutId() != DEFAULT_CHECKOUT_ID) {
				throw new FileInUseException(getName() + " is checked out");
			}
		}
	}

	/**
	 * Begin the check-in process for a versioned item.
	 * @param checkoutId assigned at time of checkout, becomes the check-in ID.
	 * @throws FileInUseException
	 */
	void beginCheckin(long checkoutId) throws FileInUseException {
		synchronized (fileSystem) {
			if (checkinId != DEFAULT_CHECKOUT_ID) {
				ItemCheckoutStatus status;
				try {
					status = checkoutMgr.getCheckout(checkinId);
				}
				catch (IOException e) {
					throw new FileInUseException(getName() + " versioning error", e);
				}
				String byMsg = status != null ? (" by: " + status.getUser()) : "";
				throw new FileInUseException("Another checkin is in progress" + byMsg);
			}
			checkinId = checkoutId;
//Log.put("Check-in started: " + checkinId);
		}
	}

	/**
	 * Terminates a check-in which is in progress or has been completed.
	 * @param itemCheckinId used to validate termination request.
	 */
	void endCheckin(long itemCheckinId) {
		synchronized (fileSystem) {
			if (this.checkinId == itemCheckinId) {
				this.checkinId = DEFAULT_CHECKOUT_ID;
//Log.put("Check-in ended: " + checkinId);
			}
		}
	}

	/**
	 * Send out notification this item has just been created.
	 */
	void fireItemCreated() {
		fileSystem.getListener().itemCreated(getParentPath(), getName());
	}

	/**
	 * Send out notification that this item has changed in some way.
	 */
	void fireItemChanged() {
		fileSystem.getListener().itemChanged(getParentPath(), getName());
	}

	/**
	 * Abort the creation of 
	 *
	 */
	void abortCreate() {
		synchronized (fileSystem) {
			propertyFile.delete();
			if (useDataDir) {
				FileUtilities.deleteDir(getDataDir());
			}
		}
	}

	/**
	 * @see ghidra.framework.store.FolderItem#delete(int, java.lang.String)
	 */
	@Override
	public void delete(int version, String user) throws IOException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			String parentPath = getParentPath();
			String name = getName();
			boolean deleted = false;
			int currentVersion = getCurrentVersion();
			if (version == -1) {
				if (isVersioned) {
					checkInUse();
				}
				deleteContent(user);
				deleted = true;
			}
			else if (!isVersioned) {
				throw new IllegalArgumentException(
					"delete version must be -1 for non-versioned items");
			}
			else {
				int minVersion = getMinimumVersion();
				if (version == minVersion) {
					checkInUse(version);
					if (minVersion == currentVersion) {
						deleteContent(user);
						deleted = true;
					}
					else {
						deleteMinimumVersion(user);
					}
				}
				else if (version == currentVersion) {
					checkInUse(version);
					deleteCurrentVersion(user);
				}
				else {
					throw new IOException("Only the oldest or latest version may be deleted");
				}
			}

			if (deleted) {
				fileSystem.itemDeleted(parentPath, name); // de-allocates index entry
				if (currentVersion > 0) {
					// Only notify if initial version was created
					fileSystem.getListener().itemDeleted(parentPath, name);
				}
				fileSystem.deleteEmptyVersionedFolders(getParentPath());
			}
			else {
				fireItemChanged();
			}
		}
	}

	/**
	 * Remove this item from the associated filesystem.
	 * The property file and the hidden data directory are removed.
	 * If in-use files prevent removal a FileInUseException will be thrown.
	 * @param user user performing removal
	 * @throws IOException if an error occurs during the delete operation.
	 * Files are restored to there original state if unable to remove
	 * all files.
	 */
	void deleteContent(String user) throws IOException {
		synchronized (fileSystem) {
			File dataDir = getDataDir();
			File chkDir = new File(dataDir.getParentFile(), dataDir.getName() + ".delete");
			FileUtilities.deleteDir(chkDir);
			if (useDataDir && dataDir.exists() && !dataDir.renameTo(chkDir)) {
				throw new FileInUseException(getName() + " is in use");
			}
			boolean success = false;
			try {
				propertyFile.delete();
				if (propertyFile.exists()) {
					throw new FileInUseException(getName() + " is in use");
				}
				success = true;
			}
			finally {
				if (!success) {
					if (useDataDir && !dataDir.exists() && chkDir.exists() && propertyFile.exists()) {
						chkDir.renameTo(dataDir);
					}
				}
				else {
					if (useDataDir) {
						FileUtilities.deleteDir(chkDir);
					}
					log("file deleted", user);
				}
			}
		}
	}

	/**
	 * Delete the item content associated with the minimum version.
	 * This method will only be invoked for versioned items and will
	 * never be the only version (i.e., minVersion will always be less
	 * than the currentVersion).
	 * @param user user name
	 * @throws IOException
	 */
	abstract void deleteMinimumVersion(String user) throws IOException;

	/**
	 * Delete the item content associated with the current version.
	 * This method will only be invoked for versioned items and will
	 * never be the only version (i.e., minVersion will always be less
	 * than the currentVersion).
	 * @param user user name
	 * @throws IOException
	 */
	abstract void deleteCurrentVersion(String user) throws IOException;

	/**
	 * Move this item into a newFolder which has a path of newPath.
	 * @param newFolder new parent directory/folder 
	 * @param newStorageName new storage name
	 * @param newPath new parent path
	 * @throws DuplicateFileException
	 * @throws FileInUseException
	 * @throws IOException
	 * @see ghidra.framework.store.FileSystem#moveItem
	 */
	void moveTo(File newFolder, String newStorageName, String newFolderPath, String newName)
			throws IOException {
		synchronized (fileSystem) {
			checkInUse();

			File oldFolder = propertyFile.getFolder();
			String oldStorageName = propertyFile.getStorageName();
			String oldPath = propertyFile.getParentPath();
			File oldDbDir = getDataDir();
			String oldName = getName();

			propertyFile.moveTo(newFolder, newStorageName, newFolderPath, newName);
			boolean success = false;
			try {
				File newDbDir = getDataDir();
				if (useDataDir && !newDbDir.equals(oldDbDir)) {
					if (newDbDir.exists()) {
						throw new DuplicateFileException(getName() + " already exists");
					}
					else if (!oldDbDir.renameTo(newDbDir)) {
						throw new FileInUseException(getName() + " is in use");
					}
				}
				success = true;
			}
			finally {
				if (!success) {
					propertyFile.moveTo(oldFolder, oldStorageName, oldPath, oldName);
				}
			}
		}
	}

	/**
	 * @see ghidra.framework.store.FolderItem#getContentType()
	 */
	@Override
	public String getContentType() {
		return propertyFile.getString(CONTENT_TYPE, null);
	}

	/**
	 * @see ghidra.framework.store.FolderItem#getFileID()
	 */
	@Override
	public String getFileID() {
		return propertyFile.getFileID();
	}

	/**
	 * @see ghidra.framework.store.FolderItem#resetFileID()
	 */
	@Override
	public String resetFileID() throws IOException {
		String fileId = FileIDFactory.createFileID();
		String oldFileId = propertyFile.getFileID();
		propertyFile.setFileID(fileId);
		propertyFile.writeState();
		fileSystem.fileIdChanged(propertyFile, oldFileId);
		return fileId;
	}

	/**
	 * @see ghidra.framework.store.FolderItem#getName()
	 */
	@Override
	public String getName() {
		return propertyFile.getName();
	}

//	/**
//	 * Change the name of this item's property file and hidden data directory
//	 * based upon the new item name.
//	 * If in-use files prevent renaming a FileInUseException will be thrown.
//	 * @param name new name for this item
//	 * @throws InvalidNameException invalid name was specified
//	 * @throws IOException an error occurred
//	 */
//	void doSetName(String name) throws InvalidNameException, IOException {
//		synchronized (fileSystem) {
//			File oldDbDir = getDataDir();
//			String oldName = getName();
//
//			boolean success = false;
//			try {
//				propertyFile.setName(name);
//				File newDbDir = getDataDir();
//				if (useDataDir) {
//					if (newDbDir.exists()) {
//						throw new DuplicateFileException(getName() + " already exists");
//					}
//					else if (!oldDbDir.renameTo(newDbDir)) {
//						throw new FileInUseException(oldName + " is in use");
//					}
//				}
//				success = true;
//			}
//			finally {
//				if (!success && !propertyFile.getName().equals(oldName)) {
//					propertyFile.setName(oldName);
//				}
//			}
//		}
//	}

	/**
	 * @see ghidra.framework.store.FolderItem#getParentPath()
	 */
	@Override
	public String getParentPath() {
		synchronized (fileSystem) {
			return propertyFile.getParentPath();
		}
	}

	/**
	 * @see ghidra.framework.store.FolderItem#getPathName()
	 */
	@Override
	public String getPathName() {
		synchronized (fileSystem) {
			return propertyFile.getPath();
		}
	}

	/**
	 * @see ghidra.framework.store.FolderItem#isCheckedOut()
	 */
	@Override
	public boolean isCheckedOut() {
		if (isVersioned) {
			throw new UnsupportedOperationException(
				"isCheckedOut is not applicable to versioned item");
		}
		return (getCheckoutId() != DEFAULT_CHECKOUT_ID);
	}

	@Override
	public boolean isCheckedOutExclusive() {
		if (isVersioned) {
			throw new UnsupportedOperationException(
				"isCheckedOutExclusive is not applicable to versioned item");
		}
		synchronized (fileSystem) {
			if (propertyFile.getLong(CHECKOUT_ID, DEFAULT_CHECKOUT_ID) != DEFAULT_CHECKOUT_ID) {
				return propertyFile.getBoolean(EXCLUSIVE_CHECKOUT, false);
			}
		}
		return false;
	}

	/**
	 * @see ghidra.framework.store.FolderItem#isVersioned()
	 */
	@Override
	public boolean isVersioned() throws IOException {
		return fileSystem.isVersioned();
	}

	/**
	 * @see ghidra.framework.store.FolderItem#getVersions()
	 */
	@Override
	public synchronized Version[] getVersions() throws IOException {
		synchronized (fileSystem) {
			if (!isVersioned) {
				throw new UnsupportedOperationException(
					"Non-versioned item does not support getVersions");
			}
			return historyMgr.getVersions();
		}
	}

	/**
	 * @see ghidra.framework.store.FolderItem#lastModified()
	 */
	@Override
	public long lastModified() {
		return lastModified;
	}

	/**
	 * @see ghidra.framework.store.FolderItem#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return propertyFile.getBoolean(READ_ONLY, false);
	}

	/**
	 * @see ghidra.framework.store.FolderItem#setReadOnly(boolean)
	 */
	@Override
	public void setReadOnly(boolean state) throws IOException {
		if (isVersioned) {
			throw new IOException("Versioned item does not support read-only property");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			synchronized (this) {
				propertyFile.putBoolean(READ_ONLY, state);
				propertyFile.writeState();
			}
			fireItemChanged();
		}
	}

	@Override
	public int getContentTypeVersion() {
		return propertyFile.getInt(CONTENT_TYPE_VERSION, 1);
	}

	@Override
	public void setContentTypeVersion(int version) throws IOException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			synchronized (this) {
				propertyFile.putInt(CONTENT_TYPE_VERSION, version);
				propertyFile.writeState();
			}
			fireItemChanged();
		}
	}

	@Override
	public ItemCheckoutStatus checkout(CheckoutType checkoutType, String user, String projectPath)
			throws IOException {
		if (!isVersioned) {
			throw new UnsupportedOperationException("Non-versioned item does not support checkout");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {

			ItemCheckoutStatus coStatus =
				checkoutMgr.newCheckout(checkoutType, 
						user, getCurrentVersion(), projectPath);
			if (checkoutType != CheckoutType.NORMAL && coStatus != null && getFileID() == null) {
				// Establish missing fileID for on exclusive checkout
				resetFileID();
			}
			return coStatus;
		}
	}

	@Override
	public void terminateCheckout(long checkoutId, boolean notify) throws IOException {
		if (!isVersioned) {
			throw new UnsupportedOperationException("Non-versioned item does not support checkout");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			ItemCheckoutStatus coStatus = checkoutMgr.getCheckout(checkoutId);
			if (coStatus == null) {
				throw new IOException("Invalid checkout ID");
			}
			if (checkoutId == checkinId) {
				throw new IOException("Checkin is in-progress");
			}
			checkoutMgr.endCheckout(checkoutId);
		}
		if (notify) {
			fireItemChanged();
		}
	}

	@Override
	public ItemCheckoutStatus getCheckout(long checkoutId) throws IOException {
		synchronized (fileSystem) {
			if (!isVersioned) {
				throw new UnsupportedOperationException(
					"Non-versioned item does not support checkout");
			}
			return checkoutMgr.getCheckout(checkoutId);
		}
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		synchronized (fileSystem) {
			if (!isVersioned) {
				throw new UnsupportedOperationException(
					"Non-versioned item does not support checkout");
			}
			return checkoutMgr.getAllCheckouts();
		}
	}

	@Override
	public long getCheckoutId() {
		synchronized (fileSystem) {
			if (isVersioned) {
				throw new UnsupportedOperationException(
					"getCheckoutId is not applicable to versioned item");
			}
			return propertyFile.getLong(CHECKOUT_ID, DEFAULT_CHECKOUT_ID);
		}
	}

	@Override
	public int getCheckoutVersion() throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				throw new UnsupportedOperationException(
					"getCheckoutVersion is not applicable to versioned item");
			}
			return propertyFile.getInt(CHECKOUT_VERSION, -1);
		}
	}

	@Override
	public int getLocalCheckoutVersion() {
		synchronized (fileSystem) {
			if (isVersioned) {
				throw new UnsupportedOperationException(
					"getLocalCheckoutVersion is not applicable to versioned item");
			}
			return propertyFile.getInt(LOCAL_CHECKOUT_VERSION, -1);
		}
	}

	@Override
	public void setCheckout(long checkoutId, boolean exclusive, int checkoutVersion,
			int localVersion) throws IOException {
		if (isVersioned) {
			throw new UnsupportedOperationException(
				"setCheckout is not applicable to versioned item");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}

		synchronized (fileSystem) {
			if (checkoutId <= 0 || checkoutVersion <= 0 || localVersion < 0) {
				throw new IllegalArgumentException("Bad checkout data: " + checkoutId + "," +
					checkoutVersion + "," + localVersion);
			}
			propertyFile.putLong(CHECKOUT_ID, checkoutId);
			propertyFile.putBoolean(EXCLUSIVE_CHECKOUT, exclusive);
			propertyFile.putInt(CHECKOUT_VERSION, checkoutVersion);
			propertyFile.putInt(LOCAL_CHECKOUT_VERSION, localVersion);
			propertyFile.writeState();

			fireItemChanged();
		}
	}

	@Override
	public void clearCheckout() throws IOException {
		if (isVersioned) {
			throw new UnsupportedOperationException(
				"clearCheckout is not applicable to versioned item");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			propertyFile.putLong(CHECKOUT_ID, DEFAULT_CHECKOUT_ID);
			propertyFile.putBoolean(EXCLUSIVE_CHECKOUT, false);
			propertyFile.putInt(CHECKOUT_VERSION, -1);
			propertyFile.putInt(LOCAL_CHECKOUT_VERSION, -1);
			propertyFile.writeState();

			fireItemChanged();
		}
	}

	/**
	 * Returns the appropriate instantiation of a LocalFolderItem 
	 * based upon a specified property file which resides within a
	 * LocalFileSystem.
	 * @param fileSystem local file system which contains property file
	 * @param propertyFile property file which identifies the folder item.
	 * @return folder item
	 */
	static LocalFolderItem getFolderItem(LocalFileSystem fileSystem, PropertyFile propertyFile) {
		int fileType = propertyFile.getInt(FILE_TYPE, UNKNOWN_FILE_TYPE);
		try {
			if (fileType == DATAFILE_FILE_TYPE) {
				return new LocalDataFile(fileSystem, propertyFile);
			}
			else if (fileType == DATABASE_FILE_TYPE) {
				return new LocalDatabaseItem(fileSystem, propertyFile);
			}
		}
		catch (FileNotFoundException e) {
			log.error("Item may be corrupt due to missing file: " + propertyFile.getPath(), e);
		}
		catch (IOException e) {
			log.error("Item may be corrupt: " + propertyFile.getPath(), e);
		}
		return new UnknownFolderItem(fileSystem, propertyFile);
	}

	@Override
	public boolean hasCheckouts() {
		synchronized (fileSystem) {
			if (isVersioned) {
				try {
					return checkoutMgr.isCheckedOut();
				}
				catch (IOException e) {
					Msg.error(getName() + " versioning error", e);
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public boolean isCheckinActive() {
		synchronized (fileSystem) {
			if (isVersioned) {
				return checkinId != DEFAULT_CHECKOUT_ID;
			}
			return false;
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof LocalFolderItem) {
			return propertyFile.equals(((LocalFolderItem) obj).propertyFile);
		}
		return false;
	}

	/**
	 * Update this non-versioned item with the latest version of the specified versioned item.
	 * @param versionedFolderItem versioned item which corresponds to this
	 * non-versioned item.
	 * @param updateItem if true this items content is updated using the versionedFolderItem
	 * @param monitor progress monitor for update 
	 * @throws IOException if this file is not a checked-out non-versioned file 
	 * or an IO error occurs.
	 * @throws CancelledException if monitor cancels operation
	 */
	public abstract void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Update this non-versioned item with the contents of the specified item which must be 
	 * within the same non-versioned fileSystem.  If successful, the specified item will be 
	 * removed after its content has been moved into this item.
	 * @param item
	 * @param checkoutVersion
	 * @throws IOException if this file is not a checked-out non-versioned file 
	 * or an IO error occurs.
	 */
	public abstract void updateCheckout(FolderItem item, int checkoutVersion) throws IOException;

	@Override
	public void updateCheckoutVersion(long checkoutId, int checkoutVersion, String user)
			throws IOException {
		if (!isVersioned) {
			throw new UnsupportedOperationException(
				"updateCheckoutVersion is not applicable to non-versioned item");
		}
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			ItemCheckoutStatus checkout = getCheckout(checkoutId);
			if (checkout == null || !checkout.getUser().equals(user)) {
				throw new IOException("Checkout not found");
			}
			checkoutMgr.updateCheckout(checkoutId, checkoutVersion);
		}
	}
}
