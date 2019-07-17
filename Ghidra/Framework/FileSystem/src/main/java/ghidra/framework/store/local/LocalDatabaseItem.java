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

import java.io.File;
import java.io.IOException;

import db.buffers.*;
import ghidra.framework.store.*;
import ghidra.framework.store.db.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LocalDatabaseItem</code> provides a FolderItem implementation
 * for a local database.  This item wraps an underlying VersionedDatabase
 * if the file-system is versioned, otherwise a PrivateDatabase is wrapped.
 * <p>
 * This item utilizes a data directory for storing all files relating to the
 * database as well as history and checkout data files if this item is versioned.
 */
public class LocalDatabaseItem extends LocalFolderItem implements DatabaseItem {

	private PrivateDatabase privateDb;
	private VersionedDatabase versionedDb;
	private LocalVersionedDbListener versionedDbListener;

	private String deleteUser;

	/**
	 * Constructor for a new or existing local database item which corresponds to the specified 
	 * property file.  
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @param create if true the data directory will be created
	 * @throws IOException
	 */
	private LocalDatabaseItem(LocalFileSystem fileSystem, PropertyFile propertyFile, boolean create)
			throws IOException {
		super(fileSystem, propertyFile, true, create);
		if (isVersioned) {
			versionedDbListener = new LocalVersionedDbListener();
		}
	}

	/**
	 * Constructor for an existing local database item which corresponds to the specified 
	 * property file.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 */
	LocalDatabaseItem(LocalFileSystem fileSystem, PropertyFile propertyFile) throws IOException {
		super(fileSystem, propertyFile, true, false);

		if (isVersioned) {
			versionedDbListener = new LocalVersionedDbListener();
			versionedDb = new VersionedDatabase(getDataDir(), versionedDbListener);
			versionedDb.setSynchronizationObject(fileSystem);
		}
		else {
			privateDb = new PrivateDatabase(getDataDir());
			privateDb.setIsCheckoutCopy(isCheckedOut());
			privateDb.setSynchronizationObject(fileSystem);
		}
	}

	/**
	 * Create a new local Database item which corresponds to the specified 
	 * property file.  The initial contents of the database are copied from the
	 * specified srcFile.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @param srcFile open source Database buffer file
	 * @param contentType user content type
	 * @param fileID unique file ID
	 * @param comment if versioned, comment used for version 1 history data
	 * @param resetDatabaseId if true database ID will be reset for new Database
	 * @param monitor copy progress monitor
	 * @param user if versioned, user used for permission check and history data
	 * @throws IOException if error occurs
	 * @throws CancelledException if database creation cancelled by user
	 */
	LocalDatabaseItem(LocalFileSystem fileSystem, PropertyFile propertyFile, BufferFile srcFile,
			String contentType, String fileID, String comment, boolean resetDatabaseId,
			TaskMonitor monitor, String user) throws IOException, CancelledException {
		super(fileSystem, propertyFile, true, true);

		boolean success = false;
		long checkoutId = DEFAULT_CHECKOUT_ID;
		try {
			if (fileID != null) {
				String oldFileId = propertyFile.getFileID();
				propertyFile.setFileID(fileID);
				fileSystem.fileIdChanged(propertyFile, oldFileId);
			}
			propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
			propertyFile.putBoolean(READ_ONLY, false);
			propertyFile.putString(CONTENT_TYPE, contentType);

			if (isVersioned) {
				ItemCheckoutStatus coStatus = checkout(CheckoutType.NORMAL, user, null);
				checkoutId = coStatus.getCheckoutId();
				beginCheckin(checkoutId);
				versionedDbListener = new LocalVersionedDbListener();
				versionedDb = new VersionedDatabase(getDataDir(), srcFile, versionedDbListener,
					checkoutId, comment, monitor);
				versionedDb.setSynchronizationObject(fileSystem);
				terminateCheckout(checkoutId, false);
			}
			else {
				privateDb = new PrivateDatabase(getDataDir(), srcFile, resetDatabaseId, monitor);
				privateDb.setIsCheckoutCopy(isCheckedOut());
				privateDb.setSynchronizationObject(fileSystem);
			}

			propertyFile.writeState();
			success = true;
		}
		finally {
			if (!success) {
				if (isVersioned) {
					endCheckin(checkoutId);
				}
				abortCreate();
			}
		}
		fireItemCreated();
	}

	/**
	 * Create a new local Database item which corresponds to the specified 
	 * property file.  The initial contents of the database are copied from the
	 * specified packedFile.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @param packedFile packed database file
	 * @param contentType user content type
	 * @param monitor copy progress monitor
	 * @param user if versioned, user used for permission check and history data
	 * @throws IOException if error occurs
	 * @throws CancelledException if database creation cancelled by user
	 */
	LocalDatabaseItem(LocalFileSystem fileSystem, PropertyFile propertyFile, File packedFile,
			String contentType, TaskMonitor monitor, String user)
			throws IOException, CancelledException {
		super(fileSystem, propertyFile, true, true);

		if (isVersioned) {
			// no supported use case
			throw new UnsupportedOperationException();
		}

		boolean success = false;
		long checkoutId = DEFAULT_CHECKOUT_ID;
		try {
			propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
			propertyFile.putBoolean(READ_ONLY, false);
			propertyFile.putString(CONTENT_TYPE, contentType);

			String oldFileId = propertyFile.getFileID();
			propertyFile.setFileID(FileIDFactory.createFileID());
			fileSystem.fileIdChanged(propertyFile, oldFileId);

//			if (isVersioned) { 
// unsupported operation
//				ItemCheckoutStatus coStatus = checkout(false, user, null);
//				checkoutId = coStatus.getCheckoutId();
//				beginCheckin(checkoutId);
//				String comment = "Unpacked " + packedFile;
//				versionedDbListener = new LocalVersionedDbListener();
//				versionedDb =
//					new VersionedDatabase(getDataDir(), packedFile, versionedDbListener, checkoutId, comment,
//						monitor);
//				versionedDb.setSynchronizationObject(fileSystem);
//				terminateCheckout(checkoutId, false);
//			}
//			else {
			privateDb = new PrivateDatabase(getDataDir(), packedFile, monitor);
			privateDb.setIsCheckoutCopy(isCheckedOut());
			privateDb.setSynchronizationObject(fileSystem);
//			}

			propertyFile.writeState();
			success = true;
		}
		finally {
			if (!success) {
				if (isVersioned) {
					endCheckin(checkoutId);
				}
				abortCreate();
			}
		}
		fireItemCreated();
	}

	/**
	 * Create a new LocalDatabaseItem and an empty updateable BufferFile which may be used
	 * to create the initial database content.
	 *  @param fileSystem file system
	 * @param propertyFile database property file
	 * @param bufferSize buffer size to be used for new database
	 * @param contentType user content type
	 * @param fileID unique file ID or null
	 * @param user if versioned, user used for permission check and history data
	 * @param projectPath path of project in versioned database checkout is done (may be null for non-versioned database)
	 * @return open updateable empty BufferFile for initial content writing
	 * @throws IOException if error occurs
	 */
	static LocalManagedBufferFile create(final LocalFileSystem fileSystem,
			PropertyFile propertyFile, int bufferSize, String contentType, String fileID,
			String user, String projectPath) throws IOException {

		final LocalDatabaseItem dbItem = new LocalDatabaseItem(fileSystem, propertyFile, true);
		File dbDir = dbItem.getDataDir();

		long checkoutId = DEFAULT_CHECKOUT_ID;
		boolean success = false;
		try {
			if (fileID != null) {
				String oldFileId = propertyFile.getFileID();
				propertyFile.setFileID(fileID);
				fileSystem.fileIdChanged(propertyFile, oldFileId);
			}
			propertyFile.putInt(FILE_TYPE, DATABASE_FILE_TYPE);
			propertyFile.putBoolean(READ_ONLY, false);
			propertyFile.putString(CONTENT_TYPE, contentType);

			LocalManagedBufferFile bfile;
			if (fileSystem.isVersioned()) {
				ItemCheckoutStatus coStatus =
					dbItem.checkout(CheckoutType.NORMAL, user, projectPath);
				checkoutId = coStatus.getCheckoutId();
				dbItem.beginCheckin(checkoutId);
				bfile = VersionedDatabase.createVersionedDatabase(dbDir, bufferSize,
					dbItem.versionedDbListener, checkoutId);
			}
			else {
				bfile = PrivateDatabase.createDatabase(dbDir, (db, version) -> {
					synchronized (fileSystem) {
						if (version == 1) {
							if (dbItem.privateDb == null) {
								db.setSynchronizationObject(dbItem.fileSystem);
								dbItem.privateDb = (PrivateDatabase) db;
							}
							dbItem.fireItemCreated();
						}
					}
				}, bufferSize);
			}

			propertyFile.writeState();
			success = true;
			return bfile;
		}
		finally {
			if (!success) {
				if (fileSystem.isVersioned()) {
					dbItem.endCheckin(checkoutId);
				}
				dbItem.abortCreate();
			}
		}
	}

	@Override
	public long length() throws IOException {
		if (isVersioned) {
			return versionedDb.length();
		}
		return privateDb.length();
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#moveTo(java.io.File, java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	void moveTo(File newFolder, String newStorageName, String newFolderPath, String newName)
			throws IOException {
		super.moveTo(newFolder, newStorageName, newFolderPath, newName);
		if (isVersioned) {
			versionedDb.dbMoved(getDataDir());
		}
		else {
			privateDb.dbMoved(getDataDir());
		}
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#fireItemChanged()
	 */
	@Override
	void fireItemChanged() {
		if (privateDb != null) {
			privateDb.setIsCheckoutCopy(isCheckedOut());
		}
		super.fireItemChanged();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCurrentVersion()
	 */
	@Override
	public int getCurrentVersion() {
		if (isVersioned) {
			return versionedDb != null ? versionedDb.getCurrentVersion() : 0;
		}
		return privateDb != null ? privateDb.getCurrentVersion() : 0;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getMinimumVersion()
	 */
	@Override
	public int getMinimumVersion() throws IOException {
		// The database object may be null during initial database creation,
		// although such an instance is private to the static create method.
		if (isVersioned) {
			if (versionedDb == null) {
				throw new IllegalStateException();
			}
			return versionedDb.getMinimumVersion();
		}
		if (privateDb == null) {
			throw new IllegalStateException();
		}
		return privateDb.getCurrentVersion();
	}

	/**
	 * <code>LocalVersionedDbListener</code> provides a listener 
	 * which maintains checkout and history data in response to 
	 * VersionedDatabase callbacks.
	 */
	private class LocalVersionedDbListener implements VersionedDBListener {

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#versionsChanged(int, int)
		 */
		@Override
		public void versionsChanged(int minVersion, int currentVersion) {
			synchronized (fileSystem) {
				if (minVersion == 0 && currentVersion == 0) {
					// file must have been removed

				}
				try {
					if (historyMgr.fixHistory(minVersion, currentVersion)) {
						fireItemChanged();
					}
				}
				catch (IOException e) {
					Msg.error(this, "Failed to update version history: " + getPathName(), e);
				}
			}
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#versionCreated(ghidra.framework.store.db.VersionedDatabase, int, long, java.lang.String, long)
		 */
		@Override
		public boolean versionCreated(VersionedDatabase database, int version, long time,
				String comment, long dbCheckinId) {
			synchronized (fileSystem) {
				try {
					ItemCheckoutStatus coStatus = checkoutMgr.getCheckout(dbCheckinId);
					if (coStatus == null || LocalDatabaseItem.this.checkinId != dbCheckinId) {
						log("ERROR! version " + version + " created without valid checkin", null);
						return false;
					}
					if (version == 1 && versionedDb == null) {
						versionedDb = database;
						versionedDb.setSynchronizationObject(fileSystem);
					}
					String user = coStatus.getUser();
					historyMgr.versionAdded(version, time, comment, user);
					checkoutMgr.updateCheckout(dbCheckinId, version);
				}
				catch (IOException e) {
					Msg.error(getName() + " versioning error", e);
				}
			}
			if (version == 1) {
				fireItemCreated();
			}
			else {
				fireItemChanged();
			}
			return true;
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#versionDeleted(int)
		 */
		@Override
		public void versionDeleted(int version) {
			synchronized (fileSystem) {
				try {
					historyMgr.versionDeleted(version, deleteUser);
				}
				catch (IOException e) {
					Msg.error(this, "Failed to update version history: " + getPathName(), e);
				}
			}
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#getCheckoutVersion(long)
		 */
		@Override
		public int getCheckoutVersion(long checkoutId) throws IOException {
			synchronized (fileSystem) {
				ItemCheckoutStatus coStatus = checkoutMgr.getCheckout(checkoutId);
				return coStatus != null ? coStatus.getCheckoutVersion() : -1;
			}
		}

		/*
		 * @see ghidra.framework.store.db.VersionedDBListener#checkinCompleted(long)
		 */
		@Override
		public void checkinCompleted(long dbCheckinId) {
			synchronized (fileSystem) {
				if (isVersioned) {
					endCheckin(dbCheckinId);
				}
				if (versionedDb == null || versionedDb.getCurrentVersion() == 0) {
					// remove item which was created during initial creation
					try {
						if (isVersioned) {
							checkoutMgr.endCheckout(dbCheckinId);
						}
						deleteContent(null);
						fileSystem.itemDeleted(getParentPath(), getName()); // de-allocates index entry
						fileSystem.deleteEmptyVersionedFolders(getParentPath());
					}
					catch (IOException e) {
						Msg.error(this, getName() + " versioning error", e);
					}
				}
			}
		}
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#deleteMinimumVersion()
	 */
	@Override
	void deleteMinimumVersion(String user) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				deleteUser = user;
				versionedDb.deleteMinimumVersion();
			}
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
			privateDb.updateCheckoutCopy(); // removes change data
			super.clearCheckout();
		}
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#deleteCurrentVersion()
	 */
	@Override
	void deleteCurrentVersion(String user) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				deleteUser = user;
				versionedDb.deleteCurrentVersion();
			}
		}
	}

	/*
	 * @see ghidra.framework.store.DatabaseItem#open(int, int)
	 */
	@Override
	public LocalManagedBufferFile open(int version, int minChangeDataVer) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				return versionedDb.openBufferFile(version, minChangeDataVer);
			}
			if (version == LATEST_VERSION) {
				return privateDb.openBufferFile();
			}
			throw new IllegalArgumentException("only LATEST_VERSION may be opened");
		}
	}

	/*
	 * @see ghidra.framework.store.DatabaseItem#open(int)
	 */
	@Override
	public LocalManagedBufferFile open(int version) throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				return versionedDb.openBufferFile(version, -1);
			}
			if (version == LATEST_VERSION) {
				return privateDb.openBufferFile();
			}
			throw new IllegalArgumentException("only LATEST_VERSION may be opened");
		}
	}

	/*
	 * @see ghidra.framework.store.DatabaseItem#open()
	 */
	@Override
	public LocalManagedBufferFile open() throws IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				return versionedDb.openBufferFile(LATEST_VERSION, -1);
			}
			return privateDb.openBufferFile();
		}
	}

	/**
	 * Open the latest database version for update.
	 * @param checkoutId reqiured for update to a versioned item, otherwise set to -1 for
	 * a non-versioned private database.
	 * @return open database handle
	 * @throws IOException
	 */
	@Override
	public LocalManagedBufferFile openForUpdate(long checkoutId) throws IOException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			if (isVersioned) {
				beginCheckin(checkoutId);
				boolean success = false;
				try {
					LocalManagedBufferFile bfile = versionedDb.openBufferFileForUpdate(checkoutId);
					success = true;
					return bfile;
				}
				finally {
					if (!success) {
						endCheckin(checkoutId);
					}
				}
			}
			return privateDb.openBufferFileForUpdate();
		}
	}

	/**
	 * @see ghidra.framework.store.FolderItem#canRecover()
	 */
	@Override
	public boolean canRecover() {
		synchronized (fileSystem) {
			return privateDb != null && privateDb.canRecover();
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#output(java.io.File, int version, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void output(File outputFile, int version, TaskMonitor monitor)
			throws CancelledException, IOException {
		synchronized (fileSystem) {
			if (isVersioned) {
				versionedDb.output(version, outputFile, getName(), DATABASE_FILE_TYPE,
					getContentType(), monitor);
			}
			else {
				privateDb.output(outputFile, getName(), DATABASE_FILE_TYPE, getContentType(),
					monitor);
			}
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#updateCheckout(ghidra.framework.store.FolderItem, boolean, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			long checkoutId = getCheckoutId();
			boolean exclusive = isCheckedOutExclusive();
			if (isVersioned || checkoutId == DEFAULT_CHECKOUT_ID) {
				throw new IOException(getName() + " is not checked-out");
			}
			DatabaseItem verDbItem = (DatabaseItem) versionedFolderItem;
			//ItemCheckoutStatus coStatus = verDbItem.getCheckout(checkoutId);
			//int coVer = coStatus.getCheckoutVersion();

			int ver = verDbItem.getCurrentVersion();

			if (updateItem) {
				ManagedBufferFile verBf = verDbItem.open(ver);
				try {
					privateDb.updateCheckoutCopy(verBf, getCheckoutVersion(), monitor);
				}
				finally {
					try {
						verBf.close();
					}
					catch (IOException e) {
						// ignored
					}
				}
			}
			else {
				privateDb.updateCheckoutCopy();
			}
			setCheckout(checkoutId, exclusive, ver, getCurrentVersion());
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#updateCheckout(ghidra.framework.store.FolderItem, int)
	 */
	@Override
	public void updateCheckout(FolderItem item, int checkoutVersion) throws IOException {
		if (fileSystem.isReadOnly()) {
			throw new ReadOnlyException();
		}
		synchronized (fileSystem) {
			long checkoutId = getCheckoutId();
			if (isVersioned || checkoutId == DEFAULT_CHECKOUT_ID) {
				throw new IOException(getName() + " is not checked-out");
			}
			if (!(item instanceof LocalDatabaseItem)) {
				throw new IllegalArgumentException("Expected local database item");
			}
			LocalDatabaseItem dbItem = (LocalDatabaseItem) item;
			if (fileSystem != dbItem.fileSystem) {
				throw new IllegalArgumentException("Items must be from same file system");
			}
			try {
				privateDb.updateCheckoutFrom(dbItem.privateDb);
				setCheckout(checkoutId, isCheckedOutExclusive(), checkoutVersion,
					getLocalCheckoutVersion());
			}
			finally {
				item.delete(-1, null);
			}
		}
	}

	/*
	 * @see ghidra.framework.store.FolderItem#lastModified()
	 */
	@Override
	public long lastModified() {
		if (privateDb != null) {
			return privateDb.lastModified();
		}
		return versionedDb.lastModified();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#refresh()
	 */
	@Override
	public LocalFolderItem refresh() throws IOException {
		if (super.refresh() == null) {
			return null;
		}
		if (isVersioned) {
			versionedDb.refresh();
		}
		else {
			privateDb.refresh();
			privateDb.setIsCheckoutCopy(isCheckedOut());
		}
		return this;
	}

	static void cleanupOldPresaveFiles(File root) {
		Thread t = new Thread(new CleanupRunnable(root), "Database-Item-Cleanup");
		t.start();
	}

	private static class CleanupRunnable implements Runnable {
		private File root;

		CleanupRunnable(File root) {
			this.root = root;
		}

		@Override
		public void run() {

			// Determine current filesystem time
			File f;
			try {
				f = File.createTempFile("tmp", ".tmp", root);
				long now = f.lastModified();
				f.delete();

				cleanupDir(root, now);

			}
			catch (IOException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			}

		}

		private void cleanupDir(File dir, long beforeNow) {
			File[] files = dir.listFiles();
			if (files != null) {
				for (File f : files) {
					if (f.isDirectory()) {
						String fname = f.getName();
						if (!LocalFileSystem.isHiddenDirName(fname)) {
							cleanupDir(f, beforeNow);
						}
						else if (fname.endsWith(DATA_DIR_EXTENSION)) {
							LocalBufferFile.cleanupOldPreSaveFiles(f, beforeNow);
						}
					}
				}
			}
		}
	}

}
