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
package ghidra.framework.store.db;

import java.io.*;
import java.util.Date;
import java.util.Random;

import db.DBHandle;
import db.Database;
import db.buffers.BufferFileManager;
import db.buffers.LocalManagedBufferFile;
import generic.jar.ResourceFile;
import ghidra.framework.store.FolderItem;
import ghidra.framework.store.db.PackedDatabaseCache.CachedDB;
import ghidra.framework.store.local.*;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import utilities.util.FileUtilities;

/**
 * <code>PackedDatabase</code> provides a packed form of Database
 * which compresses a single version into a file.  
 * <br>
 * When opening a packed database, a PackedDBHandle is returned 
 * after first expanding the file into a temporary Database.
 */
public class PackedDatabase extends Database {

	/**
	 * Presence of the directory lock file will prevent the creation or
	 * modification of any packed database files contained within that directory
	 * or any sub-directory.
	 */
	public static final String READ_ONLY_DIRECTORY_LOCK_FILE = ".dbDirLock";

	private static final Random RANDOM = new Random();

	private static final String TEMPDB_PREFIX = "tmp";
	private static final String TEMPDB_EXT = ".pdb";
	private static final String TEMPDB_DIR_PREFIX =
		LocalFileSystem.HIDDEN_DIR_PREFIX + TEMPDB_PREFIX;
	private static final String TEMPDB_DIR_EXT = TEMPDB_EXT + ".db";
	private static final String UPDATE_LOCK_TYPE = "u";

	static final int LOCK_TIMEOUT = 30000;

	private static final long ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;

	private static WeakSet<PackedDatabase> pdbInstances;

	private ResourceFile packedDbFile;
	private boolean isCached;
	private String itemName;
	private String contentType;
	private LockFile packedDbLock;
	private LockFile updateLock;
	private PackedDBHandle dbHandle;
	private long dbTime;
	private boolean isReadOnly = false;

	/**
	 * Constructor for an existing packed database which will be unpacked into
	 * a temporary dbDir.
	 * @param packedDbFile existing packed database file.
	 * @throws IOException
	 */
	private PackedDatabase(ResourceFile packedDbFile) throws IOException {
		super(createDBDir(), null, true);
		this.packedDbFile = packedDbFile;
		bfMgr = new PDBBufferFileManager();
		boolean success = false;
		try {
			isReadOnly = isReadOnlyPDBDirectory(packedDbFile.getParentFile());
			if (!isReadOnly) {
				updateLock = getUpdateLock(packedDbFile.getFile(false));
				packedDbLock = getFileLock(packedDbFile.getFile(false));
			}
			readContentTypeAndName();
			addInstance(this);
			success = true;
		}
		finally {
			if (!success) {
				dispose();
			}
		}
	}

	/**
	 * Constructor for an existing packed database backed by a unpacking cache
	 * @param packedDbFile
	 * @param packedDbLock read lock, null signals read only database
	 * @param cachedDb
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	PackedDatabase(ResourceFile packedDbFile, LockFile packedDbLock, CachedDB cachedDb,
			TaskMonitor monitor) throws CancelledException, IOException {
		super(cachedDb.dbDir, null, false);
		this.packedDbFile = packedDbFile;
		this.contentType = cachedDb.contentType;
		this.itemName = cachedDb.itemName;
		this.dbTime = cachedDb.getLastModified();
		this.isCached = true;
		bfMgr = new PDBBufferFileManager();
		boolean success = false;
		try {
			this.packedDbLock = packedDbLock;
			if (packedDbLock != null) {
				updateLock = getUpdateLock(packedDbFile.getFile(false));
			}
			else {
				isReadOnly = true; // signaled by absence of lock
			}
			if (cachedDb.refreshRequired()) {
				refreshUnpacking(monitor);
			}
			addInstance(this);
			success = true;
		}
		finally {
			if (!success) {
				dispose();
			}
		}
	}

	/**
	 * Constructor for a new packed database which will be created from an 
	 * open PackedDBHandle.
	 * @param dbHandle
	 * @param packedDbFile
	 * @param itemName
	 * @param newDatabaseId database ID to be forced for new database or null to generate 
	 * new database ID
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	PackedDatabase(PackedDBHandle dbHandle, ResourceFile packedDbFile, String itemName,
			Long newDatabaseId, TaskMonitor monitor) throws CancelledException, IOException {
		super(createDBDir(), null, true);
		bfMgr = new PDBBufferFileManager();
		boolean success = false;
		try {
			this.dbHandle = dbHandle;
			this.packedDbFile = packedDbFile;
			this.itemName = itemName;
			this.contentType = dbHandle.getContentType();
			if (isReadOnlyPDBDirectory(packedDbFile.getParentFile())) {
				throw new ReadOnlyException(
					"Read-only DB directory lock, file update not allowed: " + packedDbFile);
			}
			updateLock = getUpdateLock(packedDbFile.getFile(false));
			packedDbLock = getFileLock(packedDbFile.getFile(false));

			if (packedDbFile.exists() || !updateLock.createLock(0, true)) {
				throw new DuplicateFileException(packedDbFile + " already exists");
			}

			LocalManagedBufferFile bfile = new LocalManagedBufferFile(dbHandle.getBufferSize(),
				bfMgr, FolderItem.DEFAULT_CHECKOUT_ID);
			dbHandle.saveAs(bfile, newDatabaseId, monitor);
			packDatabase(monitor);
			addInstance(this);
			success = true;
		}
		finally {
			if (!success) {
				dispose();
			}
		}
	}

	public boolean isReadOnly() {
		return isReadOnly;
	}

	/**
	 * Add new PackedDatabase instance and ensure that all non-disposed
	 * PackedDatabase instances are properly disposed when the VM shuts-down.
	 * @param pdb new instance
	 */
	private static synchronized void addInstance(PackedDatabase pdb) {
		if (pdbInstances == null) {

			pdbInstances = WeakDataStructureFactory.createCopyOnReadWeakSet();

			Thread cleanupThread = new Thread("Packed Database Disposer") {

				@Override
				public void run() {
					for (PackedDatabase pdbInstance : pdbInstances) {
						try {
							if (pdbInstance.dbHandle != null) {
								pdbInstance.dbHandle.close();
							}
							pdbInstance.dispose();
						}
						catch (Throwable t) {
							// Ignore errors
						}
					}
				}
			};
			Runtime.getRuntime().addShutdownHook(cleanupThread);
		}
		pdbInstances.add(pdb);
	}

	/**
	 * Remove a PackedDatabase instance after it has been disposed.
	 * @param pdb disposed instance
	 */
	private static synchronized void removeInstance(PackedDatabase pdb) {
		if (pdbInstances != null) {
			pdbInstances.remove(pdb);
		}
	}

	/**
	 * Get a packed database which whose unpacking will be cached if possible
	 * @param packedDbFile
	 * @param monitor
	 * @return packed database which corresponds to the specified packedDbFile
	 * @throws IOException
	 * @throws CancelledException
	 */
	public static PackedDatabase getPackedDatabase(File packedDbFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		return getPackedDatabase(packedDbFile, false, monitor);
	}

	/**
	 * Get a packed database whose unpacking may be cached if possible
	 * provided doNotCache is false.
	 * @param packedDbFile
	 * @param neverCache if true unpacking will never be cache.
	 * @param monitor
	 * @return packed database which corresponds to the specified packedDbFile
	 * @throws IOException
	 * @throws CancelledException
	 */
	public static PackedDatabase getPackedDatabase(File packedDbFile, boolean neverCache,
			TaskMonitor monitor) throws IOException, CancelledException {
		return getPackedDatabase(new ResourceFile(packedDbFile), neverCache, monitor);
	}

	/**
	 * Get a packed database whose unpacking may be cached if possible
	 * provided doNotCache is false.
	 * @param packedDbFile
	 * @param neverCache if true unpacking will never be cache.
	 * @param monitor
	 * @return packed database which corresponds to the specified packedDbFile
	 * @throws IOException
	 * @throws CancelledException
	 */
	public static PackedDatabase getPackedDatabase(ResourceFile packedDbFile, boolean neverCache,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (!neverCache && PackedDatabaseCache.isEnabled()) {
			try {
				return PackedDatabaseCache.getCache().getCachedDB(packedDbFile, monitor);
			}
			catch (IOException e) {
				Msg.warn(PackedDatabase.class,
					"PackedDatabase cache failure for: " + packedDbFile + ", " + e.getMessage());
			}
		}
		return new PackedDatabase(packedDbFile);
	}

	/**
	 * Check for the presence of directory read-only lock
	 * @param directory
	 * @return true if read-only lock exists+
	 */
	public static boolean isReadOnlyPDBDirectory(ResourceFile directory) {
		File dir = directory.getFile(false);
		if (dir == null) {
			return true;
		}
		File readOnlyLockFile = new File(dir, READ_ONLY_DIRECTORY_LOCK_FILE);
		if (!readOnlyLockFile.isFile()) {
			try {
				ResourceFile parentFile = directory.getParentFile();
				if (parentFile == null) {
					return false;
				}
				return isReadOnlyPDBDirectory(parentFile);
			}
			catch (SecurityException e) {
				// return true
			}
		}
		return true;
	}

	@Override
	protected void finalize() throws Throwable {
		dispose();
	}

	/**
	 * Free resources consumed by this object.
	 * If there is an associated database handle it will be closed.
	 */
	public void dispose() {
		if (!isCached && dbDir != null && dbDir.exists()) {
			File tmpDbDir = new File(dbDir.getParentFile(), dbDir.getName() + ".delete");
			if (!dbDir.renameTo(tmpDbDir)) {
				Msg.error(this,
					"Failed to dispose PackedDatabase - it may still be in use!\n" + packedDbFile,
					new Exception());
				return;
			}
			deleteDir(tmpDbDir);
		}
		if (dbHandle != null) {
			dbHandle = null;
			if (updateLock != null && updateLock.haveLock(true)) {
				updateLock.removeLock();
			}
		}
		if (packedDbLock != null && packedDbLock.haveLock(true)) {
			packedDbLock.removeLock();
		}
		removeInstance(this);
	}

	/**
	 * Get 8-digit random hex value for use in naming temporary files.
	 * @return random string
	 */
	static String getRandomString() {
		int num = RANDOM.nextInt();
		return StringUtilities.pad(Integer.toHexString(num).toUpperCase(), '0', 8);
	}

	/**
	 * Creates a temporary directory which will be used for storing 
	 * the unpacked database files.
	 * @return temporary database directory
	 * @throws IOException
	 */
	private static File createDBDir() throws IOException {

		File tmpDir = new File(System.getProperty("java.io.tmpdir"));
		int tries = 0;
		while (tries++ < 10) {
			File dir = new File(tmpDir, TEMPDB_DIR_PREFIX + getRandomString() + TEMPDB_DIR_EXT);
			if (dir.mkdir()) {
				return dir;
			}
		}
		throw new IOException("Unable to create temporary database");
	}

	/**
	 * Returns the update lock file for the specified packedFile.
	 * @param packedFile
	 */
	private static LockFile getUpdateLock(File packedFile) {
		return new LockFile(packedFile.getParentFile(), packedFile.getName(), UPDATE_LOCK_TYPE);
	}

	/**
	 * Returns the general lock file for the specified packedFile.
	 * @param packedFile
	 */
	static LockFile getFileLock(File packedFile) {
		return new LockFile(packedFile.getParentFile(), packedFile.getName());
	}

	/**
	 * Returns the user defined content type associated with this database.
	 */
	public String getContentType() {
		return contentType;
	}

	/**
	 * Returns the storage file associated with this packed database.
	 */
	public ResourceFile getPackedFile() {
		return packedDbFile;
	}

	/**
	 * Deletes the storage file associated with this packed database.
	 * This method should not be called while the database is open, if
	 * it is an attempt will be made to close the handle.
	 * @throws IOException
	 */
	public void delete() throws IOException {
		if (isReadOnly) {
			throw new ReadOnlyException(
				"Read-only DB directory lock, file removal not allowed: " + packedDbFile);
		}
		dispose();
		lock(updateLock, false, false);
		try {
			if (packedDbFile.exists() && !packedDbFile.delete()) {
				throw new IOException("File is in use or write protected");
			}
		}
		finally {
			updateLock.removeLock();
		}
	}

	/**
	 * Deletes the storage file associated with this packed database.
	 * @throws IOException
	 */
	public static void delete(File packedDbFile) throws IOException {
		LockFile updateLock = getUpdateLock(packedDbFile);
		lock(updateLock, false, false);
		try {
			if (packedDbFile.exists() && !packedDbFile.delete()) {
				throw new IOException("File is in use or write protected");
			}
		}
		finally {
			updateLock.removeLock();
		}
	}

	/**
	 * Obtain a lock on the packed database for reading or writing.
	 * @param lockFile general or update lock file
	 * @param wait if true, block until lock is obtained.
	 * @param hold if true, hold lock until released.
	 * @throws FileInUseException
	 */
	static void lock(LockFile lockFile, boolean wait, boolean hold) throws FileInUseException {
		if (!lockFile.createLock(wait ? LOCK_TIMEOUT : 0, hold)) {
			String msg = "File is in use - '" + lockFile + "'";
			String user = lockFile.getLockOwner();
			if (user != null) {
				msg += " by " + user;
			}
			throw new FileInUseException(msg);
		}
	}

	/**
	 * Read user content type and name from packed file.
	 * @throws IOException
	 */
	private void readContentTypeAndName() throws IOException {

		ItemDeserializer itemDeserializer = null;
		if (packedDbLock != null) {
			lock(packedDbLock, true, true);
		}
		try {
			itemDeserializer = new ItemDeserializer(packedDbFile);
			if (itemDeserializer.getFileType() != FolderItem.DATABASE_FILE_TYPE) {
				throw new IOException("Incorrect file type");
			}
			contentType = itemDeserializer.getContentType();
			itemName = itemDeserializer.getItemName();
		}
		finally {
			if (itemDeserializer != null) {
				itemDeserializer.dispose();
			}
			if (packedDbLock != null) {
				packedDbLock.removeLock();
			}
		}
	}

	/**
	 * Create a new Database with data provided by an ItemDeserializer.
	 * @param bfMgr the buffer manager for the database
	 * @param checkinId the check-in id
	 * @param packedFile the file to unpack
	 * @param monitor the task monitor
	 * @throws CancelledException
	 */
	public static void unpackDatabase(BufferFileManager bfMgr, long checkinId, File packedFile,
			TaskMonitor monitor) throws IOException, CancelledException {
		if (bfMgr.getCurrentVersion() != 0) {
			throw new IllegalStateException("Expected empty database");
		}
		refreshDatabase(bfMgr, checkinId, new ResourceFile(packedFile), monitor);
	}

	private static void refreshDatabase(BufferFileManager bfMgr, long checkinId,
			ResourceFile packedFile, TaskMonitor monitor) throws IOException, CancelledException {
		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}
		int version = bfMgr.getCurrentVersion() + 1; // should be 1 in most situations
		File file = bfMgr.getBufferFile(version);
		OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
		ItemDeserializer itemDeserializer = null;
		try {
			Msg.debug(PackedDatabase.class, "Unpacking database " + packedFile + " -> " + file);
			itemDeserializer = new ItemDeserializer(packedFile);
			itemDeserializer.saveItem(out, monitor);
			bfMgr.versionCreated(version, "Unpacked " + packedFile, checkinId);
		}
		catch (IOCancelledException e) {
			throw new CancelledException();
		}
		finally {
			if (itemDeserializer != null) {
				itemDeserializer.dispose();
			}
			try {
				out.close();
			}
			catch (IOException e) {
				// ignore
			}
		}
	}

	/**
	 * Refresh the temporary database from the packed file if it has been updated
	 * since the previous refresh.
	 * @param monitor
	 * @return True if refresh was successful or not required.
	 * False may be returned if refresh failed due to unpacked files being in use.
	 * @throws IOException
	 * @throws CancelledException
	 */
	private boolean refreshUnpacking(TaskMonitor monitor) throws CancelledException, IOException {
		monitor.setMessage("Waiting...");
		if (!dbDir.isDirectory()) {
			throw new IOException("PackedDatabase has been disposed");
		}
		if (packedDbLock != null) {
			lock(packedDbLock, true, true);
		}
		try {
			if (!packedDbFile.isFile()) {
				throw new FileNotFoundException("File not found: " + packedDbFile);
			}
			long modTime = packedDbFile.lastModified();
			if (isCached) {
				CachedDB entry = PackedDatabaseCache.getCache().getCachedDBEntry(packedDbFile);
				if (entry != null && entry.getLastModified() == modTime) {
					return true;
				}
			}
			if (dbTime == modTime) {
				return true;
			}

//			File[] files = dbDir.listFiles();
//			for (int i = 0; i < files.length; i++) {
//				if (!files[i].delete()) {
//					return false;
//				}
//			}
//			currentVersion = 0;

			monitor.setMessage("Unpacking file...");

			refreshDatabase(bfMgr, -1, packedDbFile, monitor);
			dbTime = modTime;
			if (isCached) {
				PackedDatabaseCache.getCache().updateLastModified(packedDbFile, modTime);
			}
//			currentVersion = 1;

		}
		finally {
			if (packedDbLock != null) {
				packedDbLock.removeLock();
			}
		}
		return true;
	}

	/**
	 * Serialize (i.e., pack) an open database into the specified outputFile.
	 * @param dbh open database handle
	 * @param itemName item name to associate with packed content
	 * @param contentType supported content type
	 * @param outputFile packed output file to be created
	 * @param monitor progress monitor
	 * @throws IOException
	 * @throws CancelledException if monitor cancels operation
	 */
	public static void packDatabase(DBHandle dbh, String itemName, String contentType,
			File outputFile, TaskMonitor monitor) throws CancelledException, IOException {
		synchronized (dbh) {
			if (isReadOnlyPDBDirectory(new ResourceFile(outputFile.getParentFile()))) {
				throw new ReadOnlyException(
					"Read-only DB directory lock, file creation not allowed: " + outputFile);
			}
			if (outputFile.exists()) {
				throw new DuplicateFileException(outputFile + " already exists");
			}
			boolean success = false;
			InputStream itemIn = null;
			File tmpFile = null;
			try {
				tmpFile = File.createTempFile("pack", ".tmp");
				tmpFile.delete();
				dbh.saveAs(tmpFile, false, monitor);
				itemIn = new BufferedInputStream(new FileInputStream(tmpFile));
				try {
					ItemSerializer.outputItem(itemName, contentType, FolderItem.DATABASE_FILE_TYPE,
						tmpFile.length(), itemIn, outputFile, monitor);
				}
				finally {
					try {
						itemIn.close();
					}
					catch (IOException e) {
					}
				}
				success = true;
			}
			finally {
				if (itemIn != null) {
					try {
						itemIn.close();
					}
					catch (IOException e) {
					}
				}
				tmpFile.delete();
				if (!success) {
					outputFile.delete();
				}
			}
		}
	}

	/**
	 * Create a packed file from an existing Database.
	 * @param name database name
	 * @param contentType user content type
	 * @param bfMgr buffer file manager for existing database
	 * @param version buffer file version to be packed
	 * @param outputFile packed storage file to be created
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	private static void packDatabase(String name, String contentType, File dbFile, File outputFile,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}
		monitor.setMessage("Packing file...");

		InputStream itemIn = new FileInputStream(dbFile);
		try {
			ItemSerializer.outputItem(name, contentType, FolderItem.DATABASE_FILE_TYPE,
				dbFile.length(), itemIn, outputFile, monitor);
		}
		catch (IOCancelledException e) {
			throw new CancelledException();
		}
		finally {
			try {
				itemIn.close();
			}
			catch (IOException e) {
			}
		}
	}

	/**
	 * Using the temporary unpacked database, update the packed storage file
	 * using the latest buffer file version.
	 * @param monitor
	 * @throws CancelledException
	 * @throws IOException
	 */
	void packDatabase(TaskMonitor monitor) throws CancelledException, IOException {

		if (isReadOnly || dbHandle == null || bfMgr == null || bfMgr.getCurrentVersion() == 0 ||
			!updateLock.haveLock()) {
			throw new IOException("Update not allowed");
		}
		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}
		monitor.setMessage("Waiting...");
		if (packedDbLock != null) {
			lock(packedDbLock, true, true);
		}
		try {
			File packedFile = packedDbFile.getFile(false); // if not read-only packedDbFile must be a file
			File dbFile = bfMgr.getBufferFile(bfMgr.getCurrentVersion());
			File parentFile = packedFile.getAbsoluteFile().getParentFile();
			File tmpFile = File.createTempFile(TEMPDB_PREFIX, TEMPDB_EXT, parentFile);
			Msg.debug(PackedDatabase.class, "Packing database " + dbFile + " -> " + packedFile);
			packDatabase(itemName, contentType, dbFile, tmpFile, monitor);

			File bakFile = new File(parentFile, packedFile.getName() + ".bak");
			bakFile.delete();

			long oldTime = packedFile.lastModified();

			packedFile.renameTo(bakFile);
			if (!tmpFile.renameTo(packedFile)) {
				bakFile.renameTo(packedFile);
				throw new IOException("Update failed for " + packedFile);
			}

			bakFile.delete();
			dbTime = packedFile.lastModified();

			if (oldTime == dbTime) {
				// ensure that last-modified time on file changes
				dbTime += 1000;
				packedFile.setLastModified(dbTime);
			}

			if (isCached) {
				try {
					PackedDatabaseCache.getCache().updateLastModified(packedDbFile, dbTime);
				}
				catch (IOException e) {
					Msg.warn(this, "cache update failed: " + e.getMessage());
				}
			}
		}
		finally {
			if (packedDbLock != null) {
				packedDbLock.removeLock();
			}
		}
	}

	/**
	 * <code>PDBBufferFileManager</code> removes the update lock when 
	 * the update has completed.
	 */
	private class PDBBufferFileManager extends DBBufferFileManager {

		/*
		 * @see db.buffers.BufferFileManager#updateEnded(long)
		 */
		@Override
		public void updateEnded(long checkinId) {
			dbHandle = null;
			if (updateLock != null && updateLock.haveLock(true)) {
				updateLock.removeLock();
			}
			super.updateEnded(checkinId);
		}
	}

	@Override
	public synchronized DBHandle open(TaskMonitor monitor) throws CancelledException, IOException {

		if (dbHandle != null) {
			throw new IOException("Database is already open");
		}

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		if (!refreshUnpacking(monitor)) {
			throw new IOException("Failed to unpack/refresh database - it may be in use");
		}

		LocalManagedBufferFile bfile =
			new LocalManagedBufferFile(bfMgr, false, -1, FolderItem.DEFAULT_CHECKOUT_ID);
		dbHandle = new PackedDBHandle(this, bfile);
		return dbHandle;
	}

	@Override
	public synchronized DBHandle openForUpdate(TaskMonitor monitor)
			throws CancelledException, IOException {

		if (dbHandle != null) {
			throw new IOException("Database is already open");
		}
		if (isReadOnly) {
			throw new ReadOnlyException(
				"Read-only DB directory lock, file update not allowed: " + packedDbFile);
		}

		if (monitor == null) {
			monitor = TaskMonitorAdapter.DUMMY_MONITOR;
		}

		lock(updateLock, false, true);
		boolean success = false;
		PackedDBHandle dbh;
		try {
			if (!refreshUnpacking(monitor)) {
				throw new IOException("Failed to unpack/refresh database - it may be in use");
			}

			LocalManagedBufferFile bfile =
				new LocalManagedBufferFile(bfMgr, true, -1, FolderItem.DEFAULT_CHECKOUT_ID);
			dbh = new PackedDBHandle(this, bfile);
			dbHandle = dbh;
			success = true;
		}
		finally {
			if (!success) {
				updateLock.removeLock();
			}
		}
		return dbh;
	}

	/**
	 * Attempt to remove all old temporary databases.
	 * Those still open by an existing process should 
	 * not be removed by the operating system.
	 */
	public static void cleanupOldTempDatabases() {

		File tmpDir = new File(System.getProperty("java.io.tmpdir"));
		File[] tempDbs = tmpDir.listFiles((FileFilter) file -> {
			String name = file.getName();
			if (file.isDirectory()) {
				if (name.indexOf(TEMPDB_DIR_PREFIX) == 0 && name.endsWith(TEMPDB_DIR_EXT)) {
					return true;
				}
			}
			return false;
		});
		if (tempDbs == null) {
			return;
		}

		// We really have no way of identifying an in-use unpacked database
		// so we must give lots of room before removing one (i.e., one week)
		long lastWeek = (new Date()).getTime() - ONE_WEEK_MS;

		for (File tempDb : tempDbs) {
			try {
				if (tempDb.isDirectory() && tempDb.lastModified() <= lastWeek) {
					if (FileUtilities.deleteDir(tempDb)) {
						Msg.info(PackedDatabase.class, "Removed temporary database: " + tempDb);
					}
				}
			}
			catch (Exception e) {
			}
		}

	}

}
