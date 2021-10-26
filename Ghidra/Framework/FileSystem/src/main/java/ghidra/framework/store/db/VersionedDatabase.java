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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import db.DBHandle;
import db.Database;
import db.buffers.*;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>VersionedDatabase</code> corresponds to a versioned database.
 */
public class VersionedDatabase extends Database {
	static final Logger log = LogManager.getLogger(VersionedDatabase.class);

	public final int LATEST_VERSION = -1;
	public static final long DEFAULT_CHECKOUT_ID = -1;

	/**
	 * Change listener
	 */
	protected VersionedDBListener verDBListener;

	/**
	 * General "Versioned" Database Constructor.
	 * @param dbDir
	 * @param verDBListener
	 * @param create if true an empty database will be created.
	 * @throws IOException
	 */
	private VersionedDatabase(File dbDir, VersionedDBListener verDBListener, boolean create)
			throws IOException {
		super(dbDir, true, create);
		this.verDBListener = verDBListener;
		bfMgr = new VerDBBufferFileManager();
		scanFiles(true);
		if (create && currentVersion != 0) {
			throw new IOException("Database already exists");
		}
		if (!create && currentVersion == 0) {
			throw new FileNotFoundException("Database files not found");
		}
	}

	/**
	 * Constructor for an existing "Versioned" Database.
	 * @param dbDir database directory
	 * @param verDBListener
	 * @throws IOException
	 */
	public VersionedDatabase(File dbDir, VersionedDBListener verDBListener) throws IOException {
		this(dbDir, verDBListener, false);
	}

	/**
	 * Construct a new "Versioned" Database from an existing srcFile.
	 * @param dbDir
	 * @param srcFile
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	public VersionedDatabase(File dbDir, BufferFile srcFile, VersionedDBListener verDBListener,
			long checkoutId, String comment, TaskMonitor monitor)
			throws IOException, CancelledException {
		this(dbDir, verDBListener, true);
		boolean success = false;
		LocalManagedBufferFile newFile = null;
		try {
			if (verDBListener.getCheckoutVersion(checkoutId) != 0) {
				throw new IOException("Expected checkout version of 0");
			}
			newFile = new LocalManagedBufferFile(srcFile.getBufferSize(), bfMgr, checkoutId);
			newFile.setVersionComment(comment);
			LocalBufferFile.copyFile(srcFile, newFile, null, monitor);
			newFile.close(); // causes create notification
			success = true;
		}
		finally {
			if (!success) {
				if (newFile != null) {
					newFile.delete();
				}
				if (dbDirCreated) {
					deleteDir(dbDir);
				}
			}
		}
	}

	/**
	 * Construct a new "Versioned" Database from a packed database file
	 * @param dbDir
	 * @param packedFile
	 * @param verDBListener
	 * @param checkoutId
	 * @param comment
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	public VersionedDatabase(File dbDir, File packedFile, VersionedDBListener verDBListener,
			long checkoutId, String comment, TaskMonitor monitor)
			throws IOException, CancelledException {
		this(dbDir, verDBListener, true);
		boolean success = false;
		try {
			if (verDBListener.getCheckoutVersion(checkoutId) != 0) {
				throw new IOException("Expected checkout version of 0");
			}
			PackedDatabase.unpackDatabase(bfMgr, checkoutId, packedFile, monitor);
			success = true;
		}
		finally {
			if (!success) {
				if (dbDirCreated) {
					deleteDir(dbDir);
				}
			}
		}
	}

	/**
	 * Create a new database and provide the initial buffer file for writing.
	 * @param dbDir
	 * @param bufferSize
	 * @return initial buffer file
	 * @throws IOException
	 */
	public static LocalManagedBufferFile createVersionedDatabase(File dbDir, int bufferSize,
			VersionedDBListener verDBListener, long checkoutId) throws IOException {
		VersionedDatabase db = new VersionedDatabase(dbDir, verDBListener, true);
		boolean success = false;
		try {
			LocalManagedBufferFile bfile =
				new LocalManagedBufferFile(bufferSize, db.bfMgr, checkoutId);
			success = true;
			return bfile;
		}
		finally {
			if (!success && db.dbDirCreated) {
				deleteDir(dbDir);
			}
		}
	}

	/**
	 * Returns the version number associated with the oldest buffer file version.
	 */
	public int getMinimumVersion() {
		synchronized (syncObject) {
			return minVersion;
		}
	}

	/**
	 * Returns the version number associated with the latest buffer file version.
	 */
	@Override
	public int getCurrentVersion() {
		synchronized (syncObject) {
			return currentVersion;
		}
	}

	/**
	 * Delete oldest version.
	 * @throws IOException if an error occurs or this is the only version.
	 */
	public void deleteMinimumVersion() throws IOException {
		synchronized (syncObject) {
			if (minVersion == currentVersion) {
				throw new IOException("Unable to delete last remaining version");
			}

			// Rename previous version/change files
			File versionFile = bfMgr.getVersionFile(minVersion);
			File changeFile = bfMgr.getChangeDataFile(minVersion);
			File delVersionFile =
				new File(versionFile.getParentFile(), versionFile.getName() + ".delete");
			File delChangeFile =
				new File(changeFile.getParentFile(), changeFile.getName() + ".delete");
			delVersionFile.delete();
			delChangeFile.delete();

			if (!versionFile.renameTo(delVersionFile)) {
				throw new FileInUseException("Version " + minVersion + " is in use");
			}
			else if (!changeFile.renameTo(delChangeFile)) {
				delVersionFile.renameTo(versionFile);
				throw new FileInUseException("Version " + minVersion + " is in use");
			}

			// Complete removal
			delVersionFile.delete();
			delChangeFile.delete();
			int deletedVersion = minVersion++;
			verDBListener.versionDeleted(deletedVersion);
		}
	}

	/**
	 * Delete latest version.
	 * @throws IOException if an error occurs or this is the only version.
	 */
	public void deleteCurrentVersion() throws IOException {
		synchronized (syncObject) {
			if (minVersion == currentVersion) {
				throw new IOException("Unable to delete last remaining version");
			}

			// Re-build buffer file for (currentVersion-1)
			int prevVer = currentVersion - 1;
			File prevBFile = bfMgr.getBufferFile(prevVer);
			if (!prevBFile.exists()) {
				LocalBufferFile srcBf = openBufferFile(prevVer, -1);
				try {
					srcBf.clone(prevBFile, null);
				}
				catch (CancelledException e) {
					throw new AssertException();
				}
				finally {
					try {
						srcBf.close();
					}
					catch (IOException e) {
						// ignore
					}
				}
			}

			// Rename previous version/change files
			File versionFile = bfMgr.getVersionFile(prevVer);
			File changeFile = bfMgr.getChangeDataFile(prevVer);
			File delVersionFile =
				new File(versionFile.getParentFile(), versionFile.getName() + ".delete");
			File delChangeFile =
				new File(changeFile.getParentFile(), changeFile.getName() + ".delete");
			delVersionFile.delete();
			delChangeFile.delete();

			if (!versionFile.renameTo(delVersionFile)) {
				throw new FileInUseException("Version " + prevVer + " is in use");
			}
			else if (!changeFile.renameTo(delChangeFile)) {
				delVersionFile.renameTo(versionFile);
				throw new FileInUseException("Version " + prevVer + " is in use");
			}

			// Remove current version
			if (!bfMgr.getBufferFile(currentVersion).delete()) {
				prevBFile.delete();
				delVersionFile.renameTo(versionFile);
				delChangeFile.renameTo(changeFile);
				throw new FileInUseException("Version " + currentVersion + " is in use");
			}

			// Complete removal
			delVersionFile.delete();
			delChangeFile.delete();
			int deletedVersion = currentVersion--;
			verDBListener.versionDeleted(deletedVersion);
		}
	}

	/**
	 * Open a specific version of this database for non-update use.
	 * @param version database version or LATEST_VERSION for current version
	 * @param minChangeDataVer the minimum database version whose change data
	 * should be associated with the returned buffer file.  A value of -1 indicates that
	 * change data is not required.
	 * @return buffer file for non-update use.
	 * @throws IOException
	 */
	public LocalManagedBufferFile openBufferFile(int version, int minChangeDataVer)
			throws IOException {
		synchronized (syncObject) {
			if (version != LATEST_VERSION && (version > currentVersion || version < minVersion)) {
				throw new FileNotFoundException(
					"Version " + version + " not available for " + dbDir);
			}
			if (version == currentVersion || version == LATEST_VERSION) {
				return new LocalManagedBufferFile(bfMgr, false, minChangeDataVer,
					DEFAULT_CHECKOUT_ID);
			}
			return new LocalManagedBufferFile(bfMgr, version, minChangeDataVer);
		}
	}

	/**
	 * Open a specific version of the stored database for non-update use.
	 * The returned handle does not support the Save operation.
	 * @param version database version
	 * @param monitor task monitor (may be null)
	 * @return database handle
	 * @throws FileInUseException thrown if unable to obtain the required database lock(s).
	 * @throws IOException thrown if IO error occurs.
	 */
	public DBHandle open(int version, int minChangeDataVer, TaskMonitor monitor)
			throws IOException {
		synchronized (syncObject) {
			return new DBHandle(openBufferFile(version, minChangeDataVer));
		}
	}

	/*
	 * @see db.Database#openForUpdate(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public DBHandle openForUpdate(TaskMonitor monitor) throws IOException {
		throw new UnsupportedOperationException();
	}

	/**
	 * Open the current version of this database for update use.
	 * @param checkoutId checkout ID
	 * @return updateable buffer file
	 * @throws IOException if update not permitted or other error occurs
	 */
	public LocalManagedBufferFile openBufferFileForUpdate(long checkoutId) throws IOException {
		if (!updateAllowed) {
			throw new IOException("Update use not permitted");
		}
		synchronized (syncObject) {
			int minChangeDataVer = verDBListener.getCheckoutVersion(checkoutId);
			if (minChangeDataVer < 0) {
				throw new IOException("Checkout not found");
			}
			return new LocalManagedBufferFile(bfMgr, true, minChangeDataVer, checkoutId);
		}
	}

	/**
	 * Following a move of the database directory,
	 * this method should be invoked if this instance will
	 * continue to be used.
	 * @param dbDir new database directory
	 */
	public void dbMoved(File dbDir) throws FileNotFoundException {
		synchronized (syncObject) {
			this.dbDir = dbDir;
			refresh();
		}
	}

	/**
	 * Scan files and update state.
	 * @param repair if true files are repaired if needed.
	 */
	@Override
	protected void scanFiles(boolean repair) throws FileNotFoundException {
		synchronized (syncObject) {
			super.scanFiles(repair);
			if (currentVersion != 0 && repair) {
				verDBListener.versionsChanged(minVersion, currentVersion);
			}
		}
	}

	/**
	 * Output the current version of this database to a packed storage file.
	 * @param outputFile packed storage file to be written
	 * @param name database name
	 * @param filetype application file type
	 * @param contentType user content type
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	public void output(int version, File outputFile, String name, int filetype, String contentType,
			TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (syncObject) {
			if (outputFile.exists()) {
				throw new DuplicateFileException(outputFile.getName() + " already exists");
			}
			if (version == LATEST_VERSION || version == currentVersion) {
				File file = bfMgr.getBufferFile(currentVersion);
				InputStream itemIn = new BufferedInputStream(new FileInputStream(file));
				boolean success = false;
				try {
					ItemSerializer.outputItem(name, contentType, filetype, file.length(), itemIn,
						outputFile, monitor);
					success = true;
				}
				finally {
					try {
						itemIn.close();
					}
					catch (IOException e) {
					}
					if (!success) {
						outputFile.delete();
					}
				}
			}
			else {
				BufferFile bf = openBufferFile(version, -1);
				try {
					File tmpFile = File.createTempFile("ghidra", LocalBufferFile.TEMP_FILE_EXT);
					tmpFile.delete();
					BufferFile tmpBf = new LocalBufferFile(tmpFile, bf.getBufferSize());
					boolean success = false;
					try {
						LocalBufferFile.copyFile(bf, tmpBf, null, monitor);
						tmpBf.close();

						InputStream itemIn = new FileInputStream(tmpFile);
						try {
							ItemSerializer.outputItem(name, contentType, filetype, tmpFile.length(),
								itemIn, outputFile, monitor);
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
						if (!success) {
							outputFile.delete();
						}
						tmpBf.close();
						tmpFile.delete();
					}
				}
				finally {
					bf.close();
				}
			}
		}
	}

	/**
	 * <code>VerDBBufferFileManager</code> provides buffer file management
	 * for this versioned database instead of the DBBufferFileManager.
	 */
	private class VerDBBufferFileManager implements BufferFileManager {

		@Override
		public int getCurrentVersion() {
			synchronized (syncObject) {
				return currentVersion;
			}
		}

		@Override
		public File getBufferFile(int version) {
			return new File(dbDir,
				DATABASE_FILE_PREFIX + version + LocalBufferFile.BUFFER_FILE_EXTENSION);
		}

		@Override
		public File getVersionFile(int version) {
			return new File(dbDir,
				VERSION_FILE_PREFIX + version + LocalBufferFile.BUFFER_FILE_EXTENSION);
		}

		@Override
		public File getChangeDataFile(int version) {
			return new File(dbDir,
				CHANGE_FILE_PREFIX + version + LocalBufferFile.BUFFER_FILE_EXTENSION);
		}

		@Override
		public File getChangeMapFile() {
			return null;
		}

		@Override
		public void versionCreated(int version, String comment, long checkinId)
				throws FileNotFoundException {
			synchronized (syncObject) {

				File bfile = getBufferFile(version);
				long createTime = bfile.lastModified();
				if (createTime == 0) {
					log.error(dbDir + ": new version not found (" + version + ")");
					return;
				}

				if (currentVersion != (version - 1)) {
					log.error(dbDir + ": unexpected version created (" + version +
						"), expected version " + (currentVersion + 1));
					if (version > currentVersion || version < minVersion) {
						bfile.delete();
					}
					return;
				}

				if (!verDBListener.versionCreated(VersionedDatabase.this, version, createTime,
					comment, checkinId)) {
					bfile.delete();
					if (!bfile.exists()) {
						log.info(dbDir + ": version " + version + " removed");
						version = currentVersion;
					}
				}

				scanFiles(true);

				if (currentVersion == 0) {
					throw new FileNotFoundException("Database files not found");
				}
				if (version != currentVersion) {
					log.error(dbDir + ": Unexpected version found (" + currentVersion +
						"), expected " + version);
				}
			}
		}

		@Override
		public void updateEnded(long checkinId) {
			synchronized (syncObject) {
				verDBListener.checkinCompleted(checkinId);
			}
		}

	}
}
