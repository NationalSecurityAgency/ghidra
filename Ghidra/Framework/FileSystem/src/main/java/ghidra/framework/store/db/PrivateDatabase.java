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

import db.*;
import db.buffers.*;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>PrivateDatabase</code> corresponds to a non-versioned database.
 */
public class PrivateDatabase extends Database {

	/**
	 * Constructor used to create an empty "Non-Versioned" database.
	 * @param dbDir database directory
	 * @param dbFileListener database listener which will be notified when
	 * initial version is created.
	 * @throws IOException
	 */
	private PrivateDatabase(File dbDir, DBFileListener dbFileListener) throws IOException {
		super(dbDir, dbFileListener, true);
	}

	/**
	 * Constructor for an existing "Non-Versioned" Database.
	 * @param dbDir database directory
	 * @throws IOException
	 */
	public PrivateDatabase(File dbDir) throws IOException {
		super(dbDir);
	}

	/**
	 * Construct a new Database from an existing srcFile.
	 * @param dbDir
	 * @param srcFile
	 * @param resetDatabaseId if true database ID will be reset for new Database
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	public PrivateDatabase(File dbDir, BufferFile srcFile, boolean resetDatabaseId,
			TaskMonitor monitor) throws IOException, CancelledException {
		super(dbDir, null, true);
		boolean success = false;
		LocalBufferFile newFile = null;
		try {
			newFile = new LocalManagedBufferFile(srcFile.getBufferSize(), bfMgr, -1);
			LocalBufferFile.copyFile(srcFile, newFile, null, monitor);
			newFile.close(); // causes create notification
			if (resetDatabaseId) {
				DBHandle.resetDatabaseId(bfMgr.getBufferFile(1));
			}
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
	 * Constructs a new Database from an existing packed database file.
	 * @param dbDir private database directory
	 * @param packedFile packed database storage file
	 * @param monitor
	 * @throws IOException
	 * @throws CancelledException
	 */
	public PrivateDatabase(File dbDir, File packedFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		super(dbDir, null, true);
		boolean success = false;
		try {
			PackedDatabase.unpackDatabase(bfMgr, -1, packedFile, monitor);
			DBHandle.resetDatabaseId(bfMgr.getBufferFile(1));
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
	public static LocalManagedBufferFile createDatabase(File dbDir, DBFileListener dbFileListener,
			int bufferSize) throws IOException {
		PrivateDatabase db = new PrivateDatabase(dbDir, dbFileListener);
		boolean success = false;
		try {
			LocalManagedBufferFile bfile = new LocalManagedBufferFile(bufferSize, db.bfMgr, -1);
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
	 * If this is a checked-out copy and a cumulative change file
	 * should be maintained, this method must be invoked following
	 * construction.
	 */
	public void setIsCheckoutCopy(boolean state) {
		isCheckOutCopy = state;
	}

	/**
	 * Open the current version of this database for non-update use.
	 * @return buffer file for non-update use
	 * @throws IOException
	 */
	public LocalManagedBufferFile openBufferFile() throws IOException {
		synchronized (syncObject) {
			return new LocalManagedBufferFile(bfMgr, false, -1, -1);
		}
	}

	/**
	 * Open the current version of this database for update use.
	 * @return updateable buffer file
	 * @throws IOException if updating this database file is not allowed
	 */
	public LocalManagedBufferFile openBufferFileForUpdate() throws IOException {
		if (!updateAllowed) {
			throw new IOException("Update use not permitted");
		}
		synchronized (syncObject) {
			return new LocalManagedBufferFile(bfMgr, true, -1, -1);
		}
	}

	/**
	 * Returns true if recovery data exists which may enable recovery of unsaved changes
	 * resulting from a previous crash.
	 */
	public boolean canRecover() {
		return BufferMgr.canRecover(bfMgr);
	}

	/**
	 * Following a move of the database directory,
	 * this method should be invoked if this instance will
	 * continue to be used.
	 * @param dir new database directory
	 * @throws FileNotFoundException if the database directory cannot be found
	 */
	public void dbMoved(File dir) throws FileNotFoundException {
		synchronized (syncObject) {
			this.dbDir = dir;
			refresh();
		}
	}

	/**
	 * If this is a checked-out copy, replace the buffer file content with that
	 * provided by the specified srcFile.  This Database must be a checkout copy.
	 * If a cumulative change files exists, it will be deleted following the update.
	 * @param srcFile open source data buffer file or null if current version
	 * is already up-to-date.
	 * @param oldVersion older version of srcFile from which this database originated.
	 * @throws IOException
	 * @throws CancelledException
	 */
	public void updateCheckoutCopy(ManagedBufferFile srcFile, int oldVersion, TaskMonitor monitor)
			throws CancelledException, IOException {
		if (!isCheckOutCopy) {
			throw new IOException("Database is not a checkout copy");
		}
		synchronized (syncObject) {
			if (srcFile != null) {
				boolean success = false;
				// TODO: watch-out for multiple updatable BufferFile instances
				LocalManagedBufferFile localBf = new LocalManagedBufferFile(bfMgr, true, -1, -1);
				try {
					localBf.updateFrom(srcFile, oldVersion, monitor);  // performs a save
					localBf.close();
					success = true;
				}
				finally {
					if (!success) {
						localBf.delete();
					}
				}
			}
			(new File(dbDir, CUMULATIVE_CHANGE_FILENAME)).delete();
			(new File(dbDir, CUMULATIVE_MODMAP_FILENAME)).delete();
		}
	}

	/**
	 * If a cumulative change files exists, it will be deleted.
	 * @throws IOException
	 */
	public void updateCheckoutCopy() throws IOException {
		if (!isCheckOutCopy) {
			throw new IOException("Database is not a checkout copy");
		}
		synchronized (syncObject) {
			(new File(dbDir, CUMULATIVE_CHANGE_FILENAME)).delete();
			(new File(dbDir, CUMULATIVE_MODMAP_FILENAME)).delete();
		}
	}

	/**
	 * Move the content of the otherDb into this database.
	 * The otherDb will no longer exist if this method is successful.
	 * If already open for update, a save should not be done or the database
	 * may become corrupted.  All existing handles should be closed and reopened
	 * when this method is complete.
	 * @param otherDb the other database.
	 * @throws IOException if an IO error occurs.  An attempt will be made to restore
	 * this database to its original state, however the otherDb will not be repaired
	 * and may become unusable.
	 */
	public void updateCheckoutFrom(PrivateDatabase otherDb) throws IOException {
		if (!isCheckOutCopy) {
			throw new IOException("Database is not a checkout copy");
		}
		synchronized (syncObject) {

			int newVersion = currentVersion + 1;
			File otherBufFile = otherDb.bfMgr.getBufferFile(otherDb.currentVersion);
			File otherChangeFile = new File(otherDb.dbDir, CUMULATIVE_CHANGE_FILENAME);
			File otherMapFile = new File(otherDb.dbDir, CUMULATIVE_MODMAP_FILENAME);
			File newBufFile = bfMgr.getBufferFile(newVersion);
			File changeFile = new File(dbDir, CUMULATIVE_CHANGE_FILENAME);
			File mapFile = new File(dbDir, CUMULATIVE_MODMAP_FILENAME);
			File backupChangeFile = new File(dbDir, CUMULATIVE_CHANGE_FILENAME + ".bak");
			File backupMapFile = new File(dbDir, CUMULATIVE_MODMAP_FILENAME + ".bak");

			backupMapFile.delete();
			backupChangeFile.delete();

			if (!otherBufFile.exists()) {
				throw new IOException("Update file not found");
			}
			if (newBufFile.exists() || !otherBufFile.renameTo(newBufFile)) {
				throw new IOException("Concurrent database modification error (1)");
			}

			boolean success = false;
			try {
				if (mapFile.exists() && !mapFile.renameTo(backupMapFile)) {
					throw new IOException("Concurrent database modification error (2)");
				}
				if (changeFile.exists() && !changeFile.renameTo(backupChangeFile)) {
					throw new IOException("Concurrent database modification error (3)");
				}
				if (!otherMapFile.renameTo(mapFile) || !otherChangeFile.renameTo(changeFile)) {
					throw new IOException("Concurrent database modification error (4)");
				}
				currentVersion = newVersion;
				lastModified = newBufFile.lastModified();
				success = true;
			}
			finally {
				if (!success) {
					newBufFile.delete();
					mapFile.delete();
					backupMapFile.renameTo(mapFile);
					changeFile.delete();
					backupChangeFile.renameTo(changeFile);
				}
				else {
					backupChangeFile.delete();
					backupMapFile.delete();
				}
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
	public void output(File outputFile, String name, int filetype, String contentType,
			TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (syncObject) {
			File file = bfMgr.getBufferFile(currentVersion);
			InputStream itemIn = new BufferedInputStream(new FileInputStream(file));
			try {
				ItemSerializer.outputItem(name, contentType, filetype, file.length(), itemIn,
					outputFile, monitor);
			}
			finally {
				try {
					itemIn.close();
				}
				catch (IOException e) {
				}
			}
		}
	}

}
