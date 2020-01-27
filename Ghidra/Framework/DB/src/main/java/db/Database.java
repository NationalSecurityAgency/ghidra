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
package db;

import java.io.*;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import db.buffers.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.FileInUseException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>Database</code> facilitates the creation of a DBHandle for accessing
 * a database.
 * <p>
 * Public constructors are only provided for use with "Non-Versioned" databases.
 * This class should be extended when additional management features are needed, 
 * such as for a "Versioned" database.
 * <p>
 * This class assumes exclusive control of the associated files contained within the 
 * associated database directory and relies on the proper establishment of a 
 * syncObject to midigate potential concurrent modification issues.
 */
public abstract class Database {
	static final Logger log = LogManager.getLogger(Database.class);

	protected static final String DATABASE_FILE_PREFIX = "db.";
	protected static final String VERSION_FILE_PREFIX = "ver.";
	protected static final String CHANGE_FILE_PREFIX = "change.";
	protected static final String CUMULATIVE_CHANGE_FILENAME =
		CHANGE_FILE_PREFIX + "data" + LocalBufferFile.BUFFER_FILE_EXTENSION;
	protected static final String CUMULATIVE_MODMAP_FILENAME =
		CHANGE_FILE_PREFIX + "map" + LocalBufferFile.BUFFER_FILE_EXTENSION;

	protected int minVersion;
	protected int currentVersion;
	protected long lastModified;

	protected boolean isVersioned = false;
	protected boolean isCheckOutCopy = false;
	protected boolean updateAllowed = true;
	protected BufferFileManager bfMgr;

	protected File dbDir;
	protected DBFileListener dbFileListener;

	protected boolean dbDirCreated = false;

	protected Object syncObject = this;

	/**
	 * General Database Constructor.
	 * @param dbDir
	 * @param isVersioned
	 * @param create if true the database will be created.
	 * @throws IOException
	 */
	protected Database(File dbDir, boolean isVersioned, boolean create) throws IOException {
		this.dbDir = dbDir;
		this.isVersioned = isVersioned;
		if (create && !dbDir.exists()) {
			if (!dbDir.mkdirs()) {
				throw new IOException("Failed to create Database directory: " + dbDir);
			}
			dbDirCreated = true;
		}
		else {
			checkDbDir();
		}
	}

	/**
	 * Constructor for a new or existing "Non-Versioned" Database.
	 * @param dbDir
	 * @param dbFileListener file version listener
	 * @param create
	 * @throws IOException
	 */
	protected Database(File dbDir, DBFileListener dbFileListener, boolean create)
			throws IOException {
		this(dbDir, false, create);
		bfMgr = new DBBufferFileManager();
		this.dbFileListener = dbFileListener;
		scanFiles(false);
		if (create && currentVersion != 0) {
			throw new IOException("Database already exists");
		}
	}

	/**
	 * Constructor for an existing "Non-Versioned" Database.
	 * @param dbDir database directory
	 * @throws IOException
	 */
	protected Database(File dbDir) throws IOException {
		this(dbDir, false, false);
		bfMgr = new DBBufferFileManager();
		scanFiles(false);
	}

	/**
	 * Set the object to be used for synchronization.
	 * @param syncObject 
	 */
	public void setSynchronizationObject(Object syncObject) {
		this.syncObject = syncObject;
	}

	/**
	 * Returns the time at which this database was last saved.
	 */
	public long lastModified() {
		return lastModified;
	}

	/**
	 * Delete a directory and all of its contents.
	 * @param dir
	 * @return true if delete was successful.  
	 * If false is returned, a partial delete may have occurred.
	 */
	protected final static boolean deleteDir(File dir) {
		File[] flist = dir.listFiles();
		if (flist == null) {
			return false;
		}
		for (int i = 0; i < flist.length; i++) {
			if (flist[i].isDirectory()) {
				if (!deleteDir(flist[i]))
					return false;
			}
			else {
				if (!flist[i].delete())
					return false;
			}
		}
		return dir.delete();
	}

	/**
	 * Returns the version number associated with the latest buffer file version.
	 */
	public int getCurrentVersion() {
		return currentVersion;
	}

	/**
	 * Open the stored database for non-update use.
	 * The returned handle does not support the Save operation.
	 * @param monitor task monitor (may be null)
	 * @return database handle
	 * @throws FileInUseException thrown if unable to obtain the required database lock(s).
	 * @throws IOException thrown if IO error occurs.
	 * @throws CancelledException if cancelled by monitor
	 */
	public DBHandle open(TaskMonitor monitor) throws IOException, CancelledException {
		synchronized (syncObject) {
			return new DBHandle(new LocalManagedBufferFile(bfMgr, false, -1, -1));
		}
	}

	/**
	 * Open the stored database for update use.
	 * @param monitor task monitor (may be null)
	 * @return buffer file
	 * @throws FileInUseException thrown if unable to obtain the required database lock(s).
	 * @throws IOException thrown if IO error occurs.
	 * @throws CancelledException if cancelled by monitor
	 */

	public DBHandle openForUpdate(TaskMonitor monitor) throws IOException, CancelledException {
		if (!updateAllowed) {
			throw new IOException("Update use not permitted");
		}
		synchronized (syncObject) {
			return new DBHandle(new LocalManagedBufferFile(bfMgr, true, -1, -1));
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
		return bfMgr.getBufferFile(getCurrentVersion()).length();
	}

	private void checkDbDir() throws IOException {

		String[] fileList = dbDir.list();
		if (fileList == null) {
			throw new IOException("Database directory not found: " + dbDir);
		}

//		boolean bufferFileFound = false;
		boolean versionFileFound = false;

		for (int i = 0; i < fileList.length; i++) {
			// Identify files of interest
			String fname = fileList[i];
			if (fname.endsWith(LocalBufferFile.BUFFER_FILE_EXTENSION)) {
				if (fname.startsWith(DATABASE_FILE_PREFIX)) {
//					bufferFileFound = true;
				}
				else if (fname.equals(CUMULATIVE_CHANGE_FILENAME)) {
// TODO: This check is not reliable
// If the detabase is checked-out and not yet modified, this file will not yet exist
					isCheckOutCopy = true;
				}
				else if (fname.startsWith(VERSION_FILE_PREFIX)) {
					versionFileFound = true;
				}
			}
		}

//		if (!bufferFileFound) {
//			throw new IOException("Bad database directory: " + dbDir);
//		}
		if (!isVersioned && versionFileFound) {
			updateAllowed = false;
		}
		if (isVersioned && isCheckOutCopy) {
			throw new IOException("Versioned Database also appears to be a checkout copy");
		}
	}

	/**
	 * Scan files and update state.
	 */
	public void refresh() throws FileNotFoundException {
		scanFiles(false);
		if (currentVersion == 0) {
			throw new FileNotFoundException("Database files not found");
		}
	}

	/**
	 * Scan files and update state.
	 * @param repair if true files are repaired if needed.
	 */
	protected void scanFiles(boolean repair) throws FileNotFoundException {
		synchronized (syncObject) {

// TODO: May need to make repair an option (may not have write privilege)

			ArrayList<String> bufFiles = new ArrayList<>();
			ArrayList<String> verFiles = new ArrayList<>();
			ArrayList<String> changeFiles = new ArrayList<>();
			//		ArrayList delFiles = new ArrayList();

			String[] fileList = dbDir.list();
			if (fileList == null) {
				throw new FileNotFoundException(dbDir + " not found");
			}

			for (int i = 0; i < fileList.length; i++) {
				// Identify files of interest
				String fname = fileList[i];
				if (fname.endsWith(LocalBufferFile.BUFFER_FILE_EXTENSION)) {
					if (fname.startsWith(DATABASE_FILE_PREFIX)) {
						bufFiles.add(fname);
					}
					else if (fname.startsWith(VERSION_FILE_PREFIX)) {
						verFiles.add(fname);
					}
					else if (fname.startsWith(CHANGE_FILE_PREFIX)) {
						changeFiles.add(fname);
					}
					//				else {
					//					// unknown buffer file
					//					delFiles.add(fname);
					//				}
				}
				//			else if (fname.endsWith(LocalBufferFile.PRESAVE_FILE_EXT) ||
				//					fname.endsWith(LocalBufferFile.TEMP_FILE_EXT)) {
				//				// Attempt to remove all presave and temp files 
				//				// Open files on Windows will not be deleted, however they will under Unix
				// TODO This can cause problems under UNIX since it can be deleted while open
				//				delFiles.add(fname);	
				//			}
			}

			// Identify buffer files and current version - keep current version only
			int[] bufVersions = getFileVersions(bufFiles);
			currentVersion = bufVersions.length == 0 ? 0 : bufVersions[bufVersions.length - 1];
			minVersion = currentVersion;
			lastModified = bfMgr.getBufferFile(currentVersion).lastModified();

			// Remove old buffer files
			if (repair) {
				for (int i = 0; i < (bufVersions.length - 1); i++) {
					bfMgr.getBufferFile(bufVersions[i]).delete();
				}
			}
			if (isVersioned) {
				// Check version files
				int[] versions = getFileVersions(verFiles);
				boolean filesOrphaned = false;
				for (int i = versions.length - 1; i >= 0; i--) {
					if (versions[i] >= minVersion) {
						if (repair) {
							File f = bfMgr.getVersionFile(versions[i]);
							log.warn(dbDir + ": removing unexpected version file: " + f);
							f.delete();
						}
					}
					else if (versions[i] == (minVersion - 1)) {
						--minVersion;
					}
					else {
						log.warn(dbDir + ": missing version file " + (minVersion - 1));
						filesOrphaned = true;
						break;
					}
				}

				// Check change files		
				int[] changes = getFileVersions(changeFiles);
				int minChangeVer = currentVersion;
				for (int i = changes.length - 1; i >= 0; i--) {
					if (changes[i] >= minChangeVer) {
						if (repair) {
							File f = bfMgr.getChangeDataFile(changes[i]);
							log.warn(dbDir + ": removing unexpected change file: " + f);
							f.delete();
						}
					}
					else if (changes[i] == (minChangeVer - 1)) {
						--minChangeVer;
					}
					else {
						log.warn(dbDir + ": missing change file " + (minVersion - 1));
						filesOrphaned = true;
						break;
					}
				}

				if (minChangeVer > minVersion) {
					log.warn(dbDir + ": missing change files prior to " + minChangeVer);
					minVersion = minChangeVer;
					filesOrphaned = true;
				}
				if (repair && filesOrphaned) {
					log.warn(dbDir + ": versions prior to " + minVersion +
						" have been orphaned and will be removed");
					for (int i = 0; i < versions.length && versions[i] < minVersion; ++i) {
						bfMgr.getVersionFile(versions[i]).delete();
					}
					for (int i = 0; i < changes.length && changes[i] < minVersion; ++i) {
						bfMgr.getChangeDataFile(changes[i]).delete();
					}
				}
			}

			// Attempt to remove unwanted files
			//		if (repair) {
			//			int cnt = delFiles.size();
			//			for (int i = 0; i < cnt; i++) {
			//				File f = new File(dbDir, (String) delFiles.get(i));
			//				f.delete();
			//			}
			//		}
		}
	}

	private int[] getFileVersions(ArrayList<String> fileList) {
		ArrayList<Integer> list = new ArrayList<>();
		Iterator<String> iter = fileList.iterator();
		while (iter.hasNext()) {
			String fname = iter.next();
			int ix1 = fname.indexOf('.');
			int ix2 = fname.indexOf('.', ix1 + 1);
			if (ix1 < 0 || ix2 < ix1) {
				log.error(dbDir + ": bad file name: " + fname);
				continue;
			}
			String v = fname.substring(ix1 + 1, ix2);
			try {
				list.add(new Integer(v));
			}
			catch (NumberFormatException e) {
				log.error(dbDir + ": bad file name: " + fname);
			}
		}
		int[] versions = new int[list.size()];
		Iterator<Integer> versionsIter = list.iterator();
		int ix = 0;
		while (versionsIter.hasNext()) {
			versions[ix++] = versionsIter.next().intValue();
		}
		Arrays.sort(versions);
		return versions;
	}

	protected class DBBufferFileManager implements BufferFileManager {

		@Override
		public int getCurrentVersion() {
			return currentVersion;
		}

		@Override
		public File getBufferFile(int version) {
			return new File(dbDir,
				DATABASE_FILE_PREFIX + version + LocalBufferFile.BUFFER_FILE_EXTENSION);
		}

		@Override
		public File getVersionFile(int version) {
			return null;
		}

		@Override
		public File getChangeMapFile() {
			if (isCheckOutCopy) {
				return new File(dbDir, CUMULATIVE_MODMAP_FILENAME);
			}
			return null;
		}

		@Override
		public File getChangeDataFile(int version) {
			if (isCheckOutCopy) {
				return new File(dbDir, CUMULATIVE_CHANGE_FILENAME);
			}
			return null;
		}

		@Override
		public void versionCreated(int version, String comment, long checkinId)
				throws FileNotFoundException {
			synchronized (syncObject) {
				if (currentVersion != (version - 1)) {
					log.error(dbDir + ": unexpected version created (" + version +
						"), expected version " + (currentVersion + 1));
					if (version > currentVersion || version < minVersion) {
						getBufferFile(version).delete();
					}
					return;
				}

				scanFiles(true);

				if (currentVersion == 0) {
					throw new FileNotFoundException("Database files not found");
				}
				if (version != currentVersion) {
					log.error(dbDir + ": Unexpected version found (" + currentVersion +
						"), expected " + version);
				}
				else if (dbFileListener != null) {
					dbFileListener.versionCreated(Database.this, version);
				}
			}
		}

		@Override
		public void updateEnded(long checkinId) {
			// do nothing
		}

	}
}
