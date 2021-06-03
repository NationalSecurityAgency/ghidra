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
package db.buffers;

import java.io.*;

import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <code>LocalManagedBufferFile</code> implements a BufferFile as block-oriented
 * random-access file which utilizes a <code>BufferFileManager</code> to 
 * identify and facilitate versioning of buffer files.  This type of
 * buffer file supports both save-as and save operations.  The file
 * format used is identical to a LocalBufferFile, although additional
 * support is provided for associated files which facilitate versioning
 * (e.g., ChangeMapFile, VersionFile, and changed data files).
 */
public class LocalManagedBufferFile extends LocalBufferFile implements ManagedBufferFile {

	/**
	 * <code>versionFileHandler</code> provides original buffer file data for 
	 * older non-updatable versions.
	 */
	private VersionFileHandler versionFileHandler;

	/**
	 * <code>versionOutFile</code> tracks changes made to a pre-save file for 
	 * reverse reconstruction.
	 */
	private VersionFile versionOutFile;

	/**
	 * <code>changeMap</code> tracks buffers which have been set.
	 */
	private ChangeMapFile changeMap;

	/**
	 * <code>version</code> indicates the version of this buffer file.  A value
	 * of 0 indicates that no version has been assigned.
	 */
	private int version = 0;

	/**
	 * <code>minChangeDataVer</code> indicates the minimum change-data version 
	 * which should be associated with this buffer file.  A value of -1 indicates
	 * that no change-data is associated with this file.  If set, the maximum 
	 * change-data version always equals this buffer file's version minus one.
	 */
	private int minChangeDataVer = -1;

	/**
	 * <code>nextChangeDataVer</code> is utilized by the getNextChangeDataFile 
	 * method in iterating through the various change-data files.
	 * @see #getNextChangeDataFile
	 */
	private int nextChangeDataVer = -1;

	/**
	 * <code>comment</code> stores the comment which will be passed to bfMgr when
	 * this new file version is stored.  This applies to writable (!readOnly) files
	 * which have bfMgr set.
	 */
	private String comment;

	//
	// A non-read-only file which has bfMgr set (i.e., open for-update) is presumed to be
	// a new version when closed.  To prevent a new version from being created,
	// the file should be marked as temporary which will force it to be removed 
	// on close. 
	//
	// A save file and the use of pre-save only occurs for when a bfMgr has been set
	// and versionUpdateEnabled was true when initially constructed.  A new save file
	// will inherit this behavior once saveCompleted has been invoked on the original
	// file.
	//

	/**
	 * <code>bfMgr</code> manages the various files associated with this buffer 
	 * file.  When working with versioned files or when Save support is 
	 * required <code>bfMgr</code> must be set.  The bufMgr will be null for
	 * a read-only non-updateable file.
	 */
	private BufferFileManager bfMgr;

	/**
	 * <code>checkinId</code> is the checkin ID needed by bfMgr when a new
	 * version is created.
	 */
	private long checkinId = -1;

	/**
	 * <code>preSaveFile</code> is a buffer file which contains a copy of
	 * this buffer file.  The <code>preSaveFile</code> object is intantiated at
	 * the start of the pre-save task (see startPreSave()).  If this object is
	 * not null and the preSaveThread is not running, the <code>preSaveFile</code>
	 * can be used as the basis of a Save operation.
	 * @see #startPreSave
	 * @see #getSaveFile
	 */
	private LocalManagedBufferFile preSaveFile;

	/**
	 * <code>saveFile</code> is the <code>preSaveFile</code> which is handed-out
	 * by the getSaveFile method.  While not null, a Save is in-progress.
	 * The saveCompleted method must be invoked to terminate a Save operation on
	 * the saveFile.
	 * @see #getSaveFile
	 * @see #saveCompleted
	 */
	private LocalManagedBufferFile saveFile;

	/**
	 * <code>saveChangeFile</code> is a buffer file which contains application
	 * specific change-data associated with a new version of this file.
	 * <code>saveChangeFile</code> is instantiated when the getSaveFile method
	 * is successfully invoked.  This file is committed when the saveCompleted
	 * method is invoked.
	 */
	private LocalBufferFile saveChangeFile;

	/**
	 * <code>preSaveFailed</code> is set true when the pre-save is successfully
	 * terminated before completion.
	 */
	private boolean preSaveFailed = false;

	/**
	 * <code>preSaveBackoff</code> is set true whenever an application read I/O
	 * operation is performed on this file.  If the pre-save process is running,
	 * setting true will cause the pre-save to backoff for a short period.
	 */
	private boolean preSaveBackoff = false;

	/**
	 * <code>preSaveLock</code> is used to arbitrate access to the preSaveBackoff flag.
	 */
	private Object preSaveLock = new Object();

	/**
	 * <code>preSaveThread</code> corresponds to the PreSaveTask which creates the 
	 * preSaveFile when this buffer file is updateable.
	 */
	//private Thread preSaveThread;
	private PreSaveTask preSaveTask;

	/**
	 * Open the initial version of a block file for writing.
	 * @param bufferSize user buffer size
	 * @param bfManager buffer file version manager
	 * @param checkinId the checkinId for creating a versioned buffer file.
	 * @throws IOException if an IO error occurs or the incorrect magicNumber
	 * was read from the file.
	 */
	public LocalManagedBufferFile(int bufferSize, BufferFileManager bfManager, long checkinId)
			throws IOException {
		super(bfManager.getBufferFile(1), bufferSize);
		if (bfManager.getCurrentVersion() != 0) {
			throw new AssertException();
		}
		this.version = 1;
		this.bfMgr = bfManager;
		this.checkinId = checkinId;
	}

	/**
	 * Open the current version of an existing block file as read-only.
	 * @param bfManager buffer file version manager
	 * @param versionUpdateEnabled if true Save support is enabled (pre-save starts automatically).
	 * @param minChangeDataVer indicates the oldest change data buffer file to be
	 * included.  A -1 indicates only the last change data buffer file is applicable.
	 * @param checkinId the checkinId for versioned buffer files which are opened for update.
	 * @throws IOException if an IO error occurs or the incorrect magicNumber
	 * was read from the file.
	 */
	public LocalManagedBufferFile(BufferFileManager bfManager, boolean versionUpdateEnabled,
			int minChangeDataVer, long checkinId) throws IOException {
		super(bfManager.getBufferFile(bfManager.getCurrentVersion()), true);
		this.bfMgr = bfManager;
		this.version = bfManager.getCurrentVersion();
		this.minChangeDataVer = minChangeDataVer;
		this.checkinId = checkinId;
		if (versionUpdateEnabled) {
			startPreSave();
		}
	}

	/**
	 * Open an older version of an existing buffer file as read-only and NOT UPDATEABLE (bfMgr remains null).
	 * Version files must exist for all versions starting with the requested version.
	 * These version files will be used in conjunction with the current buffer file
	 * to emulate an older version buffer file.
	 * @param bfManager buffer file version manager
	 * @param version version of file to be opened
	 * @param minChangeDataVer indicates the oldest change data buffer file to be
	 * included.  A -1 indicates only the last change data buffer file is applicable.
	 * @throws IOException if an IO error occurs or a problem with the version
	 * reconstruction.
	 */
	public LocalManagedBufferFile(BufferFileManager bfManager, int version, int minChangeDataVer)
			throws IOException {
		super(bfManager.getBufferFile(bfManager.getCurrentVersion()), true);
		this.version = version;
		this.minChangeDataVer = minChangeDataVer;
		int curVer = bfManager.getCurrentVersion();

		versionFileHandler = new VersionFileHandler(bfManager, getFileId(), curVer, version);

		// Use general data and free list from version files
		setFileId(versionFileHandler.getOriginalFileID());
		setBufferCount(versionFileHandler.getOriginalBufferCount());
		setFreeIndexes(versionFileHandler.getFreeIndexList());
		String[] names = versionFileHandler.getOldParameterNames();
		clearParameters();
		for (int i = 0; i < names.length; i++) {
			setParameter(names[i], versionFileHandler.getOldParameter(names[i]));
		}
	}

	/**
	 * Create a new empty file for pre-save use.
	 * @param presaveFile pre-save file
	 * @param bufferSize buffer size
	 * @throws IOException if an I/O error occurs during file creation
	 */
	private LocalManagedBufferFile(File presaveFile, int bufferSize) throws IOException {
		super(presaveFile, bufferSize);
	}

	@Override
	public BufferFile getNextChangeDataFile(boolean getFirst) throws IOException {
		if (bfMgr == null) {
			return null;
		}
		if (getFirst || nextChangeDataVer == -1) {
			nextChangeDataVer = minChangeDataVer != -1 ? minChangeDataVer : (version - 1);
		}
		if (nextChangeDataVer >= version) {
			return null;
		}
		File changedDataFile = bfMgr.getChangeDataFile(nextChangeDataVer++);
		if (changedDataFile != null && (minChangeDataVer != -1 || changedDataFile.exists())) {
			return new LocalBufferFile(changedDataFile, true);
		}
		return null;
	}

	@Override
	void putFreeBlock(int index, int nextFreeIndex) throws IOException {

		versionBufferIfNeeded(index);

		super.putFreeBlock(index, nextFreeIndex);

		if (changeMap != null) {
			changeMap.bufferChanged(index, true);
		}
	}

	/**
	 * @return version associated with this buffer file
	 */
	int getVersion() {
		return version;
	}

	@Override
	public long getCheckinID() {
		return checkinId;
	}

	@Override
	public void setVersionComment(String comment) throws IOException {
		this.comment = comment;
	}

	@Override
	public synchronized DataBuffer get(DataBuffer buf, int index) throws IOException {

		if (index > getBufferCount())
			throw new EOFException(
				"Buffer index too large (" + index + " > " + getBufferCount() + ")");

		if (versionFileHandler != null) {
			DataBuffer vbuf = versionFileHandler.getOldBuffer(buf, index);
			if (vbuf != null) {
				return vbuf;
			}
		}

		synchronized (preSaveLock) {
			preSaveBackoff = true;
		}

		return super.get(buf, index);
	}

	@Override
	public synchronized void put(DataBuffer buf, int index) throws IOException {

		if (isReadOnly())
			throw new IOException("File is read-only");
		if (index > MAX_BUFFER_INDEX)
			throw new EOFException("Buffer index too large, exceeds max-int");

		versionBufferIfNeeded(index);

		boolean empty = buf.isEmpty();

		super.put(buf, index);

		if (changeMap != null) {
			changeMap.bufferChanged(index, empty);
		}
	}

	/**
	 * Output old data for a specified buffer if required for version file.
	 * @param index buffer index
	 * @throws IOException
	 */
	private void versionBufferIfNeeded(int index) throws IOException {
		if (versionOutFile != null && versionOutFile.isPutOK(index)) {
			// Record old buffer for versioning if not empty
			DataBuffer oldBuf = new DataBuffer();
			oldBuf = get(oldBuf, index);
			if (oldBuf.data == null) {
				Msg.error(this,
					"ERROR! Unexpected condition detected in LocalBufferFile.versionBufferIfNeeded");
			}
			else {
				versionOutFile.putOldBuffer(oldBuf, index);
			}
		}
	}

	/*
	 * Commits a save file as new version and sets it to a read-only state.
	 * @see ghidra.framework.store.buffers.BufferFile#setReadOnly()
	 */
	@Override
	public synchronized boolean setReadOnly() throws IOException {

		if (!flush())
			return false;

		if (versionOutFile != null) {
			versionOutFile.close();
			versionOutFile = null;
		}
		if (changeMap != null) {
			changeMap.close();
			changeMap = null;
		}

		super.setReadOnly();

		if (bfMgr != null) {
// TODO: This seems very hidden!
			bfMgr.versionCreated(version, comment, checkinId);
			startPreSave();
		}
		return true;
	}

	@Override
	public synchronized void close() throws IOException {

		if (isClosed())
			return;

		stopPreSave(true);

		if (versionFileHandler != null) {
			versionFileHandler.close();
		}

		boolean comit = false;
		try {
			comit = flush(); // commt if raf != null && !readOnly && !temporary
			if (comit) {
				if (versionOutFile != null) {
					versionOutFile.close();
					versionOutFile = null;
				}
				if (changeMap != null) {
					changeMap.close();
					changeMap = null;
				}
			}
			super.close();
			// NOTE: the above close will delete non-read-only files which were not committed
		}
		finally {
			if (bfMgr != null) {
				if (comit) {
					bfMgr.versionCreated(version, comment, checkinId);
				}
				if (!isReadOnly() || saveFile != null) {
					bfMgr.updateEnded(checkinId);
				}
			}
			if (versionOutFile != null) {
				versionOutFile.abort();
			}
			if (changeMap != null) {
				changeMap.abort();
			}
			disposeSaveFiles();
		}
	}

	@Override
	public synchronized boolean delete() {

		if (isClosed() || isReadOnly())
			return false;

		boolean success = false;
		try {
			success = super.delete();
			if (versionOutFile != null) {
				try {
					versionOutFile.abort();
				}
				catch (IOException e1) {
					// ignored
				}
				versionOutFile = null;
			}
			if (changeMap != null) {
				changeMap.abort();
				changeMap = null;
			}
		}
		finally {
			if (bfMgr != null) {
				bfMgr.updateEnded(checkinId);
			}
		}
		return success;
	}

	private byte[] getForwardModMapData() throws IOException {
		if (bfMgr == null) {
			return null;
		}
		File mf = bfMgr.getChangeMapFile();
		if (mf == null || !mf.exists()) {
			return null;
		}
		ChangeMapFile modMap = new ChangeMapFile(mf, this);
		try {
			return modMap.getModData();
		}
		finally {
			modMap.close();
		}
	}

	@Override
	public byte[] getForwardModMapData(int oldVersion) throws IOException {
		if (bfMgr == null) {
			return null;
		}
		if (oldVersion < 1 || oldVersion >= version) {
			throw new IOException("Invalid mod-map version requested: " + oldVersion);
		}
		VersionFileHandler modMapGenerator =
			new VersionFileHandler(bfMgr, getFileId(), version, oldVersion);
		try {
			return modMapGenerator.getForwardModMapData();
		}
		finally {
			modMapGenerator.close();
		}
	}

	@Override
	public BufferFile getSaveChangeDataFile() throws IOException {
		return saveChangeFile;
	}

	private void comitSaveChangeDataFile() throws IOException {

		// Identify temporary change data file (see getSaveChangeDataFile)
		if (saveChangeFile == null || !saveChangeFile.getFile().exists()) {
			throw new FileNotFoundException("Saved change data file not found");
		}
		File changeFile = saveChangeFile.getFile();

		// Determine if we are replacing an existing change data file
		File cfile = bfMgr.getChangeDataFile(version);
		File bakFile = null;
		if (cfile.exists()) {
			// Temporarily rename old change data file
			bakFile = new File(cfile.getParentFile(), cfile.getName() + ".bak");
			if (!cfile.renameTo(bakFile)) {
				throw new IOException("Failed to update change data");
			}
		}

		// Move new change data file into place
		if (changeFile.renameTo(cfile)) {
			// Remove old change data file
			if (bakFile != null) {
				bakFile.delete();
			}
		}
		else {
			// Put old change data file back in place
			if (bakFile != null) {
				bakFile.renameTo(cfile);
			}
			throw new IOException("Failed to update change data - file may be in use");
		}
	}

	/**
	 * Create a new buffer file version (used for check-in) 
	 * @param destFile must be an versioned file representing an earlier version
	 * of srcFile.
	 * @param fileComment a comment for the new version.
	 * @param monitor the current monitor.
	 * @throws CancelledException if the operation is canceled.
	 * @throws IOException if the file is in an unexpected state.
	 */
	public void createNewVersion(ManagedBufferFile destFile, String fileComment,
			TaskMonitor monitor) throws CancelledException, IOException {

		if (monitor != null) {
			monitor.checkCanceled();
			monitor.setMessage("Opening versioned file for update...");
			monitor.setProgress(0);
		}
		ManagedBufferFile outFile = destFile.getSaveFile();
		if (outFile == null) {
			throw new IOException("File update not permitted");
		}

		boolean success = false;
		BufferFile newChangeFile = null;
		BufferFile changeDataFile = null;
		try {
			if (monitor != null) {
				monitor.checkCanceled();
				monitor.setMessage("Creating new file version...");
			}
			outFile.setVersionComment(fileComment);

			changeDataFile = getNextChangeDataFile(true);
			if (changeDataFile == null) {
				throw new IOException("Unexpected state for check-in file");
			}

			BufferFile nextChangeDataFile = getNextChangeDataFile(false);
			if (nextChangeDataFile != null) {
				nextChangeDataFile.dispose();
				throw new IOException("Unexpected state for check-in file");
			}

			// Create new version
			ChangeMap newChangeMap = new ChangeMap(getForwardModMapData());
			copyFile(this, outFile, newChangeMap, monitor);

			// Copy change data
			newChangeFile = destFile.getSaveChangeDataFile();
			copyFile(changeDataFile, newChangeFile, null, monitor);

			newChangeFile.close(); // commit and close newChangeFile
			newChangeFile = null;  // null indicates closed state

			success = true;
		}
		finally {
			if (changeDataFile != null) {
				changeDataFile.dispose();
			}
			if (newChangeFile != null) {
				newChangeFile.dispose();
			}
			try {
				destFile.saveCompleted(success);
			}
			finally {
				outFile.dispose();
			}
		}
	}

	@Override
	public synchronized ManagedBufferFile getSaveFile() throws IOException {
		try {
			return getSaveFile(TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (CancelledException e) {
			// unexpected
		}
		return null;
	}

	/**
	 * Returns a Save file if available.  Returns null if
	 * a save can not be performed.  This method may block for an extended
	 * period of time if the pre-save process has not already completed.
	 * This method does not accept a monitor since a remote TaskMonitor does
	 * not yet exist.
	 * @param monitor optional monitor for canceling pre-save (may be null)
	 * @throws IOException if an I/O error occurs
	 * @throws CancelledException if monitor specified and pre-save cancelled
	 */
	public synchronized LocalManagedBufferFile getSaveFile(TaskMonitor monitor)
			throws IOException, CancelledException {
		if (saveFile != null) {
			throw new IOException("Save already in progress");
		}
		waitForPreSave(monitor);
		saveFile = preSaveFile;
		preSaveFile = null;
		if (saveFile != null) {
			if (getBufferCount() != saveFile.getBufferCount()) {
				throw new AssertException();
			}
			File vfile = bfMgr.getVersionFile(version);
			if (vfile != null) {
				// Records changes made to pre-save file for reverse reconstruction
				// If vfile already exists, modifications will be added to it.
				saveFile.versionOutFile = new VersionFile(this, saveFile, vfile);
			}

			File mFile = bfMgr.getChangeMapFile();
			if (mFile != null) {
				// Tracks buffers written since checkout
				// If mfile already exists, modifications will be added to it.
				saveFile.changeMap = new ChangeMapFile(mFile, this, saveFile);
			}

			File changeFile = bfMgr.getChangeDataFile(version);
			if (changeFile != null) {
				changeFile =
					new File(changeFile.getParentFile(), changeFile.getName() + TEMP_FILE_EXT);
				changeFile.delete();
				saveChangeFile = new LocalBufferFile(changeFile, getBufferSize());
			}
		}
		return saveFile;
	}

	private void disposeSaveFiles() {
		if (saveChangeFile != null) {
			saveChangeFile.dispose();
			saveChangeFile = null;
		}
		if (saveFile != null) {
			saveFile.dispose();
			saveFile = null;
		}
	}

	@Override
	public synchronized void saveCompleted(boolean commit) throws IOException {
		if (saveFile == null) {
			throw new IOException("Save is not in progress");
		}
		if (!commit) {
			disposeSaveFiles();
			startPreSave();
			return;
		}

		int newVersion = version + 1;
		File newFile = bfMgr.getBufferFile(newVersion);
		boolean success = false;
		try {
			if (saveChangeFile != null) {
				saveChangeFile.close();
			}

			// Rename saveFile and enable transfer versioning settings
			if (saveFile.renameFile(newFile)) {
				saveFile.version = newVersion;
				saveFile.bfMgr = bfMgr;
				saveFile.checkinId = checkinId;

				if (saveChangeFile != null) {
					comitSaveChangeDataFile();
				}

				cleanupOldPreSaveFiles(newFile.getParentFile(), 0);

				// commits new version and starts new pre-save on saveFile
				saveFile.setReadOnly();

				success = true;
			}
		}
		finally {
			if (!success) {
				saveFile.delete();
			}
			saveFile = null;
			saveChangeFile = null;
		}
		if (!success) {
			throw new IOException("File error during save");
		}
	}

	@Override
	public synchronized boolean canSave() {
		return preSaveFile != null;
	}

	/**
	 * Initiate a background pre-save if possible.
	 * This is intended to save time for the final Save.
	 * when only a small number of changes will be made.  If an I/O error
	 * or other exception occurs during the process, the preSave will
	 * be aborted silently.
	 * @param filename name of preSave file.  The preSave file will
	 * be created within the same directory as the source file.  If this file
	 * already exists, this method will have no affect.
	 * @throws IllegalStateException if this method is invoked more than
	 * once for a given instance or a source file was not used.  This method 
	 * may be re-invoked after saveAs is invoked.
	 */
	private void startPreSave() {
		synchronized (preSaveLock) {
			try {
				preSaveTask = new PreSaveTask();
			}
			catch (Throwable t) {
				Msg.error(this, "Unexpected Exception creating Pre-save file in : " +
					getFile().getParent() + ": " + t.getMessage(), t);
				preSaveFile = null;
				preSaveTask = null;
			}
		}
	}

	/**
	 * Terminate background save if it is running.
	 * This may be unsuccessful if this thread is interupted.
	 * @param endUpdate if true and pre-save successfully terminated, 
	 * notify buffer file manager that update has ended.
	 */
	private void stopPreSave(boolean endUpdate) {

		PreSaveTask task;
		synchronized (preSaveLock) {
			task = preSaveTask;
			preSaveTask = null;
		}
		if (task != null) {
			task.cancelTask();
		}

		synchronized (this) {
			// If preSaveFile is null and !preSaveFailed - we were unsuccessful at terminating the pre-save
			if (endUpdate && bfMgr != null && (preSaveFailed || preSaveFile != null)) {

				// Update is ended when we can no longer perform a save
				bfMgr.updateEnded(checkinId);
			}

			// Remove pre-save file if it exists
			if (preSaveFile != null) {
				preSaveFile.delete();
				preSaveFile = null;
			}
		}
	}

	/**
	 * Block until pre-save thread completes
	 * @param monitor optional monitor allowing the pre-save wait to be interrupted/canceled - the actual pre-save will 
	 * continue since it may be required for a future save operation.
	 * @throws CancelledException 
	 */
	private void waitForPreSave(TaskMonitor monitor) throws CancelledException {

		PreSaveTask task;
		synchronized (preSaveLock) {
			task = preSaveTask;
		}
		if (task != null) {
			task.waitForTask(monitor);
		}
	}

	/**
	 * <code>PreSaveTask</code> facilitates the pre-saving a copy of this buffer 
	 * file for update use by a BufferMgr.
	 */
	private class PreSaveTask implements Runnable {

		private BufferFile srcFile;
		private volatile Thread taskThread;
		private Thread monitorThread;
		private TaskMonitor monitor;
		private int maxIndex;
		private int curIndex;

		PreSaveTask() throws IOException {
			File psFile = File.createTempFile(PRESAVE_FILE_PREFIX, PRESAVE_FILE_EXT,
				getFile().getParentFile());
			psFile.delete();
			srcFile = new LocalManagedBufferFile(bfMgr, false, -1, checkinId);
			preSaveFile = new LocalManagedBufferFile(psFile, getBufferSize());

			taskThread = new Thread(this, "Pre-Save");
			taskThread.setPriority(Thread.MIN_PRIORITY);
			taskThread.start();
		}

		public void cancelTask() {
			if (taskThread.isAlive()) {
				taskThread.interrupt();
				try {
					taskThread.join();
				}
				catch (InterruptedException e) {
					// ignore
				}
			}
		}

		void waitForTask(TaskMonitor taskMonitor) throws CancelledException {
			if (taskThread.isAlive()) {
				if (taskMonitor != null) {
					synchronized (preSaveLock) {
						taskMonitor.initialize(maxIndex);
						taskMonitor.setProgress(curIndex);
						this.monitor = taskMonitor;
						this.monitorThread = Thread.currentThread();
					}
				}
				try {
					taskThread.join();
				}
				catch (InterruptedException e) {
					// ignore
				}
				if (taskMonitor != null) {
					taskMonitor.checkCanceled();
				}
			}
		}

		private void checkPreSaveMonitor() {
			if (monitor == null) {
				return;
			}
			if (taskThread.isInterrupted()) {
				monitor.cancel();
			}
			if (monitor.isCancelled()) {
				// interrupt waiting thread but continue pre-save
				monitorThread.interrupt();
				monitor = null;
				monitorThread = null;
			}
			else {
				monitor.setProgress(curIndex);
			}
		}

		/**
		 * Perform pre-save of sourceFile to preSaveFile.
		 * The preSaveFile is changed to null if an error occurs.
		 */
		@Override
		public void run() {

			DataBuffer buf = new DataBuffer(getBufferSize());
			boolean success = false;
			try {
				// Initial delay
				Thread.sleep(100);

				// Copy non-empty buffers only
				// Remaining content established by BuffermMgr.saveAs()
				int cnt = srcFile.getIndexCount();
				maxIndex = cnt - 1;
				for (curIndex = 0; curIndex < cnt; curIndex++) {
					while (true) {
						synchronized (preSaveLock) {
							// Check for canceled task
							checkPreSaveMonitor();
							if (taskThread.isInterrupted()) {
								return;
							}
							// Continue to back-off while primary buffer file instance is in use
							if (!preSaveBackoff) {
								break;
							}
							preSaveBackoff = false;
						}
						// Back-off a little
						Thread.sleep(50);
					}
					srcFile.get(buf, curIndex);
					preSaveFile.put(buf, curIndex);
				}
				success = true;
			}
			catch (InterruptedException e) {
				checkPreSaveMonitor();
			}
			catch (Throwable t) {
				Msg.error(this, t);
			}
			finally {
				if (!success) {
					preSaveFile.setTemporary(true);
					try {
						preSaveFile.close();
					}
					catch (IOException e) {
						Msg.error(this, e);
					}
					finally {
						preSaveFile = null;
						preSaveFailed = true;
					}
				}
				try {
					srcFile.close();
				}
				catch (IOException e) {
					Msg.error(this, e);
				}
			}
		}

	}

	/**
	 * <code>LocalManagedOutputBlockStream</code> extends <code>LocalOutputBlockStream</code>
	 * for use when updating versioned buffer file.  This implementation causes change
	 * map data to be updated.  It is important that the free list is updated after 
	 * streaming is complete.
	 */
	class LocalManagedOutputBlockStream extends LocalOutputBlockStream {

		public LocalManagedOutputBlockStream(int blockCount) throws IOException {
			super(blockCount);
		}

		@Override
		public void writeBlock(BufferFileBlock block) throws IOException {
			synchronized (LocalManagedBufferFile.this) {
				int bufferIndex = block.getIndex() - 1;
				if (bufferIndex >= 0) {
					versionBufferIfNeeded(bufferIndex);
				}
				super.writeBlock(block);
				if (changeMap != null && bufferIndex >= 0) {
					// NOTE: versioned empty blocks should not get streamed
					// and will be updated with free list update.  If free
					// buffers are written, the changeMap will get corrected
					// provided the free list is updated after the streaming
					// is complete
					changeMap.bufferChanged(bufferIndex, false);
				}
			}
		}
	}

	/**
	 * Obtain a direct stream to write blocks to this buffer file
	 * @param blockCount number of blocks to be transferred
	 * @return output block stream
	 * @throws IOException
	 */
	@Override
	public OutputBlockStream getOutputBlockStream(int blockCount) throws IOException {
		return new LocalManagedOutputBlockStream(blockCount);
	}

	/**
	 * Obtain a direct stream to read all blocks of this buffer file 
	 * @return input block stream
	 * @throws IOException
	 */
	@Override
	public InputBlockStream getInputBlockStream() throws IOException {
		if (versionFileHandler != null) {
			// Must stream at the buffer level to allow for various buffer source files
			return new LocalBufferInputBlockStream();
		}
		return super.getInputBlockStream();
	}

	/**
	 * Obtain a direct stream to read modified blocks of this buffer file 
	 * based upon the specified changeMap
	 * @return input block stream
	 * @throws IOException
	 */
	public InputBlockStream getInputBlockStream(byte[] changeMapData) throws IOException {
		return new LocalRandomInputBlockStream(changeMapData);
	}

	/**
	 * Create a new version of this file by updating it from a versionedBufferFile.  
	 * This file must be open as read-only with versionUpdateEnabled and have been derived 
	 * from an oldVersion of the versionedBufferFile (i.e., was based on a check-out of oldVersion).
	 * The save-file corresponding to this file is updated using those buffers
	 * which have been modified or added in the specified versionedBufferFile 
	 * since olderVersion.  When complete, this file should be closed
	 * as soon as possible.
	 * @param versionedBufferFile versioned buffer file
	 * @param oldVersion older version of versionedBufferFile from which this buffer file originated.
	 * @param monitor progress monitor
	 * @throws IOException if an I/O error occurs
	 * @throws CancelledException if monitor cancels operation
	 */
	public synchronized void updateFrom(ManagedBufferFile versionedBufferFile, int oldVersion,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (!canSave()) {
			throw new IOException("File does not allow update");
		}
		if (bfMgr == null) {
			throw new UnsupportedOperationException(
				"Buffer file is not associated with BufferFileManager");
		}

		// Create combined change map so that every buffer modified locally since checkout
		// or within the versionedBufferFile since checkout gets copied from versionedBufferFile.
		byte[] versionedChanges = versionedBufferFile.getForwardModMapData(oldVersion);
		ChangeMap newChangeMap = new ChangeMap(versionedChanges);
		byte[] myModifiedBuffers = getForwardModMapData();
		if (myModifiedBuffers != null) {
			newChangeMap.addChangeMapData(myModifiedBuffers);
		}
		newChangeMap.setChangedIndexes(getFreeIndexes());
		newChangeMap.setUnchangedIndexes(versionedBufferFile.getFreeIndexes());

		LocalManagedBufferFile bf = getSaveFile(monitor);
		boolean success = false;
		try {

			copyFile(versionedBufferFile, bf, newChangeMap, monitor);

			// Merged file may be smaller - truncate if necessary
			int indexCount = versionedBufferFile.getIndexCount();
			if (indexCount < bf.getIndexCount()) {
				bf.truncate(indexCount);
			}
			success = true;
		}
		finally {
			saveCompleted(success);
			if (!success) {
				bfMgr.updateEnded(checkinId);
			}
//			else {
//				// VERIFY RESULT FILE
//				System.err.println("Update check: " + file);
//				checkSameContent(versionedBufferFile, bf);
//			}
		}

	}

}
