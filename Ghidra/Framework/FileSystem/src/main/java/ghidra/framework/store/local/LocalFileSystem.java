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

import db.buffers.BufferFile;
import db.buffers.LocalManagedBufferFile;
import ghidra.framework.store.*;
import ghidra.framework.store.FileSystem;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LocalFileSystem</code> provides access to FolderItem's which
 * exist within a File-based directory structure.  Although FolderItem
 * caching is highly recommended, it is not provided by this implementation
 * and should be provided by an encompassing set of folder/file objects.
 * <p>
 * A LocalFileSystem may optionally support version control of its
 * FolderItem's.  When versioned, FolderItem's must be checked-out
 * to create new versions.  When not versioned, the check-out mechanism
 * is not used.
 * <p>
 * FileSystemListener's will only be notified of changes made by the
 * associated LocalFileSystem instance.  For this reason, it is important
 * that proper measures are taken to prevent concurrent modification of the
 * underlying files/directories by another instance or by any other
 * means.
 */
public abstract class LocalFileSystem implements FileSystem {

	static final Logger log = LogManager.getLogger(LocalFileSystem.class);

	/**
	 * Hidden directory name prefix.
	 * Should only be prepended to an escaped base-name.
	 * @see #escapeHiddenDirPrefixChars(String)
	 */
	public static final char HIDDEN_DIR_PREFIX_CHAR = '~';
	public static final String HIDDEN_DIR_PREFIX = Character.toString(HIDDEN_DIR_PREFIX_CHAR);

	/**
	 * Hidden item name prefix.
	 */
	public static final String HIDDEN_ITEM_PREFIX = ".ghidra.";

	// NOTE: The / and : chars are reserved for use by the file system and should always be disallowed!
	private static final String INVALID_FILENAME_CHARS = "/\\'`\"*:<>?|";

	static final String PROPERTY_EXT = PropertyFile.PROPERTY_EXT;
//	private static final int MAX_PATHNAME_LENGTH = 255;

	private static boolean refreshRequired = false;

	protected final File root;
	protected final boolean isVersioned;
	protected final boolean readOnly;
	protected final FileSystemListenerList listeners;

	private RepositoryLogger repositoryLogger;

	// Always false in production; can be manipulated by tests
	private boolean isShared;

	/**
	 * Construct a local filesystem for existing data
	 * @param rootPath
	 * @param create
	 * @param isVersioned
	 * @param readOnly
	 * @param enableAsyncronousDispatching
	 * @return local filesystem
	 * @throws FileNotFoundException if specified rootPath does not exist
	 * @throws IOException if error occurs while reading/writing index files
	 */
	public static LocalFileSystem getLocalFileSystem(String rootPath, boolean create,
			boolean isVersioned, boolean readOnly, boolean enableAsyncronousDispatching)
			throws IOException {

		File root = new File(rootPath);
		if (!root.isDirectory()) {
			throw new IOException("filesystem directory not found: " + rootPath);
		}
		if (create && root.list().length != 0) {
			throw new IOException("new filesystem directory is not empty: " + rootPath);
		}
		if (create) {
//			if (isCreateMangledFileSystemEnabled()) {
//				return new MangledLocalFileSystem(rootPath, isVersioned, readOnly,
//					enableAsyncronousDispatching);
//			}
			return new IndexedV1LocalFileSystem(rootPath, isVersioned, readOnly,
				enableAsyncronousDispatching, true);
		}
		else if (!readOnly && !root.canWrite()) {
			throw new IOException("filesystem directory is not writable: " + rootPath);
		}

		int indexVersion = -1;
		if (IndexedLocalFileSystem.isIndexed(rootPath)) {
			indexVersion = IndexedLocalFileSystem.readIndexVersion(rootPath);
		}
		else if (IndexedLocalFileSystem.hasIndexedStructure(rootPath)) {
			// assume latest version - index file missing, rebuild required
			indexVersion = IndexedLocalFileSystem.LATEST_INDEX_VERSION;
		}

		switch (indexVersion) {
			case -1:
				if (hasAnyHiddenFiles(root)) {
					throw new IOException("Unsupported file system schema: " + rootPath);
				}
				// Use legacy mangled filesystem if existing data does not appear to be indexed
				Msg.warn(LocalFileSystem.class, "Using deprecated Mangled filesystem: " + rootPath);
				return new MangledLocalFileSystem(rootPath, isVersioned, readOnly,
					enableAsyncronousDispatching);
			case 0:
				Msg.warn(LocalFileSystem.class,
					"Using deprecated Indexed filesystem (V0): " + rootPath);
				return IndexedLocalFileSystem.getFileSystem(rootPath, isVersioned, readOnly,
					enableAsyncronousDispatching);
			case 1:
				return IndexedV1LocalFileSystem.getFileSystem(rootPath, isVersioned, readOnly,
					enableAsyncronousDispatching);
			default:
				throw new IOException(
					"Unsupported file system version (" + indexVersion + "): " + rootPath);
		}
	}

	@Override
	public String getUserName() {
		return SystemUtilities.getUserName();
	}

	/**
	 * Returns true if any file found within dir whose name starts
	 * with '~' character (e.g., ~index.dat, etc)
	 * @param dir
	 * @return true if any hidden file found with '~' prefix
	 */
	private static boolean hasAnyHiddenFiles(File dir) {
		for (File f : dir.listFiles()) {
			if (f.getName().startsWith("~") && f.isFile()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Constructor.
	 * @param rootPath root path directory.
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws FileNotFoundException if specified rootPath does not exist
	 */
	protected LocalFileSystem(String rootPath, boolean isVersioned, boolean readOnly,
			boolean enableAsyncronousDispatching) throws FileNotFoundException {

		root = new File(rootPath);
		if (!root.isDirectory()) {
			throw new FileNotFoundException("data directory not found: " + rootPath);
		}

		this.isVersioned = isVersioned;
		this.readOnly = readOnly;
		listeners = new FileSystemListenerList(enableAsyncronousDispatching);

	}

	protected void cleanupAfterConstruction() {
		if (!readOnly) {
			LocalDatabaseItem.cleanupOldPresaveFiles(root);
			cleanupTemporaryFiles(SEPARATOR);
		}
	}

	/**
	 * Constructor for an empty read-only file-system.
	 */
	protected LocalFileSystem() {
		this.root = null;
		this.isVersioned = false;
		this.readOnly = true;
		listeners = null;
	}

	private void cleanupTemporaryFiles(String folderPath) {
		try {
			for (String itemName : getItemNames(folderPath, true)) {
				if (!itemName.startsWith(HIDDEN_ITEM_PREFIX)) {
					continue;
				}
				LocalFolderItem item = getItem(folderPath, itemName);
				if (item != null) {
					item.deleteContent(null);
				}
				else {
					// make sure we get item out of index
					deallocateItemStorage(folderPath, itemName);
				}
			}
			String parentPath = folderPath + (folderPath.endsWith(SEPARATOR) ? "" : SEPARATOR);
			for (String subfolder : getFolderNames(folderPath)) {
				cleanupTemporaryFiles(parentPath + subfolder);
			}
		}
		catch (FileNotFoundException e) {
			// ignore
		}
		catch (IOException e) {
			e.printStackTrace();
			// ignore
		}
	}

	/**
	 * Associate file system with a specific repository logger
	 * @param repositoryLogger
	 */
	public void setAssociatedRepositoryLogger(RepositoryLogger repositoryLogger) {
		this.repositoryLogger = repositoryLogger;
	}

	protected void log(LocalFolderItem item, String msg, String user) {
		String path = item != null ? item.getPathName() : null;
		if (repositoryLogger != null) {
			repositoryLogger.log(path, msg, user);
		}
		else {
			StringBuffer buf = new StringBuffer();
			if (item != null) {
				buf.append(item.getPathName());
			}
			buf.append(": ");
			buf.append(msg);
			if (user != null) {
				buf.append(" (");
				buf.append(user);
				buf.append(")");
			}
			log.info(buf.toString());
		}
	}

	/**
	 * If set, the state of folder item resources will be continually refreshed.
	 * This is required if multiple instances exist for a single item.  The default is
	 * disabled.   This feature should be enabled for testing only since it may have a
	 * significant performance impact.  This does not provide locking which may be
	 * required for a shared environment (e.g., checkin locking is only managed by a
	 * single instance).
	 */
	public static void setValidationRequired() {
		refreshRequired = true;
	}

	/**
	 * @return true if folder item resources must be refreshed.
	 * @see #setValidationRequired()
	 */
	public static boolean isRefreshRequired() {
		return refreshRequired;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#isVersioned()
	 */
	@Override
	public boolean isVersioned() {
		return isVersioned;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#isOnline()
	 */
	@Override
	public boolean isOnline() {
		return true;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return readOnly;
	}

	protected static class ItemStorage {
		File dir;
		String storageName;
		String folderPath;
		String itemName;

		ItemStorage(File dir, String storageName, String folderPath, String itemName) {
			this.dir = dir;
			this.storageName = storageName;
			this.folderPath = folderPath;
			this.itemName = itemName;
		}

		boolean exists() {
			File pfile = new File(dir, storageName + PROPERTY_EXT);
			return pfile.exists();
		}

		PropertyFile getPropertyFile() throws IOException {
			return new PropertyFile(dir, storageName, folderPath, itemName);
		}

		@Override
		public String toString() {
			String path;
			try {
				path = getPropertyFile().getPath();
			}
			catch (IOException e) {
				path = "<ERROR: " + e.getMessage() + ">";
			}
			return itemName + " (" + storageName + ", " + path + ")";
		}
	}

	/**
	 * Find an existing storage location
	 * @param folderPath
	 * @param itemName
	 * @return storage location.  A non-null value does not guarantee that the associated
	 * item actually exists.
	 * @throws FileNotFoundException
	 */
	protected abstract ItemStorage findItemStorage(String folderPath, String itemName)
			throws FileNotFoundException;

	/**
	 * Allocate a new storage location
	 * @param folderPath
	 * @param itemName
	 * @return storage location
	 * @throws DuplicateFileException if item path has previously been allocated
	 * @throws IOException if invalid path/item name specified
	 * @throws InvalidNameException if folderPath or itemName contains invalid characters
	 */
	protected abstract ItemStorage allocateItemStorage(String folderPath, String itemName)
			throws IOException, InvalidNameException;

	/**
	 * Deallocate item storage
	 * @param folderPath
	 * @param itemName
	 * @throws IOException
	 */
	protected abstract void deallocateItemStorage(String folderPath, String itemName)
			throws IOException;

	protected abstract String[] getItemNames(String folderPath, boolean includeHiddenFiles)
			throws IOException;

	/**
	 *
	 * @see ghidra.framework.store.FileSystem#getItemNames(java.lang.String)
	 */
	@Override
	public synchronized String[] getItemNames(String folderPath) throws IOException {
		return getItemNames(folderPath, false);
	}

	/*
	 * @see ghidra.framework.store.FileSystem#getItem(java.lang.String, java.lang.String)
	 */
	@Override
	public synchronized LocalFolderItem getItem(String folderPath, String name) throws IOException {
		try {
			ItemStorage itemStorage = findItemStorage(folderPath, name);
			if (itemStorage == null) {
				return null;
			}
			PropertyFile propertyFile = itemStorage.getPropertyFile();
			if (propertyFile.exists()) {
				return LocalFolderItem.getFolderItem(this, propertyFile);
			}
		}
		catch (FileNotFoundException e) {
			// ignore
		}
		return null;
	}

	/**
	 * Notification that FileID has been changed within propertyFile
	 * @param propertyFile
	 * @param oldFileId
	 * @throws IOException
	 */
	protected void fileIdChanged(PropertyFile propertyFile, String oldFileId) throws IOException {
		// do nothing by default
	}

	@Override
	public FolderItem getItem(String fileID) throws IOException, UnsupportedOperationException {
		throw new UnsupportedOperationException("getItem by File-ID");
	}

	/*
	 * @see ghidra.framework.store.FileSystem#createDatabase(java.lang.String, java.lang.String, java.lang.String, db.buffers.BufferFile, java.lang.String, java.lang.String, boolean, ghidra.util.task.TaskMonitor, java.lang.String)
	 */
	@Override
	public synchronized LocalDatabaseItem createDatabase(String parentPath, String name,
			String fileID, BufferFile bufferFile, String comment, String contentType,
			boolean resetDatabaseId, TaskMonitor monitor, String user)
			throws InvalidNameException, IOException, CancelledException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(name, false);

		ItemStorage itemStorage = allocateItemStorage(parentPath, name);
		LocalDatabaseItem item = null;
		try {
			PropertyFile propertyFile = itemStorage.getPropertyFile();
			item = new LocalDatabaseItem(this, propertyFile, bufferFile, contentType, fileID,
				comment, resetDatabaseId, monitor, user);
		}
		finally {
			if (item == null) {
				deallocateItemStorage(parentPath, name);
			}
		}
		return item;
	}

	public synchronized LocalDatabaseItem createTemporaryDatabase(String parentPath, String name,
			String fileID, BufferFile bufferFile, String contentType, boolean resetDatabaseId,
			TaskMonitor monitor) throws InvalidNameException, IOException, CancelledException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(name, false);

		String hiddenName = HIDDEN_ITEM_PREFIX + name;

		ItemStorage itemStorage = allocateItemStorage(parentPath, hiddenName);
		LocalDatabaseItem item = null;
		try {
			PropertyFile propertyFile = itemStorage.getPropertyFile();
			item = new LocalDatabaseItem(this, propertyFile, bufferFile, contentType, fileID, null,
				resetDatabaseId, monitor, null);
		}
		finally {
			if (item == null) {
				deallocateItemStorage(parentPath, name);
			}
		}
		return item;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#createDatabase(java.lang.String, java.lang.String, java.lang.String, int, java.lang.String)
	 */
	@Override
	public LocalManagedBufferFile createDatabase(String parentPath, String name, String fileID,
			String contentType, int bufferSize, String user, String projectPath)
			throws InvalidNameException, IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(name, false);

		ItemStorage itemStorage = allocateItemStorage(parentPath, name);
		LocalManagedBufferFile bufferFile = null;
		try {
			PropertyFile propertyFile = itemStorage.getPropertyFile();
			bufferFile = LocalDatabaseItem.create(this, propertyFile, bufferSize, contentType,
				fileID, user, projectPath);
		}
		finally {
			if (bufferFile == null) {
				deallocateItemStorage(parentPath, name);
			}
		}
		return bufferFile;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#createDataFile(java.lang.String, java.lang.String, java.io.InputStream, java.lang.String, java.lang.String, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public synchronized LocalDataFile createDataFile(String parentPath, String name,
			InputStream istream, String comment, String contentType, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(name, false);

		ItemStorage itemStorage = allocateItemStorage(parentPath, name);
		LocalDataFile dataFile = null;
		try {
//TODO handle comment
			PropertyFile propertyFile = itemStorage.getPropertyFile();
			dataFile = new LocalDataFile(this, propertyFile, istream, contentType, monitor);
		}
		finally {
			if (dataFile == null) {
				deallocateItemStorage(parentPath, name);
			}
		}

		listeners.itemCreated(parentPath, name);

		return dataFile;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#createFile(java.lang.String, java.lang.String, java.io.File, ghidra.util.task.TaskMonitor, java.lang.String)
	 */
	@Override
	public LocalDatabaseItem createFile(String parentPath, String name, File packedFile,
			TaskMonitor monitor, String user)
			throws InvalidNameException, IOException, CancelledException {
		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(name, false);

		ItemDeserializer itemDeserializer = new ItemDeserializer(packedFile);
		String contentType;
		try {
			int fileType = itemDeserializer.getFileType();
			if (fileType != FolderItem.DATABASE_FILE_TYPE) {
				throw new UnsupportedOperationException("Only packed database files are supported");
			}
			if (name == null) {
				name = itemDeserializer.getItemName();
			}
			contentType = itemDeserializer.getContentType();
		}
		finally {
			itemDeserializer.dispose();
		}

		ItemStorage itemStorage = allocateItemStorage(parentPath, name);
		LocalDatabaseItem item = null;
		try {
			PropertyFile propertyFile = itemStorage.getPropertyFile();
			item =
				new LocalDatabaseItem(this, propertyFile, packedFile, contentType, monitor, user);
		}
		finally {
			if (item == null) {
				deallocateItemStorage(parentPath, name);
			}
		}
		return item;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#moveItem(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public synchronized void moveItem(String folderPath, String name, String newFolderPath,
			String newName) throws IOException, InvalidNameException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		ItemStorage itemStorage = findItemStorage(folderPath, name);
		LocalFolderItem item = getItem(folderPath, name);
		if (itemStorage == null || item == null) {
			throw new FileNotFoundException(
				"Item " + name + " in folder " + folderPath + " not found");
		}

		if (folderPath.equals(newFolderPath) && name.equals(newName)) {
			return;
		}

		testValidName(newFolderPath, true);
		testValidName(newName, false);

		item.checkInUse();

		ItemStorage newStorage = null;
		boolean success = false;
		try {

			newStorage = allocateItemStorage(newFolderPath, newName);

			item.moveTo(newStorage.dir, newStorage.storageName, newFolderPath, newName);

			deallocateItemStorage(folderPath, name);

			success = true;

			if (folderPath.equals(newFolderPath)) {
				listeners.itemRenamed(folderPath, name, newName);
			}
			else {
				listeners.itemMoved(folderPath, name, newFolderPath, newName);
			}
			deleteEmptyVersionedFolders(folderPath);
			deallocateItemStorage(folderPath, name);
		}
		finally {
			if (!success) {
				if (newStorage != null) {
					deallocateItemStorage(newFolderPath, newName);
				}
				deleteEmptyVersionedFolders(newFolderPath);
			}
		}
	}

	@Override
	public abstract boolean folderExists(String folderPath);

	/*
	 * @see ghidra.framework.store.FileSystem#fileExists(java.lang.String, java.lang.String)
	 */
	@Override
	public boolean fileExists(String folderPath, String name) {
		try {
			ItemStorage itemStorage = findItemStorage(folderPath, name);
			if (itemStorage == null) {
				return false;
			}
			return itemStorage.exists();
		}
		catch (IOException e) {
			return false;
		}
	}

	/*
	 * @see ghidra.framework.store.FileSystem#addFileSystemListener(ghidra.framework.store.FileSystemListener)
	 */
	@Override
	public void addFileSystemListener(FileSystemListener listener) {
		if (listeners != null) {
			listeners.add(listener);
		}
	}

	/*
	 * @see ghidra.framework.store.FileSystem#removeFileSystemListener(ghidra.framework.store.FileSystemListener)
	 */
	@Override
	public void removeFileSystemListener(FileSystemListener listener) {
		if (listeners != null) {
			listeners.remove(listener);
		}
	}

	/**
	 * Returns file system listener.
	 */
	FileSystemListener getListener() {
		return listeners;
	}

	/**
	 * @return the maximum name length permitted for folders or items.
	 */
	public abstract int getMaxNameLength();

	/**
	 * Validate a folder/item name or path.
	 * @param name folder or item name
	 * @param isPath if true name represents full path
	 * @throws InvalidNameException if name is invalid
	 */
	public void testValidName(String name, boolean isPath) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("path or name is empty or null");
		}

		if (isPath) {
			if (name.equals(SEPARATOR)) {
				return;
			}
			if (name.startsWith(SEPARATOR)) {
				name = name.substring(1);
			}
			String[] splitName = name.split(SEPARATOR);
			for (String element : splitName) {
				testValidName(element, false);
			}
			return;
		}

		if (!isPath && name.length() > getMaxNameLength()) {
			throw new InvalidNameException("Project file names within Ghidra must be less than " +
				getMaxNameLength() + " characters in length.");
		}

		if (name.startsWith(HIDDEN_ITEM_PREFIX)) {
			throw new InvalidNameException(
				name + " starts with a reserved prefix '" + HIDDEN_ITEM_PREFIX + "'");
		}

		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (!isValidNameCharacter(c)) {
				throw new InvalidNameException(
					name + " contains an invalid character: \'" + c + "\'");
			}
		}
	}

	/**
	 * @return true if c is a valid character within the FileSystem.
	 */
	public static boolean isValidNameCharacter(char c) {
		return !((c < ' ') || (INVALID_FILENAME_CHARS.indexOf(c) >= 0) || (c > 255));
	}

	/**
	 * Remove the directory which corresponds to the specified folder path if it is empty.
	 * If folder directory is removed, this method is invoked recursively for parent folder
	 * path which may also be removed if it is empty.
	 * This method is intended for use with a versioned file system
	 * which only retains folders if they contain one or more items or sub-folders.
	 * @param folderPath folder path
	 */
	protected synchronized void deleteEmptyVersionedFolders(String folderPath) {
		try {
			if (isVersioned) {
				if (folderPath.length() == 1) {
					return;
				}
				String[] items = getItemNames(folderPath);
				if (items.length > 0) {
					return;
				}
				String[] folders = getFolderNames(folderPath);
				if (folders.length > 0) {
					return;
				}
				deleteFolder(folderPath);
				deleteEmptyVersionedFolders(getParentPath(folderPath));
			}
		}
		catch (IOException e) {
			// ignore
		}
	}

	/**
	 * Notify the filesystem that the property file and associated data files for
	 * an item have been removed from the filesystem.
	 * @param folderPath
	 * @param itemName
	 * @throws IOException
	 */
	protected synchronized void itemDeleted(String folderPath, String itemName) throws IOException {
		// do nothing
	}

	/**
	 * Returns the full path for a specific folder or item
	 * @param parentPath full parent path
	 * @param name child folder or item name
	 */
	protected final static String getPath(String parentPath, String name) {
		if (parentPath.length() == 1) {
			return parentPath + name;
		}
		return parentPath + SEPARATOR_CHAR + name;
	}

	protected final static String getParentPath(String path) {
		if (path.length() == 1) {
			return null;
		}
		int index = path.lastIndexOf(SEPARATOR_CHAR);
		if (index == 0) {
			return SEPARATOR;
		}
		return path.substring(0, index);
	}

	protected final static String getName(String path) {
		if (path.length() == 1) {
			return path;
		}
		if (path.endsWith(SEPARATOR)) {
			path = path.substring(0, path.length() - 1);
		}
		return path.substring(path.lastIndexOf(SEPARATOR_CHAR) + 1);
	}

	@Override
	public boolean isShared() {
		// Does not support direct sharing in production
		return isShared;
	}

//	static void testValidPathLength(File file) throws IOException {
//		String path = file.getAbsolutePath();
//		if (path.length() + LocalFolderItem.DATA_DIR_EXTENSION.length() > MAX_PATHNAME_LENGTH) {
//			throw new IOException("Length of path name for file exceeds maximum of " +
//				MAX_PATHNAME_LENGTH);
//		}
//	}

	@Override
	public void dispose() {
		if (listeners != null) {
			listeners.dispose();
		}
	}

	public boolean migrationInProgress() {
		return false;
	}

	/**
	 * Determines if the specified storage directory name corresponds to a 
	 * hidden directory (includes both system and application hidden directories).
	 * @param name directory name as it appears on storage file system.
	 * @return true if name is a hidden name, else false
	 */
	public static final boolean isHiddenDirName(String name) {
		if (name.startsWith(".")) {
			return true;
		}
		// odd number of prefix chars at start of name indicates hidden name
		return (countHiddenDirPrefixChars(name) & 1) == 1;
	}

	/**
	 * Escape hidden prefix chars in name
	 * @param name
	 * @return escaped name
	 */
	public static final String escapeHiddenDirPrefixChars(String name) {
		int prefixCount = countHiddenDirPrefixChars(name);
		if (prefixCount == 0) {
			return name;
		}
		StringBuilder buf = new StringBuilder();
		// keep number of hidden prefix chars even
		for (int i = 0; i < prefixCount; ++i) {
			buf.append(HIDDEN_DIR_PREFIX_CHAR);
		}
		buf.append(name);
		return buf.toString();
	}

	/**
	 * Unescape a non-hidden directory name
	 * @param name
	 * @return unescaped name or null if name is a hidden name
	 */
	public static final String unescapeHiddenDirPrefixChars(String name) {
		int prefixCount = countHiddenDirPrefixChars(name);
		if ((prefixCount & 1) == 1) {
			return null;
		}
		prefixCount = prefixCount >> 1;
		return name.substring(prefixCount);
	}

	private static int countHiddenDirPrefixChars(String name) {
		int count = 0;
		int length = name.length();
		for (int index = 0; index < length &&
			name.charAt(index) == HIDDEN_DIR_PREFIX_CHAR; index++) {
			++count;
		}
		return count;
	}

}
