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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import generic.timer.GhidraSwinglessTimer;
import ghidra.framework.store.FolderNotEmptyException;
import ghidra.util.*;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.exception.NotFoundException;

/**
 * <code>IndexedLocalFileSystem</code> implements a case-sensitive indexed filesystem
 * which uses a shallow storage hierarchy with no restriction on file name or path 
 * length.  This filesystem is identified by the existence of an index file (~index.dat) 
 * and recovery journal (~index.jrn).
 */
public class IndexedLocalFileSystem extends LocalFileSystem {

	public static final int LATEST_INDEX_VERSION = 1;

	/**
	 * <code>INDEX_REWRITE_JOURNAL_LIMIT</code> determines the maximum number of journal
	 * entries permitted before a rewrite of the index is forced
	 */
	static final int INDEX_REWRITE_JOURNAL_LIMIT = 1000;		// 1000 journal entries

	/**
	 * <code>INDEX_REWRITE_TIME_LIMIT_MS</code> determines the maximum time which will
	 * lapse before the index is rewritten with any changes
	 */
	static final int INDEX_REWRITE_TIME_LIMIT_MS = 30 * 60 * 1000; // 30-minutes

	static final int MAX_NAME_LENGTH = 254; // value is arbitrary

	static final String INDEX_FILE = "~index.dat";
	static final String BAK_INDEX_FILE = "~index.bak";
	static final String TMP_INDEX_FILE = "~index.tmp";
	static final String JOURNAL_FILE = "~journal.dat";
	static final String BAK_JOURNAL_FILE = "~journal.bak";
	static final String REBUILD_ERROR_FILE = "~rebuild.err";
	static final String INDEX_LOCK_FILE = "~index.lock";

	private static final String INDEX_VERSION_PREFIX = "VERSION=";

	private static final String MD5_PREFIX = "MD5:";
	private static final String NEXT_FILE_INDEX_ID_PREFIX = "NEXT-ID:";

	protected static final String INDEX_ITEM_INDENT = "  ";
	protected static final String INDEX_ITEM_SEPARATOR = ":";

	private final File indexFile;
	private final File journalFile;

	IndexJournal indexJournal; // will always be null when readOnly is true
	private int journalCount;

	private long nextFileIndexID = 0;

	private Folder rootFolder;
	private boolean emptyFilesystem;

	private GhidraSwinglessTimer indexRewriteTimer;

	/**
	 * Constructor.
	 * @param file path path for root directory.
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws FileNotFoundException if specified rootPath does not exist
	 * @throws IOException if error occurs while reading/writing index files
	 */
	IndexedLocalFileSystem(String rootPath, boolean isVersioned, boolean readOnly,
			boolean enableAsyncronousDispatching, boolean create) throws IOException {
		super(rootPath, isVersioned, readOnly, enableAsyncronousDispatching);

		indexFile = new File(rootPath, INDEX_FILE);
		journalFile = new File(rootPath, JOURNAL_FILE);

		if (create) {
			rootFolder = new Folder();
			if (readOnly) {
				// Allow empty read-only filesystem to exist
				// This is needed for transient project data
				emptyFilesystem = true;
				return;
			}
			if (indexFile.getParentFile().list().length != 0) {
				throw new IOException("data directory is not empty: " + rootPath);
			}
			writeIndex();
		}
		else {
			readIndex();
		}

		indexJournal = new IndexJournal(); // will replay any existing entries

		if (!readOnly) {
			indexRewriteTimer = new GhidraSwinglessTimer(INDEX_REWRITE_TIME_LIMIT_MS, () -> {
				synchronized (IndexedLocalFileSystem.this) {
					if (journalCount != 0) {
						flushIndex();
					}
				}
			});
			indexRewriteTimer.start();
			if (!create) {
				cleanupAfterConstruction();
			}
		}
	}

	/**
	 * Construct existing indexed filesystem with an empty index.
	 * This can be used to prepare for rebuilding the filesystem index.
	 * @param rootPath
	 * @throws IOException
	 */
	protected IndexedLocalFileSystem(String rootPath) throws IOException {
		super(rootPath, false, false, false);

		indexFile = new File(rootPath, INDEX_FILE);
		indexFile.delete();

		journalFile = new File(rootPath, JOURNAL_FILE);
		journalFile.delete();

		rootFolder = new Folder();
		writeIndex();
		indexJournal = new IndexJournal();
	}

	@Override
	public int getMaxNameLength() {
		return MAX_NAME_LENGTH;
	}

	private void refreshReadOnlyIndex() throws IOException {
		if (emptyFilesystem) {
			// read-only filesystem created as empty filesystem
			// with no index
			return;
		}
		readIndex();
		indexJournal = new IndexJournal();
	}

	@Override
	public synchronized void dispose() {
		if (rootFolder == null) {
			return; // already disposed
		}
		if (indexRewriteTimer != null) {
			indexRewriteTimer.stop();
			indexRewriteTimer = null;
		}
		if (!readOnly) {
			flushIndex();
		}
		dispose(rootFolder);
		rootFolder = null;
		super.dispose();
	}

	/**
	 * Dispose folder structure to speed-up garbage collection
	 * @param folder
	 */
	private void dispose(Folder folder) {
		for (Folder subfolder : folder.folders.values()) {
			dispose(subfolder);
		}
		folder.folders.clear();

		for (Item item : folder.items.values()) {
			item.parent = null;
		}
		folder.items.clear();
	}

	/**
	 * Assign next available storage name
	 * @return storage name (8 hex digits)
	 */
	private synchronized String getNextStorageName() {
		String storageName = StringUtilities.pad(Long.toHexString(nextFileIndexID++), '0', 8);
		getStorageDir(storageName); // ensure that storage sub-directory exists
		return storageName;
	}

	/**
	 * Ensure that the nextFileIndexID is adjusted when replaying 
	 * item adds and moves from the index journal
	 * @param storageName previously allocated storageName
	 */
	private synchronized void bumpNextFileIndexID(String storageName)
			throws BadStorageNameException {
		try {
			long id = NumericUtilities.parseHexLong(storageName);
			nextFileIndexID = Math.max(nextFileIndexID, id + 1);
		}
		catch (Exception e) {
			throw new BadStorageNameException(storageName);
		}
	}

	/**
	 * Get storage directory corresponding to the specified storageName
	 * @param storageName Item storage name (8 hex digits)
	 * @return
	 */
	private File getStorageDir(String storageName) {
		// storage dir uses 3rd and 2nd hex digits to form name
		int len = storageName.length(); // should be 8
		File dir = new File(root, storageName.substring(len - 3, len - 1));
		if (!dir.exists()) {
			dir.mkdir();
		}
		return dir;
	}

	/**
	 * Writes current folder index.
	 * Same as writeIndex with any IOException getting logged
	 * @see #writeIndex()
	 */
	private void flushIndex() {
		try {
			writeIndex();
		}
		catch (IOException e) {
			Msg.error(this, "Failed to flush index file", e);
		}
	}

	/**
	 * Writes current folder index.
	 * @throws IOException
	 */
	private void writeIndex() throws IOException {

		if (readOnly) {
			throw new IOException("Unexpected attempt to write index for read-only filesystem");
		}

		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.toString());
		}

		File tempIndexFile = new File(root, TMP_INDEX_FILE);
		tempIndexFile.delete();
		PrintWriter indexWriter = new PrintWriter(tempIndexFile, "UTF8");
		try {
			int version = getIndexImplementationVersion();
			if (version != 0) {
				String versionLine = INDEX_VERSION_PREFIX + version;
				digest(versionLine, messageDigest);
				indexWriter.println(versionLine);
			}
			writeIndexFolder(indexWriter, rootFolder, messageDigest);
			String idLine = NEXT_FILE_INDEX_ID_PREFIX + Long.toHexString(nextFileIndexID);
			digest(idLine, messageDigest);
			indexWriter.println(idLine);
			indexWriter.println(
				MD5_PREFIX + NumericUtilities.convertBytesToString(messageDigest.digest()));
			indexWriter.flush();
			indexWriter.close();
			if (indexWriter.checkError()) {
				indexWriter = null;
				throw new IOException(
					"error occurred while writing filesystem index: " + tempIndexFile);
			}
		}
		finally {
			if (indexWriter != null) {
				indexWriter.close();
			}
		}

		File backupIndexFile = new File(root, BAK_INDEX_FILE);
		File backupJournalFile = new File(root, BAK_JOURNAL_FILE);

		if (indexFile.exists()) {
			backupIndexFile.delete();
			backupJournalFile.delete();
			if (!indexFile.renameTo(backupIndexFile)) {
				throw new IOException("failed to backup filesystem index: " + indexFile);
			}
			if (journalFile.exists() && !journalFile.renameTo(backupJournalFile)) {
				backupIndexFile.renameTo(indexFile);
				throw new IOException("failed to backup filesystem journal: " + journalFile);
			}
		}
		else {
			backupIndexFile.delete();
			backupJournalFile.delete();
			backupIndexFile = null;
			backupJournalFile = null;
		}

		if (!tempIndexFile.renameTo(indexFile)) {
			// hopefully we can restore index
			if (backupIndexFile != null) {
				backupIndexFile.renameTo(indexFile);
			}
			if (backupJournalFile != null) {
				backupJournalFile.renameTo(journalFile);
			}
			throw new IOException("failed to update filesystem index (2): " + indexFile);
		}

		journalCount = 0;
	}

	void digest(String str, MessageDigest messageDigest) {
		messageDigest.digest(str.getBytes());
	}

	private void writeIndexFolder(PrintWriter indexWriter, Folder folder,
			MessageDigest messageDigest) {

		// all folder paths will start with FileSystem.SEPARATOR_CHAR '/'
		String folderPath = folder.getPathname();
		indexWriter.println(folderPath);
		digest(folderPath, messageDigest);

		for (Item item : folder.items.values()) {
			String entry = formatIndexItem(item);
			indexWriter.println(INDEX_ITEM_INDENT + entry);
			digest(entry, messageDigest);
		}

		for (Folder subfolder : folder.folders.values()) {
			writeIndexFolder(indexWriter, subfolder, messageDigest);
		}
	}

	String formatIndexItem(Item item) {
		return item.getStorageName() + INDEX_ITEM_SEPARATOR + item.getName();
	}

	public int getIndexImplementationVersion() {
		return 0;
	}

	/**
	 * Check the firstIndexLine to verify the index version.
	 * @return true if firstIndexLine was consumed
	 * @throws IndexVersionException if index version error occurs
	 */
	private boolean checkIndexVersion(String firstIndexLine) throws IndexVersionException {

		boolean consumed =
			firstIndexLine != null && firstIndexLine.startsWith(INDEX_VERSION_PREFIX);

		int indexImplVersion = getIndexImplementationVersion();

		int indexVersion = getIndexVersion(firstIndexLine);

		if (indexVersion >= 0 && indexVersion < indexImplVersion) {
			throw new IndexVersionException("Filesystem Index upgrade/rebuild required", true);
		}
		if (indexVersion != indexImplVersion) {
			throw new IndexVersionException(
				"Unsupported Filesystem Index version (newer version of application required)",
				false);
		}

		return consumed;
	}

	/**
	 * Attempt to parse index version
	 * @param firstIndexLine
	 * @return index version or -1 if index version unknown
	 */
	private static int getIndexVersion(String firstIndexLine) {
		int indexVersion = -1;
		if (firstIndexLine != null && firstIndexLine.length() != 0) {
			if (firstIndexLine.startsWith(INDEX_VERSION_PREFIX)) {
				String versionStr = firstIndexLine.substring(INDEX_VERSION_PREFIX.length());
				try {
					indexVersion = Integer.parseInt(versionStr);
				}
				catch (Exception e) {
					Msg.error(IndexedLocalFileSystem.class,
						"Invalid file-system version (" + versionStr + ")");
					indexVersion = Integer.MAX_VALUE;
				}
			}
			else {
				indexVersion = 0;
			}
		}
		return indexVersion;
	}

	public static int readIndexVersion(String rootPath) throws IOException {
		File indexFile = new File(rootPath, INDEX_FILE);
		BufferedReader indexReader = null;
		try {
			indexReader = new BufferedReader(new InputStreamReader(
				new BufferedInputStream(new FileInputStream(indexFile)), "UTF8"));
			return getIndexVersion(indexReader.readLine());
		}
		finally {
			if (indexReader != null) {
				try {
					indexReader.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}
	}

	private void readIndex() throws IndexReadException {

		// TODO: current implementation does not attempt to avoid concurrent read/write
		// access to index/journal files

		MessageDigest messageDigest = null;
		try {
			messageDigest = MessageDigest.getInstance("MD5");
		}
		catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e.toString());
		}

		if (rootFolder != null) {
			// help-out the garbage collector by clearing references
			dispose(rootFolder);
		}
		rootFolder = new Folder();

		String md5Str = null;
		String idLine = null;
		BufferedReader indexReader = null;
		try {
			indexReader = new BufferedReader(new InputStreamReader(
				new BufferedInputStream(new FileInputStream(indexFile)), "UTF8"));
			String line = indexReader.readLine();
			if (checkIndexVersion(line)) {
				// version line consumed - read next line
				line = indexReader.readLine();
			}
			Folder currentFolder = null;
			while (line != null) {
				if (line.startsWith(MD5_PREFIX)) {
					// should be last line in file
					md5Str = line.substring(MD5_PREFIX.length());
				}
				else if (line.startsWith(NEXT_FILE_INDEX_ID_PREFIX)) {
					// should immediately proceed MD5 line
					md5Str = null;
					digest(line, messageDigest);
					idLine = line.substring(NEXT_FILE_INDEX_ID_PREFIX.length());
				}
				else {
					md5Str = null;
					idLine = null;
					if (line.startsWith(SEPARATOR)) {
						digest(line, messageDigest);
						currentFolder = getFolder(line, GetFolderOption.CREATE);
					}
					else {
						String entry = line.substring(INDEX_ITEM_INDENT.length());
						digest(entry, messageDigest);
						if (parseIndexItem(currentFolder, entry) == null) {
							throw new IOException("Invalid filesystem index: " + indexFile);
						}
					}
				}
				line = indexReader.readLine();
			}
		}
		catch (Exception e) {
			if (e instanceof IndexVersionException) {
				throw (IndexVersionException) e;
			}
			throw new IndexReadException("Filesystem Index error: " + indexFile, e);
		}
		finally {
			if (indexReader != null) {
				try {
					indexReader.close();
				}
				catch (IOException e) {
					// ignore
				}
			}
		}

		try {
			nextFileIndexID = NumericUtilities.parseHexLong(idLine);
		}
		catch (Exception e) {
			throw new IndexReadException("Invalid Filesystem Index (NEXT-ID): " + indexFile);
		}

		String md5Digest = NumericUtilities.convertBytesToString(messageDigest.digest());
		if (md5Str == null || !md5Str.equals(md5Digest)) {
			throw new IndexReadException("Invalid Filesystem Index (MD5): " + indexFile);
		}
	}

	Item parseIndexItem(Folder parent, String entry) {
		int index = entry.indexOf(INDEX_ITEM_SEPARATOR);
		if (index < 0) {
			return null;
		}
		String storageName = entry.substring(0, index);
		String name = entry.substring(index + 1);
		return new Item(parent, name, storageName);
	}

	private PrintWriter rebuildErrWriter;

	private void logRebuildError(String text) throws IOException {
		if (rebuildErrWriter == null) {
			File file = new File(root, REBUILD_ERROR_FILE);
			file.delete();
			rebuildErrWriter = new PrintWriter(
				new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file))));
		}
		rebuildErrWriter.println(text);
	}

	boolean rebuildIndex() throws IOException {
		for (File f : root.listFiles()) {
			if (f.isDirectory()) {
				rebuildDirectoryIndex(f);
			}
		}
		if (rebuildErrWriter != null) {
			rebuildErrWriter.close();
			return false;
		}
		return true;
	}

	private void rebuildDirectoryIndex(File dir) throws IOException {
		for (File f : dir.listFiles()) {
			if (f.isFile() && f.getName().endsWith(PROPERTY_EXT)) {
				try {
					if (!addFileToIndex(new IndexedPropertyFile(f))) {
						logRebuildError("Invalid item property file: " + f);
					}
				}
				catch (NotFoundException e) {
					logRebuildError("Item property file contains invalid parent path:" + f);
				}
			}
		}
	}

	private boolean addFileToIndex(PropertyFile pfile) throws IOException, NotFoundException {

		String parentPath = pfile.getParentPath();
		String name = pfile.getName();
		if (parentPath == null || name == null) {
			return false;
		}

		indexJournal.open();
		try {
			Folder folder = addFolderToIndexIfMissing(parentPath);
			Item item = new Item(folder, name, pfile.getStorageName());
			bumpNextFileIndexID(item.getStorageName());
			indexJournal.addItem(item);
		}
		finally {
			indexJournal.close();
		}
		return true;
	}

	/**
	 * Add folder to index during rebuild if missing
	 * NOTE: indexJournal must already open'ed by caller
	 * @param folderPath
	 * @return
	 * @throws IOException
	 * @throws NotFoundException
	 */
	private Folder addFolderToIndexIfMissing(String folderPath)
			throws IOException, NotFoundException {

		if (SEPARATOR.equals(folderPath)) {
			return rootFolder;
		}

		int index = folderPath.lastIndexOf(SEPARATOR);
		String name = folderPath.substring(index + 1);
		String parentPath = index == 0 ? SEPARATOR : folderPath.substring(0, index);

		Folder parent = getFolder(parentPath, GetFolderOption.CREATE_ALL);
		Folder folder = parent.folders.get(name);
		if (folder != null) {
			return folder;
		}
		folder = new Folder();
		folder.parent = parent;
		folder.name = name;
		parent.folders.put(name, folder);
		indexJournal.addFolder(folderPath);
		return folder;
	}

	/**
	 * Verify that the specified root directory passes all criteria to be an indexed 
	 * filesystem.
	 * @param root
	 * @return number of property files processed
	 * @throws IndexReadException
	 */
	static int verifyIndexedFileStructure(File root) throws IndexReadException {
		int itemCount = 0;
		for (File f : root.listFiles()) {
			if (f.isDirectory()) {
				if (!isHiddenDirName(f.getName())) {
					itemCount += verifyIndexedDirectory(f);
				}
			}
			else {
				String fname = f.getName();
				if (fname.endsWith(PROPERTY_EXT)) {
					throw new IndexReadException(
						"Unexpected property file in filesystem root: " + fname);
				}
			}
		}
		return itemCount;
	}

	private static int verifyIndexedDirectory(File dir) throws IndexReadException {
		int itemCount = 0;
		String fname = dir.getName();
		boolean badFolder = true;
		if (fname.length() == 2) {
			try {
				Integer.parseInt(fname, 16);
				badFolder = false;
			}
			catch (NumberFormatException e) {
				// handled below
			}
		}
		if (badFolder) {
			throw new IndexReadException("Unexpected folder in filesystem root: " + fname);
		}
		for (File f : dir.listFiles()) {
			fname = f.getName();
			if (f.isDirectory()) {
				// ignore hidden directories
				if (!isHiddenDirName(fname)) {
					throw new IndexReadException(
						"Unexpected folder in filesystem: " + dir.getName() + SEPARATOR + fname);
				}
			}
			else if (fname.endsWith(PROPERTY_EXT)) {
				verifyIndexedPropertyFile(f);
				++itemCount;
			}
		}
		return itemCount;
	}

	private static void verifyIndexedPropertyFile(File f) throws IndexReadException {
		String fname = f.getName();
		fname = fname.substring(0, fname.length() - PROPERTY_EXT.length());
		boolean badFile = true;
		int len = fname.length();
		if (len >= 8 && len <= 16) {
			try {
				Integer.parseInt(fname, 16);
				badFile = false;
			}
			catch (NumberFormatException e) {
				// handled below
			}
		}
		if (badFile) {
			throw new IndexReadException("Unexpected property file in filesystem: " +
				f.getParentFile().getName() + SEPARATOR + fname);
		}
	}

	enum GetFolderOption {
		READ_ONLY, CREATE, CREATE_ALL, CREATE_ALL_NOTIFY
	}

	Folder getFolder(String path, GetFolderOption option) throws NotFoundException {
		if (rootFolder == null) {
			throw new NotFoundException("Filesystem has been disposed");
		}
		if (!path.startsWith(SEPARATOR)) {
			throw new NotFoundException("Invalid folder path: " + path);
		}
		Folder folder = rootFolder;
		if (path.length() == 1) {
			return folder;
		}
		String[] names = path.substring(1).split(SEPARATOR);
		for (int i = 0; i < names.length; i++) {
			String name = names[i];
			Folder subfolder = folder.folders.get(name);
			if (subfolder == null) {
				if ((option == GetFolderOption.CREATE && i == (names.length - 1)) ||
					option == GetFolderOption.CREATE_ALL_NOTIFY ||
					option == GetFolderOption.CREATE_ALL) {
					subfolder = new Folder();
					subfolder.parent = folder;
					subfolder.name = name;
					folder.folders.put(name, subfolder);
					if (option == GetFolderOption.CREATE_ALL_NOTIFY) {
						listeners.folderCreated(folder.getPathname(), name);
					}
				}
				else {
					throw new NotFoundException(
						"Folder not found: " + getPath(folder.getPathname(), name));
				}
			}
			folder = subfolder;
		}
		return folder;
	}

	/**
	 * Find an existing storage location
	 * @param folderPath
	 * @param itemName
	 * @return storage location.  A non-null value does not guarantee that the associated 
	 * item actually exists.
	 * @throws FileNotFoundException 
	 */
	@Override
	protected ItemStorage findItemStorage(String folderPath, String itemName)
			throws FileNotFoundException {
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			Item item = folder.items.get(itemName);
			if (item != null) {
				return item.itemStorage;
			}
		}
		catch (NotFoundException e) {
			// ignore - handled below
		}
		throw new FileNotFoundException("Item not found: " + folderPath + SEPARATOR + itemName);
	}

	/**
	 * Allocate a new storage location
	 * @param folderPath
	 * @param itemName
	 * @return storage location
	 * @throws DuplicateFileException if item path has previously been allocated
	 * @throws IOException if invalid path/item name specified
	 * @throws InvalidNameException if folderPath or itemName contains invalid characters
	 */
	@Override
	protected ItemStorage allocateItemStorage(String folderPath, String itemName)
			throws IOException, InvalidNameException {

		indexJournal.open();
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.CREATE_ALL_NOTIFY);
			if (folder.items.containsKey(itemName)) {
				throw new DuplicateFileException(
					getPath(folderPath, itemName) + " already exists.");
			}
			Item item = new Item(folder, itemName);
			indexJournal.addItem(item);
			return item.itemStorage;
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException("Folder not found: " + folderPath);
		}
		finally {
			indexJournal.close();
		}
	}

	/**
	 * Deallocate item storage
	 * @param folderPath
	 * @param itemName
	 */
	@Override
	protected void deallocateItemStorage(String folderPath, String itemName) throws IOException {
		indexJournal.open();
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			if (folder == null) {
				return; // parent not found
			}
			Item item = folder.items.get(itemName);
			if (item != null) {
				indexJournal.deleteItem(item);
				folder.items.remove(itemName);
			}
		}
		catch (NotFoundException e) {
			// ignore
		}
		finally {
			indexJournal.close();
		}
	}

	@Override
	protected synchronized void itemDeleted(String folderPath, String itemName) throws IOException {
		deallocateItemStorage(folderPath, itemName);
		super.itemDeleted(folderPath, itemName);
	}

	void mapFileID(String fileId, Item item) {
		// not implemented
	}

	void unmapFileID(String fileId) {
		// not implemented
	}

	@Override
	protected String[] getItemNames(String folderPath, boolean includeHiddenFiles)
			throws IOException {
		if (readOnly) {
			refreshReadOnlyIndex();
		}
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			Set<String> nameSet = folder.items.keySet();
			int count = nameSet.size();
			ArrayList<String> fileList = new ArrayList<>(count);
			for (String name : nameSet) {
				if (includeHiddenFiles || !name.startsWith(HIDDEN_ITEM_PREFIX)) {
					fileList.add(name);
				}
			}
			return fileList.toArray(new String[fileList.size()]);
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException("Folder not found: " + folderPath);
		}
	}

	@Override
	public int getItemCount() throws IOException {
		if (readOnly) {
			refreshReadOnlyIndex();
		}
		return getItemCount(rootFolder);
	}

	private int getItemCount(Folder folder) {
		int count = folder.items.size();
		for (Folder f : folder.folders.values()) {
			count += getItemCount(f);
		}
		return count;
	}

	/*
	 * @see ghidra.framework.store.FileSystem#getFolders(java.lang.String)
	 */
	@Override
	public synchronized String[] getFolderNames(String folderPath) throws IOException {
		if (readOnly) {
			refreshReadOnlyIndex();
		}
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			Set<String> nameSet = folder.folders.keySet();
			return nameSet.toArray(new String[nameSet.size()]);
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException("Folder not found: " + folderPath);
		}
	}

	/*
	 * @see ghidra.framework.store.FileSystem#createFolder(java.lang.String, java.lang.String)
	 */
	@Override
	public synchronized void createFolder(String parentPath, String folderName)
			throws InvalidNameException, IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(folderName, false);

		String path = getPath(parentPath, folderName);
		indexJournal.open();
		try {
			Folder parent = getFolder(parentPath, GetFolderOption.CREATE_ALL_NOTIFY);
			if (parent.folders.get(folderName) != null) {
				return; // ignore request if already exists
			}

			indexJournal.addFolder(path);

			Folder folder = new Folder();
			folder.parent = parent;
			folder.name = folderName;
			parent.folders.put(folderName, folder);
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException("Folder not found: " + parentPath);
		}
		finally {
			indexJournal.close();
		}

		listeners.folderCreated(parentPath, getName(path));
	}

	/*
	 * @see ghidra.framework.store.FileSystem#deleteFolder(java.lang.String)
	 */
	@Override
	public synchronized void deleteFolder(String folderPath) throws IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		if (SEPARATOR.equals(folderPath)) {
			throw new IOException("Root folder may not be deleted");
		}

		indexJournal.open();
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			if (folder.folders.size() != 0 || folder.items.size() != 0) {
				throw new FolderNotEmptyException(folderPath + " is not empty");
			}

			indexJournal.deleteFolder(folderPath);

			folder.parent.folders.remove(folder.name);
		}
		catch (NotFoundException e) {
			return; // silent - folder already deleted
		}
		finally {
			indexJournal.close();
		}

		listeners.folderDeleted(getParentPath(folderPath), getName(folderPath));
	}

	void migrateItem(LocalFolderItem item) throws IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		// Perform move without assigning new storageName

		String destFolderPath = item.getParentPath();
		String itemName = item.getName();
		String path = item.getPathName();

		indexJournal.open();
		try {
			Folder folder = getFolder(destFolderPath, GetFolderOption.READ_ONLY);
			if (folder.items.containsKey(itemName)) {
				throw new DuplicateFileException("Item already exists: " + path);
			}

			Item newItem = new Item(folder, itemName);

			item.moveTo(newItem.itemStorage.dir, newItem.itemStorage.storageName, path, itemName);

			newItem.itemStorage.getPropertyFile().writeState();

			indexJournal.addItem(newItem);
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException(e.getMessage());
		}
		finally {
			indexJournal.close();
		}

		getListener().itemCreated(destFolderPath, itemName);
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

		// Perform move without assigning new storageName

		String oldPath = getPath(folderPath, name);
		String newPath = getPath(newFolderPath, newName);
		boolean success = false;
		indexJournal.open();
		try {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			Item item = folder.items.get(name);
			if (item == null) {
				throw new FileNotFoundException("Item not found: " + oldPath);
			}

			if (folderPath.equals(newFolderPath) && name.equals(newName)) {
				return;
			}

			testValidName(newFolderPath, true);
			testValidName(newName, false);

			LocalFolderItem folderItem = getItem(folderPath, name);
			if (folderItem == null) {
				throw new FileNotFoundException("Item not found: " + oldPath);
			}
			folderItem.checkInUse();

			Folder newFolder = folder;
			if (!folderPath.equals(newFolderPath)) {
				newFolder = getFolder(newFolderPath, GetFolderOption.CREATE_ALL_NOTIFY);
			}

			folderItem.moveTo(item.itemStorage.dir, item.itemStorage.storageName, newFolderPath,
				newName);

			folder.items.remove(name);
			item.parent = newFolder;
			item.itemStorage.itemName = newName;
			item.itemStorage.folderPath = newFolderPath;
			newFolder.items.put(newName, item);

			indexJournal.moveItem(oldPath, newPath);

			success = true;

		}
		catch (NotFoundException e) {
			throw new FileNotFoundException(e.getMessage());
		}
		finally {
			indexJournal.close();
			if (!success) {
				deleteEmptyVersionedFolders(newFolderPath);
			}
		}

		if (folderPath.equals(newFolderPath)) {
			listeners.itemRenamed(folderPath, name, newName);
		}
		else {
			listeners.itemMoved(folderPath, name, newFolderPath, newName);
		}

		deleteEmptyVersionedFolders(folderPath);
	}

	/*
	 * @see ghidra.framework.store.FileSystem#moveFolder(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public synchronized void moveFolder(String parentPath, String folderName, String newParentPath)
			throws InvalidNameException, IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(newParentPath, true);

		String folderPath = getPath(parentPath, folderName);
		Folder folder;
		boolean success = false;
		indexJournal.open();
		try {
			folder = getFolder(folderPath, GetFolderOption.READ_ONLY);

			// TODO Must scan for items in use !!!

			String newFolderPath = getPath(newParentPath, folderName);
			Folder newParentFolder = getFolder(newParentPath, GetFolderOption.CREATE_ALL_NOTIFY);
			if (newParentFolder.folders.get(folderName) != null) {
				throw new DuplicateFileException(newFolderPath + " already exists.");
			}

			indexJournal.moveFolder(folderPath, newFolderPath);

			folder.parent.folders.remove(folderName);
			folder.parent = newParentFolder;
			newParentFolder.folders.put(folderName, folder);

			success = true;
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException(e.getMessage());
		}
		finally {
			indexJournal.close();
			if (!success) {
				deleteEmptyVersionedFolders(newParentPath);
			}
		}

		updateAffectedItemPaths(folder);

		listeners.folderMoved(parentPath, folderName, newParentPath);
		deleteEmptyVersionedFolders(parentPath);
	}

	private void updateAffectedItemPaths(Folder folder) throws IOException {
		String newFolderPath = folder.getPathname();
		for (Item item : folder.items.values()) {
			ItemStorage itemStorage = item.itemStorage;
			PropertyFile pfile = item.itemStorage.getPropertyFile();
			pfile.moveTo(itemStorage.dir, itemStorage.storageName, newFolderPath,
				itemStorage.itemName);
			itemStorage.folderPath = newFolderPath;
		}
		for (Folder subfolder : folder.folders.values()) {
			updateAffectedItemPaths(subfolder);
		}
	}

	/*
	 * @see ghidra.framework.store.FileSystem#renameFolder(java.lang.String, java.lang.String, java.lang.String)
	 */
	@Override
	public synchronized void renameFolder(String parentPath, String folderName,
			String newFolderName) throws InvalidNameException, IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(newFolderName, false);

		String folderPath = getPath(parentPath, folderName);
		Folder folder;
		indexJournal.open();
		try {
			folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			if (folder.parent.folders.get(newFolderName) != null) {
				throw new DuplicateFileException(
					parentPath + SEPARATOR + newFolderName + " already exists.");
			}

			indexJournal.moveFolder(folderPath, getPath(parentPath, newFolderName));

			folder.parent.folders.remove(folderName);
			folder.name = newFolderName;
			folder.parent.folders.put(newFolderName, folder);
		}
		catch (NotFoundException e) {
			throw new FileNotFoundException(folderPath + " does not exist or is not a folder");
		}
		finally {
			indexJournal.close();
		}

		updateAffectedItemPaths(folder);

		listeners.folderRenamed(parentPath, folderName, newFolderName);
	}

	/*
	 * @see ghidra.framework.store.FileSystem#folderExists(java.lang.String)
	 */
	@Override
	public synchronized boolean folderExists(String folderPath) {
		try {
			getFolder(folderPath, GetFolderOption.READ_ONLY);
			return true;
		}
		catch (NotFoundException e) {
			return false;
		}
	}

	class Item {

		private String fileId; // this is not the same as the file index ID
		private Folder parent;
		private String storageName;

		ItemStorage itemStorage;

		/**
		 * Construct a new item and allocate an associated storage name
		 * @param parent
		 * @param name
		 */
		Item(Folder parent, String name) {
			this.storageName = getNextStorageName();
			set(parent, name, null);
		}

		/**
		 * Construct a previously allocated item and add it to the parent's 
		 * item map.  Property file will not be read.
		 * @param parent
		 * @param name
		 * @param fileId
		 * @param storageName
		 */
		Item(Folder parent, String name, String fileId, String storageName) {
			this.storageName = storageName;
			set(parent, name, fileId);
		}

		/**
		 * Construct a previously allocated item and add it to the parent's 
		 * item map.  The FileID will be read from the Property file.
		 * @param parent
		 * @param name
		 * @param storageName
		 */
		Item(Folder parent, String name, String storageName) {
			this.storageName = storageName;
			set(parent, name);
		}

		/**
		 * Set this items parent, name and storage name and add the modified item
		 * to the specified parent's item map
		 * @param parent
		 * @param name
		 * @param fileId unique file ID from property file content
		 */
		void set(Folder newParent, String newName, String newFileId) {
			if (parent != null && itemStorage != null) {
				parent.items.remove(itemStorage.itemName);
			}
			parent = newParent;
			itemStorage = new IndexedItemStorage(getStorageDir(storageName), storageName,
				parent.getPathname(), newName);
			parent.items.put(newName, this);
			setFileID(newFileId);
		}

		/**
		 * Set this items parent, name and storage name and add the modified item
		 * to the specified parent's item map.  The FileID will be read from the
		 * existing property file
		 * @param parent
		 * @param name
		 * @param fileId unique file ID from property file content
		 * @param storageName
		 */
		void set(Folder newParent, String newName) {
			if (parent != null && itemStorage != null) {
				parent.items.remove(itemStorage.itemName);
			}
			parent = newParent;
			itemStorage = new IndexedItemStorage(getStorageDir(storageName), storageName,
				parent.getPathname(), newName);
			parent.items.put(newName, this);
			try {
				setFileID(itemStorage.getPropertyFile().getFileID());
			}
			catch (IOException e) {
				setFileID(null);
			}
		}

		String getName() {
			return itemStorage.itemName;
		}

		void setFileID(String newFileId) {
			if (fileId != null) {
				unmapFileID(fileId);
			}
			fileId = newFileId;
			if (fileId != null) {
				mapFileID(fileId, this);
			}
		}

		String getFileID() {
			return fileId;
		}

		String getStorageName() {
			return itemStorage.storageName;
		}

		String getPathname() {
			return getPath(parent.getPathname(), itemStorage.itemName);
		}

		@Override
		public String toString() {
			return itemStorage.toString();
		}
	}

	class Folder {
		// root folder has null parent and null name
		Folder parent;
		String name;
		Map<String, Item> items = new TreeMap<>();
		Map<String, Folder> folders = new TreeMap<>();

		public String getPathname() {
			if (parent == null) {
				return SEPARATOR;
			}
			return getPath(parent.getPathname(), name);
		}

		@Override
		public String toString() {
			StringBuffer buf = new StringBuffer();
			String path = getPathname();
			Folder p = parent;
			while (p != null) {
				buf.append(' ');
				p = p.parent;
			}
			String pad = buf.toString();
			buf.append(path);
			for (Item item : items.values()) {
				buf.append('\n');
				buf.append(pad);
				buf.append(' ');
				buf.append(item.toString());
				if (item.parent != this) {
					buf.append(" **BAD-PARENT**");
				}
			}
			for (Folder sf : folders.values()) {
				buf.append('\n');
				buf.append(sf.toString());
			}
			return buf.toString();
//			return getPathname();
		}
	}

	class IndexJournal {

		private PrintWriter journalWriter;

		IndexJournal() throws IOException {
			if (journalFile.exists()) {
				replayJournal();
			}
		}

		/**
		 * Close index journal
		 */
		void close() {
			if (journalWriter != null) {
				journalWriter.close();
				journalWriter = null;
			}
			if (journalCount >= INDEX_REWRITE_JOURNAL_LIMIT) {
				flushIndex();
			}
		}

		void open() throws IOException {
			if (readOnly) {
				throw new ReadOnlyException();
			}
			journalWriter = new PrintWriter(new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(journalFile, true), "UTF8")));
		}

		private void replayJournal() throws IndexReadException {
			Msg.info(this, "restoring data storage index...");
			int lineNum = 0;
			BufferedReader journalReader = null;
			try {
				journalReader = new BufferedReader(new InputStreamReader(
					new BufferedInputStream(new FileInputStream(journalFile)), "UTF8"));
				String line;
				while ((line = journalReader.readLine()) != null) {
					++lineNum;
					String[] args = line.split(":");
					if ("FADD".equals(args[0])) {
						replayFolderAdd(args[1]);
					}
					else if ("FDEL".equals(args[0])) {
						replayFolderDelete(args[1]);
					}
					else if ("FMV".equals(args[0])) {
						replayFolderMove(args[1], args[2]);
					}
					else if ("IADD".equals(args[0])) {
						replayItemAdd(args[1], args[2]);
					}
					else if ("IDEL".equals(args[0])) {
						replayItemDelete(args[1]);
					}
					else if ("IMV".equals(args[0])) {
						replayItemMove(args[1], args[2]);
					}
					else if ("IDSET".equals(args[0])) {
						replayFileIdSet(args[1], args[2]);
					}
					else {
						throw new IndexReadException("Invalid index journal (" + lineNum +
							") - unable to replay: " + journalFile);
					}
				}
				journalReader.close();
				journalReader = null;

				journalCount = lineNum;
				if (!readOnly) {
					writeIndex();
				}
			}
			catch (Exception e) {
				if (e instanceof IndexReadException) {
					throw (IndexReadException) e;
				}
				throw new IndexReadException(
					"Index journal error (" + lineNum + ") - unable to replay: " + journalFile, e);
			}
			finally {
				if (journalReader != null) {
					try {
						journalReader.close();
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}

		private void replayFolderAdd(String folderPath)
				throws NotFoundException, DuplicateFileException {
			int index = folderPath.lastIndexOf(SEPARATOR);
			String name = folderPath.substring(index + 1);
			String parentPath = index == 0 ? SEPARATOR : folderPath.substring(0, index);
			Folder parent = getFolder(parentPath, GetFolderOption.CREATE_ALL);
			if (parent.folders.get(name) != null) {
				throw new DuplicateFileException("Folder already exists: " + folderPath);
			}
			Folder folder = new Folder();
			folder.parent = parent;
			folder.name = name;
			parent.folders.put(name, folder);
		}

		private void replayFolderDelete(String folderPath) throws NotFoundException {
			Folder folder = getFolder(folderPath, GetFolderOption.READ_ONLY);
			folder.parent.folders.remove(folder.name);
		}

		private void replayFolderMove(String oldPath, String newPath)
				throws NotFoundException, DuplicateFileException {
			Folder folder = getFolder(oldPath, GetFolderOption.READ_ONLY);
			int index = newPath.lastIndexOf(SEPARATOR);
			String newName = newPath.substring(index + 1);
			String newParentPath = index == 0 ? SEPARATOR : newPath.substring(0, index);
			Folder newParent = getFolder(newParentPath, GetFolderOption.CREATE_ALL);
			if (newParent.folders.get(newName) != null) {
				throw new DuplicateFileException("Folder already exists: " + newPath);
			}
			folder.parent.folders.remove(folder.name);
			folder.name = newName;
			folder.parent = newParent;
			newParent.folders.put(newName, folder);
		}

		private void replayItemAdd(String storageName, String itemPath)
				throws NotFoundException, BadStorageNameException, DuplicateFileException {
			int index = itemPath.lastIndexOf(SEPARATOR);
			String name = itemPath.substring(index + 1);
			String parentPath = index == 0 ? SEPARATOR : itemPath.substring(0, index);
			Folder parent = getFolder(parentPath, GetFolderOption.CREATE_ALL);
			if (parent.items.get(name) != null) {
				throw new DuplicateFileException("Item already exists: " + itemPath);
			}
			new Item(parent, name, storageName);
			bumpNextFileIndexID(storageName);
		}

		private void replayItemDelete(String itemPath) throws NotFoundException {
			int index = itemPath.lastIndexOf(SEPARATOR);
			String name = itemPath.substring(index + 1);
			String parentPath = index == 0 ? SEPARATOR : itemPath.substring(0, index);
			Folder parent = getFolder(parentPath, GetFolderOption.READ_ONLY);
			if (parent.items.remove(name) == null) {
				throw new NotFoundException("Item not found: " + itemPath);
			}
		}

		private void replayItemMove(String oldPath, String newPath) throws NotFoundException {
			int index = oldPath.lastIndexOf(SEPARATOR);
			String name = oldPath.substring(index + 1);
			String parentPath = index == 0 ? SEPARATOR : oldPath.substring(0, index);
			Folder parent = getFolder(parentPath, GetFolderOption.READ_ONLY);
			Item item = parent.items.get(name);
			if (item == null) {
				throw new NotFoundException("Item not found: " + oldPath);
			}
			index = newPath.lastIndexOf(SEPARATOR);
			String newName = newPath.substring(index + 1);
			String newParentPath = index == 0 ? SEPARATOR : newPath.substring(0, index);
			Folder newParent = getFolder(newParentPath, GetFolderOption.CREATE_ALL);
			if (newParent.items.get(newName) != null) {
				throw new NotFoundException("Item already exists: " + newPath);
			}
			parent.items.remove(name);
			item.set(newParent, newName, item.getFileID());
			newParent.items.put(newName, item);
		}

		private void replayFileIdSet(String path, String fileId) throws NotFoundException {
			int index = path.lastIndexOf(SEPARATOR);
			String name = path.substring(index + 1);
			String parentPath = index == 0 ? SEPARATOR : path.substring(0, index);
			Folder parent = getFolder(parentPath, GetFolderOption.READ_ONLY);
			Item item = parent.items.get(name);
			if (item == null) {
				throw new NotFoundException("Item not found: " + path);
			}
			item.setFileID(fileId);
		}

		void addFolder(String folderPath) throws IOException {
			journalWriter.println("FADD:" + folderPath);
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}

		void deleteFolder(String folderPath) throws IOException {
			journalWriter.println("FDEL:" + folderPath);
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}

		void moveFolder(String oldPath, String newPath) throws IOException {
			journalWriter.println("FMV:" + oldPath + ":" + newPath);
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}

		void addItem(Item item) throws IOException {
			journalWriter.println("IADD:" + item.getStorageName() + ":" + item.getPathname());
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}

		void deleteItem(Item item) throws IOException {
			journalWriter.println("IDEL:" + item.getPathname());
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}

		void moveItem(String oldPath, String newPath) throws IOException {
			journalWriter.println("IMV:" + oldPath + ":" + newPath);
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}

		void fileIdSet(String path, String fileId) throws IOException {
			journalWriter.println("IDSET:" + path + ":" + fileId);
			++journalCount;
			if (journalWriter.checkError()) {
				throw new IOException("Journal update error");
			}
		}
	}

	/**
	 * Determine if the specified directory corresponds to an 
	 * indexed filesystem.
	 * @param rootPath filesystem root
	 * @return true if filesystem contains an index (not mangled)
	 */
	public static boolean isIndexed(String rootPath) {
		File rootFile = new File(rootPath);
		if (!rootFile.isDirectory()) {
			return false;
		}
		File indexFile = new File(rootPath, INDEX_FILE);
		return indexFile.exists();
	}

	/**
	 * Determine if the specified directory contains a likely 
	 * indexed filesystem.
	 * @param rootPath filesystem root
	 * @return true if filesystem appears to be indexed (not mangled)
	 */
	public static boolean hasIndexedStructure(String rootPath) {
		File rootFile = new File(rootPath);
		if (rootFile.isDirectory()) {
			try {
				int itemCount = verifyIndexedFileStructure(rootFile);
				// if there are no items assume it is not indexed
				// since we rely on property files to make this
				// determination
				return itemCount != 0;
			}
			catch (IndexReadException e) {
				// contains non-indexed content
			}
		}
		return false;
	}

	/**
	 * Get the V0 indexed-file-system instance.  File system storage should first be 
	 * pre-qualified as an having indexed storage using the {@link #isIndexed(String)} method.
	 * @param rootPath
	 * @param isVersioned
	 * @param readOnly
	 * @param enableAsyncronousDispatching
	 * @return file-system instance
	 * @throws IOException
	 */
	static IndexedLocalFileSystem getFileSystem(String rootPath, boolean isVersioned,
			boolean readOnly, boolean enableAsyncronousDispatching) throws IOException {
		try {
			return new IndexedLocalFileSystem(rootPath, isVersioned, readOnly,
				enableAsyncronousDispatching, false);
		}
		catch (IndexReadException e) {
			if (readOnly) {
				throw e; // don't attempt repair if read-only
			}

			Msg.error(LocalFileSystem.class, "Indexed filesystem error: " + e.getMessage());

			Msg.info(LocalFileSystem.class, "Attempting index rebuild: " + rootPath);
			if (!IndexedLocalFileSystem.rebuild(new File(rootPath))) {
				throw e;
			}

			// retry after index rebuild
			return new IndexedLocalFileSystem(rootPath, isVersioned, readOnly,
				enableAsyncronousDispatching, false);
		}
	}

	/**
	 * Completely rebuild filesystem index using item information contained
	 * within indexed property files.  Empty folders will be lost.
	 * @param rootDir
	 * @throws IOException
	 */
	public static boolean rebuild(File rootDir) throws IOException {

		verifyIndexedFileStructure(rootDir);

		IndexedLocalFileSystem fs = new IndexedLocalFileSystem(rootDir.getAbsolutePath());
		fs.rebuildIndex();
		fs.cleanupAfterConstruction();
		fs.dispose();

		File errorFile = new File(rootDir, REBUILD_ERROR_FILE);
		if (errorFile.exists()) {
			Msg.error(LocalFileSystem.class,
				"Indexed filesystem rebuild failed, see log for details: " + errorFile);
			return false;
		}
		Msg.info(LocalFileSystem.class, "Index rebuild completed: " + rootDir);
		return true;
	}

	static class IndexedItemStorage extends ItemStorage {

		IndexedItemStorage(File dir, String storageName, String folderPath, String itemName) {
			super(dir, storageName, folderPath, itemName);
		}

		@Override
		PropertyFile getPropertyFile() throws IOException {
			return new IndexedPropertyFile(dir, storageName, folderPath, itemName);
		}
	}

	/**
	 * <code>BadStorageNameException</code> invalid storage name
	 * encountered.
	 */
	public static class BadStorageNameException extends IOException {

		private static final long serialVersionUID = 1L;

		BadStorageNameException(String storageName) {
			super("Bad item storage name (expected hex value): " + storageName);
		}
	}

	/**
	 * <code>IndexReadException</code> occurs when an error occurs
	 * while reading/processing the filesystem index
	 */
	public static class IndexReadException extends IOException {

		private static final long serialVersionUID = 1L;

		IndexReadException(String msg) {
			super(msg);
		}

		IndexReadException(String msg, Throwable cause) {
			super(msg, cause);
		}
	}

	/**
	 * <code>IndexReadException</code> occurs when an error occurs
	 * while reading/processing the filesystem index
	 */
	public static class IndexVersionException extends IndexReadException {

		private static final long serialVersionUID = 1L;

		boolean canUpgrade = false;

		IndexVersionException(String msg, boolean canUpgrade) {
			super(msg);
			this.canUpgrade = canUpgrade;
		}

		public boolean canUpgrade() {
			return canUpgrade;
		}
	}

}
