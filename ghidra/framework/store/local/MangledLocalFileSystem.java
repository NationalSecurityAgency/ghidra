/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.framework.store.FolderNotEmptyException;
import ghidra.util.*;
import ghidra.util.exception.DuplicateFileException;

import java.io.*;
import java.util.ArrayList;
import java.util.Collections;

import utilities.util.FileUtilities;

/**
 * <code>MangledLocalFileSystem</code> implements the legacy project data storage 
 * scheme which utilizes a simplified name mangling which provides case-sensitive 
 * file-naming with support for spaces.  Project folder hierarchy maps directly to
 * the actual storage hierarchy.
 */
public class MangledLocalFileSystem extends LocalFileSystem {

	public static final int MAX_NAME_LENGTH = 60; // allow room for name mangling

	private boolean migrationInProgress = false;

	/**
	 * Constructor.
	 * @param rootPath path for root directory (must already exist).
	 * @param isVersioned if true item versioning will be enabled.
	 * @param readOnly if true modifications within this file-system will not be allowed
	 * and result in an ReadOnlyException
	 * @param enableAsyncronousDispatching if true a separate dispatch thread will be used
	 * to notify listeners.  If false, blocking notification will be performed.
	 * @throws FileNotFoundException if specified rootPath does not exist
	 */
	MangledLocalFileSystem(String rootPath, boolean isVersioned, boolean readOnly,
			boolean enableAsyncronousDispatching) throws FileNotFoundException {
		super(rootPath, isVersioned, readOnly, enableAsyncronousDispatching);
		if (!readOnly) {
			cleanupAfterConstruction();
		}
	}

	/**
	 * Constructor for an empty read-only file-system.
	 */
	MangledLocalFileSystem() {
		super();
	}

	@Override
	public int getMaxNameLength() {
		return MAX_NAME_LENGTH;
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
		File dir = getFile(folderPath);
		String storageName = mangleName(itemName);
		return new ItemStorage(dir, storageName, folderPath, itemName);
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

		ItemStorage itemStorage = findItemStorage(folderPath, itemName);
		File pf = new File(itemStorage.dir, itemStorage.storageName + PROPERTY_EXT);
		if (pf.exists()) {
			throw new DuplicateFileException(getPath(folderPath, itemName) + " already exists.");
		}

		createFolders(itemStorage.dir, folderPath);

		return itemStorage;
	}

	/**
	 * Deallocate item storage
	 * @param folderPath
	 * @param itemName
	 */
	@Override
	protected void deallocateItemStorage(String folderPath, String itemName) {
		// nothing to do for mangled name allocation
	}

	@Override
	public int getItemCount() {
		throw new UnsupportedOperationException("getItemCount");
	}

//	private int getItemCount(File dir) {
//		int count = 0;
//		for (File f : dir.listFiles()) {
//			String name = f.getName();
//
//			if (f.isDirectory()) {
//				if (name.startsWith(HIDDEN_DIR_PREFIX)) {
//					continue;
//				}
//				count += getItemCount(f);
//			}
//			else if (name.endsWith(PROPERTY_EXT)) {
//				++count;
//			}
//		}
//		return count;
//	}

	@Override
	protected String[] getItemNames(String folderPath, boolean includeHiddenFiles)
			throws IOException {

		File dir = getFile(folderPath);
		File[] dirList = dir.listFiles();
		if (dirList == null) {
			throw new FileNotFoundException("Folder " + folderPath + " not found");
		}
		ArrayList<String> fileList = new ArrayList<String>(dirList.length);
		for (int i = 0; i < dirList.length; i++) {
			String name = dirList[i].getName();
			if (name.endsWith(PROPERTY_EXT) && dirList[i].isFile()) {
				if (!NamingUtilities.isValidMangledName(dirList[i].getName())) {
					log.warn("Ignoring property file with bad name: " + dirList[i]);
					continue;
				}
				int index = name.lastIndexOf(PROPERTY_EXT);
				name = demangleName(name.substring(0, index));
				if (name != null && (includeHiddenFiles || !name.startsWith(HIDDEN_ITEM_PREFIX))) {
					fileList.add(name);
				}
			}
		}
		Collections.sort(fileList);
		return fileList.toArray(new String[fileList.size()]);
	}

	/*
	 * @see ghidra.framework.store.FileSystem#getFolders(java.lang.String)
	 */
	public synchronized String[] getFolderNames(String folderPath) throws IOException {
		File dir = getFile(folderPath);

		File[] dirList = dir.listFiles();
		if (dirList == null) {
			throw new FileNotFoundException("Folder " + folderPath + " not found");
		}
		ArrayList<String> folderList = new ArrayList<String>(dirList.length);
		for (int i = 0; i < dirList.length; i++) {
			if (!dirList[i].isDirectory()) {
				continue;
			}
			String name = demangleName(dirList[i].getName());
			if (name != null) {
				folderList.add(name);
			}
		}
		Collections.sort(folderList);
		return folderList.toArray(new String[folderList.size()]);
	}

	/*
	 * @see ghidra.framework.store.FileSystem#createFolder(java.lang.String, java.lang.String)
	 */
	public synchronized void createFolder(String parentPath, String folderName)
			throws InvalidNameException, IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(parentPath, true);
		testValidName(folderName, false);

		String path = getPath(parentPath, folderName);
		File dir = getFile(path);
		if (dir.exists()) {
			return; // ignore request if already exists
		}
		createFolders(dir, path);

	}

	/*
	 * @see ghidra.framework.store.FileSystem#deleteFolder(java.lang.String)
	 */
	public synchronized void deleteFolder(String folderPath) throws IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		if (SEPARATOR.equals(folderPath)) {
			throw new IOException("Root folder may not be deleted");
		}

		File file = getFile(folderPath);
		if (!file.exists()) {
			return;
		}
		if (!file.isDirectory()) {
			throw new FileNotFoundException(folderPath + " does not exist or is not a directory");
		}
		String[] contents = file.list();
		if (contents.length != 0) {
			if (contents.length > 1 || !".properties".equals(contents[0])) {
				throw new FolderNotEmptyException(folderPath + " is not empty");
			}
		}
		FileUtilities.deleteDir(file);

		listeners.folderDeleted(getParentPath(folderPath), getName(folderPath));
	}

	/*
	 * @see ghidra.framework.store.FileSystem#moveFolder(java.lang.String, java.lang.String, java.lang.String)
	 */
	public synchronized void moveFolder(String parentPath, String folderName, String newParentPath)
			throws InvalidNameException, IOException {

		boolean success = false;
		try {
			if (readOnly) {
				throw new ReadOnlyException();
			}

			testValidName(newParentPath, true);
			String folderPath = getPath(parentPath, folderName);
			File folder = getFile(folderPath);
			if (!folder.isDirectory()) {
				throw new FileNotFoundException(folderPath + " does not exist or is not a folder");
			}

			// TODO Must scan for items in use !!!

			String newFolderPath = getPath(newParentPath, folderName);
			File newFolder = getFile(newFolderPath);
			if (newFolder.exists()) {
				throw new DuplicateFileException(newFolderPath + " already exists.");
			}
			createFolders(getFile(newParentPath), newParentPath);
			if (!folder.renameTo(newFolder)) {
				throw new IOException("move failed for unknown reason");
			}

			listeners.folderMoved(parentPath, folderName, newParentPath);
			deleteEmptyVersionedFolders(parentPath);
		}
		finally {
			if (!success) {
				deleteEmptyVersionedFolders(newParentPath);
			}
		}
	}

	/*
	 * @see ghidra.framework.store.FileSystem#renameFolder(java.lang.String, java.lang.String, java.lang.String)
	 */
	public synchronized void renameFolder(String parentPath, String folderName, String newFolderName)
			throws InvalidNameException, IOException {

		if (readOnly) {
			throw new ReadOnlyException();
		}

		testValidName(newFolderName, false);
		String folderPath = getPath(parentPath, folderName);
		File folder = getFile(folderPath);
		if (!folder.isDirectory()) {
			throw new FileNotFoundException(folderPath + " does not exist or is not a folder");
		}
		String newFolderPath = getPath(parentPath, newFolderName);
		File newFolder = getFile(newFolderPath);
		if (newFolder.exists()) {
			throw new DuplicateFileException(newFolderPath + " already exists.");
		}

// TODO Must scan for items in use !!!

		if (!folder.renameTo(newFolder)) {
			throw new IOException("Folder may contain files that are in use");
		}

		listeners.folderRenamed(parentPath, folderName, newFolderName);
	}

	/**
	 * Returns the underlying File object which corresponds to the specified unmangled path.
	 * @param path unmangled path for folder or file
	 * @return File object
	 * @throws FileNotFoundException if specified file path does not begin with '/'
	 */
	private File getFile(String path) throws FileNotFoundException {
		if (root == null) {
			throw new FileNotFoundException("Empty read-only file system");
		}
		if (path.charAt(0) != SEPARATOR_CHAR) {
			throw new FileNotFoundException("Path names must begin with \'" + SEPARATOR_CHAR + "\'");
		}
		if (path.length() == 1) {
			return root;
		}
		path = toSystemDependantSeparator(manglePath(path));
		return new File(root, path);
	}

	private String manglePath(String path) {
		if (SEPARATOR.equals(path)) {
			return path;
		}
		StringBuilder buf = new StringBuilder();
		String[] split = path.split(SEPARATOR);
		for (int i = 0; i < split.length; i++) {
			buf.append(SEPARATOR_CHAR);
			buf.append(escapeHiddenDirPrefixChars(split[i]));
		}
		return NamingUtilities.mangle(buf.toString());
	}

	/**
	 * Mangle non-hidden name
	 * @param name
	 * @return mangled non-hidden name
	 */
	private String mangleName(String name) {
		return NamingUtilities.mangle(escapeHiddenDirPrefixChars(name));
	}

	/**
	 * Demangle non-hidden name
	 * @param name
	 * @return demangled name or null if name was hidden
	 */
	private String demangleName(String name) {
		// null will be returned if this is used on a hidden name
		return unescapeHiddenDirPrefixChars(NamingUtilities.demangle(name));
	}

	/**
	 * Convert the path separators to system specific File path separators.
	 * @param path file path
	 * @return modified file path
	 */
	private String toSystemDependantSeparator(String path) {
		int n = path.length();
		StringBuffer sb = new StringBuffer(n - 1);
		for (int i = 1; i < n; i++) {
			char c = path.charAt(i);
			c = (c == SEPARATOR_CHAR) ? File.separatorChar : c;
			sb.append(c);
		}
		return sb.toString();
	}

	/**
	 * Recursively create all directories associated with the specified
	 * folder path.
	 * @param folderDir folder path
	 */
	private void createFolders(File folderDir, String folderPath) throws FileNotFoundException {
		if (folderDir.exists()) {
			return;
		}
		File parentDir = folderDir.getParentFile();
		String parentPath = getParentPath(folderPath);
		createFolders(parentDir, parentPath);
		folderDir.mkdir();
		listeners.folderCreated(parentPath, getName(folderPath));
	}

	/*
	 * @see ghidra.framework.store.FileSystem#folderExists(java.lang.String)
	 */
	@Override
	public boolean folderExists(String folderPath) {
		try {
			File file = getFile(folderPath);
			return file.isDirectory();
		}
		catch (FileNotFoundException e) {
			return false;
		}
	}

	@Override
	public boolean migrationInProgress() {
		return migrationInProgress;
	}

	/**
	 * Convert this mangled filesystem to an indexed filesystem.  This instance should be discarded
	 * and not used once the conversion has completed.
	 * 
	 * @throws IOException
	 */
	public synchronized void convertToIndexedLocalFileSystem() throws IOException {

		if (readOnly) {
			throw new IOException("Unable to convert read-only filesystem");
		}

		cleanupAfterConstruction(); // remove all temporary content

		File tmpRoot =
			new File(root.getCanonicalFile().getParentFile(), HIDDEN_DIR_PREFIX + '.' +
				root.getName());
		if (tmpRoot.exists() || !tmpRoot.mkdir()) {
			throw new IOException("Failed to create data directory: " + tmpRoot);
		}

		IndexedV1LocalFileSystem indexedFs =
			new IndexedV1LocalFileSystem(tmpRoot.getAbsolutePath(), isVersioned, false, false, true);

		migrationInProgress = true;
		migrateFolder(SEPARATOR, indexedFs);
		indexedFs.dispose();

		for (File f : root.listFiles()) {
			File newFile = new File(tmpRoot, f.getName());
			f.renameTo(newFile);
		}

		if (!root.delete()) {
			throw new IOException("Failed to remove old root following conversion: " + root);
		}

		tmpRoot.renameTo(root);
	}

	private void migrateFolder(String folderPath, IndexedLocalFileSystem indexedFs)
			throws IOException {
		try {
			for (String name : getFolderNames(folderPath)) {
				indexedFs.createFolder(folderPath, name);
				migrateFolder(getPath(folderPath, name), indexedFs);
			}
			for (String name : getItemNames(folderPath)) {
				LocalFolderItem item = getItem(folderPath, name);
				indexedFs.migrateItem(item);
			}

			if (!SEPARATOR.equals(folderPath)) {
				// non-root should be empty - remove it
				File dir = getFile(folderPath);
				dir.delete();
			}
		}
		catch (InvalidNameException e) {
			throw new IOException("Unexpected exception", e);
		}
	}

}
