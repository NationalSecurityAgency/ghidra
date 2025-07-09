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
package ghidra.framework.store;

import java.io.*;
import java.util.ArrayList;
import java.util.NoSuchElementException;

import db.buffers.BufferFile;
import db.buffers.ManagedBufferFile;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.framework.store.remote.RemoteFileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>FileSystem</code> provides a hierarchical view and management of a 
 * set of files and folders.  
 */
public interface FileSystem {

	/**
	 * Character used to separate folder and item names within a path string.
	 */
	public static final char SEPARATOR_CHAR = '/';
	public static final String SEPARATOR = Character.toString(SEPARATOR_CHAR);

	/**
	 * Get user name associated with this filesystem.  In the case of a remote filesystem
	 * this will correspond to the name used during login/authentication.  A null value may 
	 * be returned if user name unknown.
	 * @return user name used to authenticate or null if not-applicable
	 */
	public String getUserName();

	/**
	 * {@return true if the file-system requires check-outs when
	 * modifying folder items.}
	 */
	public boolean isVersioned();

	/**
	 * {@return true if file-system is on-line.}
	 */
	public boolean isOnline();

	/**
	 * {@return true if file-system is read-only.}
	 * @throws IOException if IO error occurs
	 */
	public boolean isReadOnly() throws IOException;

	/**
	 * {@return the number of folder items contained within this file-system.}
	 * @throws IOException if an IO error occurs
	 * @throws UnsupportedOperationException if file-system does not support this operation
	 */
	public int getItemCount() throws IOException, UnsupportedOperationException;

	/**
	 * {@return a list of the folder item names contained in the given folder.}
	 * @param folderPath the path of the folder.
	 * @throws IOException if an IO error occurs
	 */
	public String[] getItemNames(String folderPath) throws IOException;

	/**
	 * Returns a list of the folder items contained in the given folder.
	 * @param folderPath the path of the folder.
	 * @return a list of folder items.  Null items may exist if index contained item name
	 * while storage was not found.  An {@link UnknownFolderItem} may be returned if unsupported
	 * item storage encountered.
	 * @throws IOException if an IO error occurs
	 */
	public FolderItem[] getItems(String folderPath) throws IOException;

	/**
	 * Returns the FolderItem in the given folder with the given name
	 * @param folderPath the folder path containing the item.
	 * @param name the name of the item.
	 * @return the FolderItem with the given folderPath and name, or null if it doesn't exist.
	 * @throws IOException if IO error occurs.
	 */
	public FolderItem getItem(String folderPath, String name) throws IOException;

	/**
	 * Returns the FolderItem specified by its unique File-ID
	 * @param fileID the items unique file ID
	 * @return the FolderItem with the given folderPath and name, or null if it doesn't exist.
	 * @throws IOException if IO error occurs.
	 * @throws UnsupportedOperationException if file-system does not support this operation
	 */
	public FolderItem getItem(String fileID) throws IOException, UnsupportedOperationException;

	/**
	 * Return a list of subfolders (by name) that are stored within the specified folder path.
	 * @param folderPath folder path
	 * @return subfolders names
	 * @throws FileNotFoundException if folder path does not exist.
	 * @throws IOException if IO error occurs.
	 */
	public String[] getFolderNames(String folderPath) throws IOException;

	/**
	 * Creates a new subfolder within the specified parent folder.
	 * @param parentPath folder path of parent
	 * @param folderName name of new subfolder
	 * @throws DuplicateFileException if a folder exists with this name
	 * @throws InvalidNameException if the name does not have
	 * all alphanumerics
	 * @throws IOException thrown if an IO error occurs.
	 */
	public void createFolder(String parentPath, String folderName)
			throws InvalidNameException, IOException;

	/**
	 * Determine if the specified folder item is supported by this filesystem's interface and 
	 * storage.  This method primarily exists to determine if a remote server can support
	 * the specified content.  This can come into play as new storage formats are added
	 * to a {@link LocalFileSystem} but may not be supported by a connected {@link RemoteFileSystem}.
	 * @param folderItem folder item
	 * @return true if folder item storage is supported
	 */
	public boolean isSupportedItemType(FolderItem folderItem);

	/**
	 * Create a new database item within the specified parent folder using the contents
	 * of the specified BufferFile.
	 * @param parentPath folder path of parent
	 * @param name new database name
	 * @param fileID file ID to be associated with new database or null
	 * @param bufferFile data source
	 * @param comment version comment (used for versioned file system only)
	 * @param contentType application defined content type
	 * @param resetDatabaseId if true database ID will be reset for new Database
	 * @param monitor allows the database copy to be monitored and cancelled.
	 * @param user name of user creating item (required for versioned item)
	 * @return new DatabaseItem
	 * @throws FileNotFoundException thrown if parent folder does not exist.
	 * @throws DuplicateFileException if a folder item exists with this name
	 * @throws InvalidNameException if the name does not have
	 * all alphanumerics
	 * @throws IOException if an IO error occurs.
	 * @throws CancelledException if cancelled by monitor
	 */
	public DatabaseItem createDatabase(String parentPath, String name, String fileID,
			BufferFile bufferFile, String comment, String contentType, boolean resetDatabaseId,
			TaskMonitor monitor, String user)
			throws InvalidNameException, IOException, CancelledException;

	/**
	 * Create a new empty database item within the specified parent folder. 
	 * If this is a versioned file-system, the associated item is checked-out.
	 * The resulting checkoutId can be obtained from the returned buffer file.
	 * @param parentPath folder path of parent
	 * @param name new database name
	 * @param fileID file ID to be associated with new database or null
	 * @param contentType application defined content type
	 * @param bufferSize buffer size.  If copying an existing BufferFile, the buffer 
	 * size must be the same as the source file.
	 * @param user name of user creating item (required for versioned item)
	 * @param projectPath path of project in which database is checked-out (required for versioned item)
	 * @return an empty BufferFile open for read-write.
	 * @throws FileNotFoundException thrown if parent folder does not exist.
	 * @throws DuplicateFileException if a folder item exists with this name
	 * @throws InvalidNameException if the name has illegal characters.
	 * @throws IOException if an IO error occurs.
	 */
	public ManagedBufferFile createDatabase(String parentPath, String name, String fileID,
			String contentType, int bufferSize, String user, String projectPath)
			throws InvalidNameException, IOException;

	/**
	 * Creates a new empty data file within the specified parent folder.
	 * @param parentPath folder path of parent
	 * @param name new data file name
	 * @param istream source data
	 * @param comment version comment (used for versioned file system only)
	 * @param contentType application defined content type
	 * @param monitor progress monitor (used for cancel support, 
	 * progress not used since length of input stream is unknown)
	 * @return new data file
	 * @throws DuplicateFileException Thrown if a folderItem with that name already exists.
	 * @throws InvalidNameException if the name has illegal characters.
	 * @throws IOException if an IO error occurs.
	 * @throws CancelledException if cancelled by monitor
	 */
	public DataFileItem createDataFile(String parentPath, String name, InputStream istream,
			String comment, String contentType, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException;

	/**
	 * Creates a new text data file within the specified parent folder.
	 * @param parentPath folder path of parent
	 * @param name new data file name
	 * @param fileID file ID to be associated with new file or null
	 * @param contentType application defined content type
	 * @param textData text data (required)
	 * @param comment file comment (may be null, only used if versioning is enabled)
	 * @return new data file
	 * @throws DuplicateFileException Thrown if a folderItem with that name already exists.
	 * @throws InvalidNameException if the name has illegal characters.
	 * @throws IOException if an IO error occurs.
	 */
	public TextDataItem createTextDataItem(String parentPath, String name, String fileID,
			String contentType, String textData, String comment)
			throws InvalidNameException, IOException;

	/**
	 * Creates a new file item from a packed file.
	 * The content/item type must be determined from the input stream.
	 * @param parentPath folder path of parent
	 * @param name new data file name
	 * @param packedFile packed file data
	 * @param monitor progress monitor (used for cancel support, 
	 * progress not used since length of input stream is unknown)
	 * @param user name of user creating item (required for versioned item)
	 * @return new item
	 * @throws InvalidNameException if the name has illegal characters.
	 * all alphanumerics
	 * @throws IOException if an IO error occurs.
	 * @throws CancelledException if cancelled by monitor
	 */
	public FolderItem createFile(String parentPath, String name, File packedFile,
			TaskMonitor monitor, String user)
			throws InvalidNameException, IOException, CancelledException;

	/**
	 * Delete the specified folder.
	 * @param folderPath path of folder to be deleted
	 * @throws FolderNotEmptyException Thrown if the folder is not empty.
	 * @throws FileNotFoundException if there is no folder with the given path name.
	 * @throws IOException if error occurred during delete.
	 */
	public void deleteFolder(String folderPath) throws IOException;

	/**
	 * Move the specified folder to the path specified by newFolderPath. 
	 * The moved folder must not be an ancestor of the new Parent.
	 * @param parentPath path of parent folder that the moving folder currently resides in.
	 * @param folderName name of the folder within the parentPath to be moved.
	 * @param newParentPath path to where the folder is to be moved.
	 * @throws FileNotFoundException if the moved folder does not exist.
	 * @throws DuplicateFileException if folder with the same name exists within the new parent folder
	 * @throws FileInUseException if any file within this folder or its descendants are in-use or checked-out
	 * @throws IOException if an IO error occurs.
	 * @throws InvalidNameException if the new FolderPath contains an illegal file name.
	 * @throws IllegalArgumentException if new Parent is invalid.
	 */
	public void moveFolder(String parentPath, String folderName, String newParentPath)
			throws InvalidNameException, IOException;

	/**
	 * Renames the specified folder to a new name.
	 * @param parentPath the parent folder of the folder to be renamed.
	 * @param folderName the current name of the folder to be renamed.
	 * @param newFolderName the name the folder to be renamed to.
	 * @throws FileNotFoundException if the folder to be renamed does not exist.
	 * @throws DuplicateFileException if folder with the new name already exists.
	 * @throws FileInUseException if any file within this folder or its descendants are in-use or checked-out
	 * @throws IOException if an IO error occurs.
	 * @throws InvalidNameException if the new FolderName contains an illegal file name.
	 */
	public void renameFolder(String parentPath, String folderName, String newFolderName)
			throws InvalidNameException, IOException;

	/**
	 * Moves the specified item to a new folder.
	 * @param folderPath path of folder containing the item.
	 * @param name name of the item to be moved.
	 * @param newFolderPath path of folder where item is to be moved to.
	 * @param newName new item name to be applied
	 * @throws FileNotFoundException if the item does not exist.
	 * @throws DuplicateFileException if item with the same name exists within the new parent folder.
	 * @throws FileInUseException if the item is in-use or checked-out
	 * @throws IOException if an IO error occurs.
	 * @throws InvalidNameException if the newName is invalid
	 */
	public void moveItem(String folderPath, String name, String newFolderPath, String newName)
			throws IOException, InvalidNameException;

	/**
	 * Adds a file system listener to be notified of file system changes.
	 * @param listener the listener to be added.
	 */
	public void addFileSystemListener(FileSystemListener listener);

	/**
	 * Removes a file system listener from being notified of file system changes.
	 * @param listener file system listener
	 */
	public void removeFileSystemListener(FileSystemListener listener);

	/**
	 * Returns true if the folder specified by the path exists.
	 * @param folderPath the name of the folder to check for existence.
	 * @return true if the folder exists.
	 * @throws IOException if an IO error occurs.
	 */
	public boolean folderExists(String folderPath) throws IOException;

	/**
	 * {@return true if the file exists}
	 * @param folderPath the folderPath of the folder that may contain the file.
	 * @param name the name of the file to check for existence.
	 * @throws IOException if an IO error occurs.
	 */
	public boolean fileExists(String folderPath, String name) throws IOException;

	/**
	 * {@return true if this file system is shared}
	 */
	public boolean isShared();

	/**
	 * Cleanup and release resources
	 */
	public void dispose();

	/**
	 * Normalize an absolute path, removing all "." and ".." use.
	 * <P>
	 * NOTE: This method does not consider possible linked folder traversal which may
	 * get ignored when flattening/simplifying path.
	 * 
	 * @param path absolute filesystem path which may contain "." or ".." path elements.
	 * @return normalized path
	 * @throws IllegalArgumentException if an absolute path starting with {@link #SEPARATOR}
	 * was not specified or an illegal path was specified.
	 */
	public static String normalizePath(String path) throws IllegalArgumentException {
		if (!path.startsWith(SEPARATOR)) {
			throw new IllegalArgumentException("Absolute path required");
		}

		String[] split = path.split(SEPARATOR);

		ArrayList<String> elements = new ArrayList<>();
		for (int i = 1; i < split.length; i++) {
			String e = split[i];
			if (e.length() == 0) {
				throw new IllegalArgumentException("Invalid path with empty element: " + path);
			}
			if ("..".equals(e)) {
				try {
					// remove last element
					elements.removeLast();
				}
				catch (NoSuchElementException ex) {
					throw new IllegalArgumentException("Invalid path: " + path);
				}
			}
			else if (".".equals(e)) {
				// ignore element
				continue;
			}
			else {
				elements.add(e);
			}
		}

		if (elements.isEmpty()) {
			return SEPARATOR;
		}

		StringBuilder buf = new StringBuilder();
		for (String e : elements) {
			buf.append(SEPARATOR);
			buf.append(e);
		}
		return buf.toString();
	}

}
