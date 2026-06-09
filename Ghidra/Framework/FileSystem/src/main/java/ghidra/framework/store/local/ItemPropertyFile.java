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

import javax.help.UnsupportedOperationException;

import ghidra.framework.store.FileSystem;
import ghidra.framework.store.FolderItem;
import ghidra.util.PropertyFile;
import ghidra.util.exception.DuplicateFileException;

/**
 * {@link ItemPropertyFile} provides basic property storage which is primarily intended to 
 * store limited information related to a logical {@link FolderItem}.  The file
 * extension used is {@link #PROPERTY_EXT}.
 */
public class ItemPropertyFile extends PropertyFile {

	private static final String FILE_ID_PROPERTY = "FILE_ID";

	protected String name;
	protected String parentPath;

	/**
	 * Construct a new or existing PropertyFile.
	 * This constructor ignores retained property values for NAME and PARENT path.
	 * This constructor will not throw an exception if the file does not exist.
	 * @param dir native directory where this file is stored
	 * @param storageName stored property file name (without extension)
	 * @param parentPath logical parent path for the associated item
	 * @param name name of the associated item
	 * @throws InvalidObjectException if a file parse error occurs
	 * @throws IOException if an IO error occurs reading an existing file
	 */
	public ItemPropertyFile(File dir, String storageName, String parentPath, String name)
			throws IOException {
		super(dir, storageName);
		this.name = name;
		this.parentPath = parentPath;
	}

	/**
	 * Return the name of the item associated with this PropertyFile.  A null value may be returned
	 * if this is an older property file and the name was not specified at
	 * time of construction.
	 * @return associated item name or null if unknown
	 */
	public String getName() {
		return name;
	}

	/**
	 * Return the logical path of the item associated with this PropertyFile.  A null value may be 
	 * returned if this is an older property file and the name and parentPath was not specified at
	 * time of construction.
	 * @return logical path of the associated item or null if unknown
	 */
	public String getPath() {
		if (parentPath == null || name == null) {
			return null;
		}
		if (parentPath.length() == 1) {
			return parentPath + name;
		}
		return parentPath + FileSystem.SEPARATOR_CHAR + name;
	}

	/**
	 * Return the logical parent path containing the item descibed by this PropertyFile.
	 * @return logical parent directory path
	 */
	public String getParentPath() {
		return parentPath;
	}

	/**
	 * Returns the FileID associated with this file.
	 * @return FileID associated with this file or null
	 */
	public String getFileID() {
		return getString(FILE_ID_PROPERTY, null);
	}

	/**
	 * Set the FileID associated with this file.
	 * @param fileId unique file ID
	 */
	public void setFileID(String fileId) {
		putString(FILE_ID_PROPERTY, fileId);
	}

	/**
	 * Move this PropertyFile to the newParent file.
	 * @param newStorageParent new storage parent of the native file
	 * @param newStorageName new storage name for this property file
	 * @param newParentPath new logical parent path
	 * @param newName new logical item name
	 * @throws IOException thrown if there was a problem accessing the
	 * @throws DuplicateFileException thrown if a file with the newName
	 * already exists
	 */
	public void moveTo(File newStorageParent, String newStorageName, String newParentPath,
			String newName) throws DuplicateFileException, IOException {
		super.moveTo(newStorageParent, newStorageName);
		if (!newParentPath.equals(parentPath) || !newName.equals(name)) {
			parentPath = newParentPath;
			name = newName;
		}
	}

	/**
	 * NOTE!! This method must not be used.
	 * <P>
	 * Movement of an item is related to its logical pathname and must be accomplished
	 * with the {@link #moveTo(File, String, String, String)} method. There is no supported
	 * direct use of this method.
	 * 
	 * @param newStorageParent new storage parent of the native file
	 * @param newStorageName new storage name for this property file
	 * @throws UnsupportedOperationException always thrown
	 * @deprecated method must not be used
	 */
	@Deprecated(forRemoval = false, since = "11.4")
	@Override
	public final void moveTo(File newStorageParent, String newStorageName)
			throws UnsupportedOperationException {
		throw new UnsupportedOperationException();
	}

}
