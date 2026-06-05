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

import ghidra.util.exception.DuplicateFileException;

public class IndexedPropertyFile extends ItemPropertyFile {

	protected static final String NAME_PROPERTY = "NAME";
	protected static final String PARENT_PATH_PROPERTY = "PARENT";

	/**
	 * Construct a new or existing PropertyFile.
	 * This constructor ignores retained property values for NAME and PARENT path.
	 * This constructor will not throw an exception if the file does not exist.
	 * @param dir parent directory
	 * @param storageName stored property file name (without extension)
	 * @param parentPath path to parent
	 * @param name name of the property file
	 * @throws InvalidObjectException if a file parse error occurs
	 * @throws IOException if an IO error occurs reading an existing file
	 */
	public IndexedPropertyFile(File dir, String storageName, String parentPath, String name)
			throws IOException {
		super(dir, storageName, parentPath, name);
		if (contains(NAME_PROPERTY) && contains(PARENT_PATH_PROPERTY)) {
			this.name = getString(NAME_PROPERTY, name);
			this.parentPath = getString(PARENT_PATH_PROPERTY, parentPath);
		}
		else {
			// new property file
			putString(NAME_PROPERTY, name);
			putString(PARENT_PATH_PROPERTY, parentPath);
		}
	}

	/**
	 * Construct a existing PropertyFile.
	 * This constructor uses property values for NAME and PARENT path.
	 * @param dir parent directory
	 * @param storageName stored property file name (without extension)
	 * @throws FileNotFoundException if property file does not exist
	 * @throws InvalidObjectException if a file parse error occurs
	 * @throws IOException if error occurs reading property file
	 */
	public IndexedPropertyFile(File dir, String storageName) throws IOException {
		super(dir, storageName, null, null);
		if (!exists()) {
			throw new FileNotFoundException(
				new File(dir, storageName + PROPERTY_EXT) + " not found");
		}
		name = getString(NAME_PROPERTY, null);
		parentPath = getString(PARENT_PATH_PROPERTY, null);
		if (name == null || parentPath == null) {
			throw new IOException("Invalid indexed property file: " + propertyFile);
		}
	}

	/**
	 * Construct a existing PropertyFile.
	 * This constructor uses property values for NAME and PARENT path.
	 * @param file property file
	 * @throws FileNotFoundException if property file does not exist
	 * @throws InvalidObjectException if a file parse error occurs
	 * @throws IOException if error occurs reading property file
	 */
	public IndexedPropertyFile(File file) throws IOException {
		this(file.getParentFile(), getStorageName(file.getName()));
	}

	private static String getStorageName(String propertyFileName) {
		if (!propertyFileName.endsWith(PROPERTY_EXT)) {
			throw new IllegalArgumentException("property file name must have .prp file extension");
		}
		return propertyFileName.substring(0, propertyFileName.length() - PROPERTY_EXT.length());
	}

	@Override
	public void moveTo(File newParent, String newStorageName, String newParentPath, String newName)
			throws DuplicateFileException, IOException {
		String oldName = name;
		String oldParentPath = parentPath;
		super.moveTo(newParent, newStorageName, newParentPath, newName);
		if (!newParentPath.equals(oldParentPath) || !newName.equals(oldName)) {
			putString(NAME_PROPERTY, name);
			putString(PARENT_PATH_PROPERTY, parentPath);
			writeState();
		}
	}

}
