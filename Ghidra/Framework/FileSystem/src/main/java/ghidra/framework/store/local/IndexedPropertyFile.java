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

import ghidra.framework.store.FileSystem;
import ghidra.util.PropertyFile;
import ghidra.util.exception.DuplicateFileException;

import java.io.*;

public class IndexedPropertyFile extends PropertyFile {

	public final static String NAME_PROPERTY = "NAME";
	public final static String PARENT_PATH_PROPERTY = "PARENT";

	/**
	 * Construct a new or existing PropertyFile.
	 * This form ignores retained property values for NAME and PARENT path.
	 * @param dir parent directory
	 * @param storageName stored property file name (without extension)
	 * @param parentPath path to parent
	 * @param name name of the property file
	 * @throws IOException 
	 */
	public IndexedPropertyFile(File dir, String storageName, String parentPath, String name)
			throws IOException {
		super(dir, storageName, parentPath, name);
//		if (exists() &&
//			(!name.equals(getString(NAME_PROPERTY, null)) || !parentPath.equals(getString(
//				PARENT_PATH_PROPERTY, null)))) {
//			throw new AssertException();
//		}
		putString(NAME_PROPERTY, name);
		putString(PARENT_PATH_PROPERTY, parentPath);
	}

	/**
	 * Construct an existing PropertyFile.
	 * @param dir parent directory
	 * @param storageName stored property file name (without extension)
	 * @throws FileNotFoundException if property file does not exist
	 * @throws IOException if error occurs reading property file
	 */
	public IndexedPropertyFile(File dir, String storageName) throws IOException {
		super(dir, storageName, FileSystem.SEPARATOR, storageName);
		if (!exists()) {
			throw new FileNotFoundException();
		}
		if (name == null || parentPath == null) {
			throw new IOException("Invalid indexed property file: " + propertyFile);
		}
	}

	/**
	 * Construct an existing PropertyFile.
	 * @param file
	 * @throws FileNotFoundException if property file does not exist
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
	public void readState() throws IOException {
		super.readState();
		name = getString(NAME_PROPERTY, null);
		parentPath = getString(PARENT_PATH_PROPERTY, null);
	}

	@Override
	public void moveTo(File newParent, String newStorageName, String newParentPath, String newName)
			throws DuplicateFileException, IOException {

		super.moveTo(newParent, newStorageName, newParentPath, newName);
//		if (!parentPath.equals(newParentPath)) {
//			throw new AssertException();
//		}
//		if (!name.equals(newName)) {
//			throw new AssertException();
//		}
		putString(NAME_PROPERTY, newName);
		putString(PARENT_PATH_PROPERTY, newParentPath);
		writeState();
	}

}
