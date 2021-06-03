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
package ghidra.util;

import generic.stl.Pair;
import ghidra.framework.store.FileSystem;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlElement;

import java.io.*;
import java.util.HashMap;
import java.util.Map.Entry;

import org.xml.sax.*;

/**
 * Class that represents a file of property names and values. The file
 * extension used is PROPERTY_EXT.
 *
 */
public class PropertyFile {

	/**
	 * File extension indicating the file is a property file.
	 */
	public final static String PROPERTY_EXT = ".prp";

	private static final String FILE_ID = "FILE_ID";

	protected File propertyFile;
	protected String storageName;
	protected String parentPath;
	protected String name;

	private static enum PropertyEntryType {
		INT_TYPE("int"), LONG_TYPE("long"), BOOLEAN_TYPE("boolean"), STRING_TYPE("string");
		PropertyEntryType(String rep) {
			this.rep = rep;
		}

		private final String rep;

		public static PropertyEntryType lookup(String rep) {
			for (PropertyEntryType entryType : PropertyEntryType.values()) {
				if (rep.equals(entryType.rep)) {
					return entryType;
				}
			}
			return null;
		}
	}

	private HashMap<String, Pair<PropertyEntryType, String>> map =
		new HashMap<String, Pair<PropertyEntryType, String>>();

	/**
	 * Construct a new or existing PropertyFile.
	 * This form ignores retained property values for NAME and PARENT path.
	 * @param dir parent directory
	 * @param storageName stored property file name (without extension)
	 * @param parentPath path to parent
	 * @param name name of the property file
	 * @throws IOException 
	 */
	public PropertyFile(File dir, String storageName, String parentPath, String name)
			throws IOException {
		if (!dir.isAbsolute()) {
			throw new IllegalArgumentException("dir must be specified by an absolute path");
		}
		this.name = name;
		this.parentPath = parentPath;
		this.storageName = storageName;
		propertyFile = new File(dir, storageName + PROPERTY_EXT);
		if (propertyFile.exists()) {
			readState();
		}
	}

	/**
	 * Return the name of this PropertyFile.  A null value may be returned
	 * if this is an older property file and the name was not specified at
	 * time of construction.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns true if file is writable
	 */
	public boolean isReadOnly() {
		return !propertyFile.canWrite();
	}

	/**
	 * Return the path to this PropertyFile.  A null value may be returned
	 * if this is an older property file and the name and parentPath was not specified at
	 * time of construction.
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
	 * Return the path to the parent of this PropertyFile.
	 */
	public String getParentPath() {
		return parentPath;
	}

	/**
	 * Return the parent file to this PropertyFile.
	 */
	public File getFolder() {
		return propertyFile.getParentFile();
	}

	/**
	 * Return the storage name of this PropertyFile.  This name does not include the property
	 * file extension (.prp)
	 */
	public String getStorageName() {
		return storageName;
	}

	/**
	 * Returns the FileID associated with this file.
	 * @return FileID associated with this file
	 */
	public String getFileID() {
		return getString(FILE_ID, null);
	}

	/**
	 * Set the FileID associated with this file.
	 * @param fileId
	 */
	public void setFileID(String fileId) {
		putString(FILE_ID, fileId);
	}

	/**
	 * Return the int value with the given propertyName.
	 * @param propertyName name of property that is an int
	 * @param defaultValue value to use if the property does not exist
	 * @return int value
	 */
	public int getInt(String propertyName, int defaultValue) {
		Pair<PropertyEntryType, String> pair = map.get(propertyName);
		if (pair == null || pair.first != PropertyEntryType.INT_TYPE) {
			return defaultValue;
		}
		try {
			String value = pair.second;
			return Integer.parseInt(value);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Assign the int value to the given propertyName.
	 * @param propertyName name of property to set
	 * @param value value to set
	 */
	public void putInt(String propertyName, int value) {
		map.put(propertyName, new Pair<PropertyEntryType, String>(PropertyEntryType.INT_TYPE,
			Integer.toString(value)));
	}

	/**
	 * Return the long value with the given propertyName.
	 * @param propertyName name of property that is a long
	 * @param defaultValue value to use if the property does not exist
	 * @return long value
	 */
	public long getLong(String propertyName, long defaultValue) {
		Pair<PropertyEntryType, String> pair = map.get(propertyName);
		if (pair == null || pair.first != PropertyEntryType.LONG_TYPE) {
			return defaultValue;
		}
		try {
			String value = pair.second;
			return Long.parseLong(value);
		}
		catch (NumberFormatException e) {
			return defaultValue;
		}
	}

	/**
	 * Assign the long value to the given propertyName.
	 * @param propertyName name of property to set
	 * @param value value to set
	 */
	public void putLong(String propertyName, long value) {
		map.put(propertyName,
			new Pair<PropertyEntryType, String>(PropertyEntryType.LONG_TYPE, Long.toString(value)));
	}

	/**
	 * Return the string value with the given propertyName.
	 * @param propertyName name of property that is a string
	 * @param defaultValue value to use if the property does not exist
	 * @return string value
	 */
	public String getString(String propertyName, String defaultValue) {
		Pair<PropertyEntryType, String> pair = map.get(propertyName);
		if (pair == null || pair.first != PropertyEntryType.STRING_TYPE) {
			return defaultValue;
		}
		String value = pair.second;
		return value;
	}

	/**
	 * Assign the string value to the given propertyName.
	 * @param propertyName name of property to set
	 * @param value value to set
	 */
	public void putString(String propertyName, String value) {
		map.put(propertyName, new Pair<PropertyEntryType, String>(PropertyEntryType.STRING_TYPE,
			value));
	}

	/**
	 * Return the boolean value with the given propertyName.
	 * @param propertyName name of property that is a boolean
	 * @param defaultValue value to use if the property does not exist
	 * @return boolean value
	 */
	public boolean getBoolean(String propertyName, boolean defaultValue) {
		Pair<PropertyEntryType, String> pair = map.get(propertyName);
		if (pair == null || pair.first != PropertyEntryType.BOOLEAN_TYPE) {
			return defaultValue;
		}
		String value = pair.second;
		return Boolean.parseBoolean(value);
	}

	/**
	 * Assign the boolean value to the given propertyName.
	 * @param propertyName name of property to set
	 * @param value value to set
	 */
	public void putBoolean(String propertyName, boolean value) {
		map.put(propertyName, new Pair<PropertyEntryType, String>(PropertyEntryType.BOOLEAN_TYPE,
			Boolean.toString(value)));
	}

	/**
	 * Remove the specified property
	 * @param propertyName
	 */
	public void remove(String propertyName) {
		map.remove(propertyName);
	}

	/**
	 * Return the time of last modification in number of milliseconds. 
	 */
	public long lastModified() {
		return propertyFile.lastModified();
	}

	/**
	 * Write the contents of this PropertyFile.
	 * @throws IOException thrown if there was a problem writing the file
	 */
	public void writeState() throws IOException {
		PrintWriter writer = new PrintWriter(propertyFile);
		try {
			writer.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
			writer.println("<FILE_INFO>");
			writer.println("    <BASIC_INFO>");
			for (Entry<String, Pair<PropertyEntryType, String>> entry : map.entrySet()) {
				String propertyName = entry.getKey();
				String propertyType = entry.getValue().first.rep;
				String propertyValue = entry.getValue().second;
				writer.print("        <STATE NAME=\"");
				writer.print(XmlUtilities.escapeElementEntities(propertyName));
				writer.print("\" TYPE=\"");
				writer.print(XmlUtilities.escapeElementEntities(propertyType));
				writer.print("\" VALUE=\"");
				writer.print(XmlUtilities.escapeElementEntities(propertyValue));
				writer.println("\" />");
			}
			writer.println("    </BASIC_INFO>");
			writer.println("</FILE_INFO>");
		}
		finally {
			writer.close();
		}
	}

	private static final ErrorHandler HANDLER = new ErrorHandler() {
		@Override
		public void warning(SAXParseException exception) throws SAXException {
			throw exception;
		}

		@Override
		public void error(SAXParseException exception) throws SAXException {
			throw exception;
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			throw exception;
		}
	};

	/**
	 * Read in this PropertyFile into a SaveState object.
	 * @throws IOException thrown if there was a problem reading the file
	 */
	public void readState() throws IOException {
		NonThreadedXmlPullParserImpl parser = null;
		try {
			parser = new NonThreadedXmlPullParserImpl(propertyFile, HANDLER, false);
			XmlElement file_info = parser.start("FILE_INFO");
			XmlElement basic_info = parser.start("BASIC_INFO");
			XmlElement state;
			while ((state = parser.softStart("STATE")) != null) {
				String propertyName = state.getAttribute("NAME");
				String propertyTypeString = state.getAttribute("TYPE");
				String propertyValue = state.getAttribute("VALUE");
				PropertyEntryType propertyType = PropertyEntryType.lookup(propertyTypeString);
				map.put(propertyName, new Pair<PropertyEntryType, String>(propertyType,
					propertyValue));
				parser.end(state);
			}
			parser.end(basic_info);
			parser.end(file_info);
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			throw new InvalidObjectException("XML parse error in properties file");
		}
		finally {
			if (parser != null) {
				parser.dispose();
			}
		}
	}

	/**
	 * Move this PropertyFile to the newParent file.
	 * @param newParent new parent of the file
	 * @param newStorageName new storage name
	 * @param newParentPath parent path of the new parent
	 * @param newName new name for this PropertyFile
	 * @throws IOException thrown if there was a problem accessing the
	 * @throws DuplicateFileException thrown if a file with the newName
	 * already exists
	 */
	public void moveTo(File newParent, String newStorageName, String newParentPath, String newName)
			throws DuplicateFileException, IOException {
		if (!newParent.equals(propertyFile.getParentFile()) || !newStorageName.equals(storageName)) {
			File newPropertyFile = new File(newParent, newStorageName + PROPERTY_EXT);
			if (newPropertyFile.exists()) {
				throw new DuplicateFileException(newName + " already exists");
			}
			if (!propertyFile.renameTo(newPropertyFile)) {
				throw new IOException("move failed");
			}
			propertyFile = newPropertyFile;
			storageName = newStorageName;
		}
		parentPath = newParentPath;
		name = newName;
	}

	/**
	 * Return whether the file for this PropertyFile exists.
	 */
	public boolean exists() {
		return propertyFile.exists();
	}

	/**
	 * Delete the file for this PropertyFile.
	 */
	public void delete() {
		propertyFile.delete();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((propertyFile == null) ? 0 : propertyFile.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		PropertyFile other = (PropertyFile) obj;
		if (propertyFile == null) {
			if (other.propertyFile != null) {
				return false;
			}
		}
		else if (!propertyFile.equals(other.propertyFile)) {
			return false;
		}
		return true;
	}
}
