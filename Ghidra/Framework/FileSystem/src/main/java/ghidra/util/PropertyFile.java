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

import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.xml.sax.*;

import ghidra.framework.store.local.ItemPropertyFile;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.xml.XmlUtilities;
import ghidra.xml.NonThreadedXmlPullParserImpl;
import ghidra.xml.XmlElement;

/**
 * {@link ItemPropertyFile} provides basic property storage.  The file extension 
 * used is {@link #PROPERTY_EXT}.
 */
public class PropertyFile {

	/**
	 * File extension indicating the file is a property file.
	 */
	public final static String PROPERTY_EXT = ".prp";

	protected File propertyFile;
	protected String storageName;

	//@formatter:off
	private static enum PropertyEntryType {
		INT_TYPE("int"), 
		LONG_TYPE("long"), 
		BOOLEAN_TYPE("boolean"), 
		STRING_TYPE("string");
	//@formatter:on

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

	private record PropertyMapEntry(PropertyEntryType entityType, String value) {
		// no behaviors
	}

	private Map<String, PropertyMapEntry> basicInfoMap = new HashMap<String, PropertyMapEntry>();

	/**
	 * Construct a new or existing PropertyFile.
	 * This constructor ignores retained property values for NAME and PARENT path.
	 * This constructor will not throw an exception if the file does not exist.
	 * @param dir native directory where this file is stored
	 * @param storageName stored property file name (without extension)
	 * @throws InvalidObjectException if a file parse error occurs
	 * @throws IOException if an IO error occurs reading an existing file
	 */
	public PropertyFile(File dir, String storageName) throws IOException {
		if (!dir.isAbsolute()) {
			throw new IllegalArgumentException("dir must be specified by an absolute path");
		}
		this.storageName = storageName;
		propertyFile = new File(dir, storageName + PROPERTY_EXT);
		if (propertyFile.exists()) {
			readState();
		}
	}

	protected boolean contains(String key) {
		return basicInfoMap.containsKey(key);
	}

	/**
	 * {@return true if file is read-only as reported by underlying native file-system}
	 */
	public boolean isReadOnly() {
		return !propertyFile.canWrite();
	}

	/**
	 * {@return the native parent storage directory containing this PropertyFile.}
	 */
	public File getParentStorageDirectory() {
		return propertyFile.getParentFile();
	}

	/**
	 * Return the native storage name for this PropertyFile.  This name does not include the property
	 * file extension (.prp)
	 * @return native storage name
	 */
	public String getStorageName() {
		return storageName;
	}

	/**
	 * Return the int value with the given propertyName.
	 * @param propertyName name of property that is an int
	 * @param defaultValue value to use if the property does not exist
	 * @return int value
	 */
	public int getInt(String propertyName, int defaultValue) {
		PropertyMapEntry entry = basicInfoMap.get(propertyName);
		if (entry == null || entry.entityType != PropertyEntryType.INT_TYPE) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(entry.value);
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
		basicInfoMap.put(propertyName,
			new PropertyMapEntry(PropertyEntryType.INT_TYPE, Integer.toString(value)));
	}

	/**
	 * Return the long value with the given propertyName.
	 * @param propertyName name of property that is a long
	 * @param defaultValue value to use if the property does not exist
	 * @return long value
	 */
	public long getLong(String propertyName, long defaultValue) {
		PropertyMapEntry entry = basicInfoMap.get(propertyName);
		if (entry == null || entry.entityType != PropertyEntryType.LONG_TYPE) {
			return defaultValue;
		}
		try {
			return Long.parseLong(entry.value);
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
		basicInfoMap.put(propertyName,
			new PropertyMapEntry(PropertyEntryType.LONG_TYPE, Long.toString(value)));
	}

	/**
	 * Return the string value with the given propertyName.
	 * @param propertyName name of property that is a string
	 * @param defaultValue value to use if the property does not exist
	 * @return string value
	 */
	public String getString(String propertyName, String defaultValue) {
		PropertyMapEntry entry = basicInfoMap.get(propertyName);
		if (entry == null || entry.entityType != PropertyEntryType.STRING_TYPE) {
			return defaultValue;
		}
		return entry.value;
	}

	/**
	 * Assign the string value to the given propertyName.
	 * @param propertyName name of property to set
	 * @param value value to set
	 */
	public void putString(String propertyName, String value) {
		if (value == null) {
			basicInfoMap.remove(propertyName);
		}
		else {
			basicInfoMap.put(propertyName,
				new PropertyMapEntry(PropertyEntryType.STRING_TYPE, value));
		}
	}

	/**
	 * Return the boolean value with the given propertyName.
	 * @param propertyName name of property that is a boolean
	 * @param defaultValue value to use if the property does not exist
	 * @return boolean value
	 */
	public boolean getBoolean(String propertyName, boolean defaultValue) {
		PropertyMapEntry entry = basicInfoMap.get(propertyName);
		if (entry == null || entry.entityType != PropertyEntryType.BOOLEAN_TYPE) {
			return defaultValue;
		}
		return Boolean.parseBoolean(entry.value);
	}

	/**
	 * Assign the boolean value to the given propertyName.
	 * @param propertyName name of property to set
	 * @param value value to set
	 */
	public void putBoolean(String propertyName, boolean value) {
		basicInfoMap.put(propertyName,
			new PropertyMapEntry(PropertyEntryType.BOOLEAN_TYPE, Boolean.toString(value)));
	}

	/**
	 * Remove the specified property
	 * @param propertyName name of property to be removed
	 */
	public void remove(String propertyName) {
		basicInfoMap.remove(propertyName);
	}

	/**
	 * Return the time of last modification in number of milliseconds
	 * @return time of last modification
	 */
	public long lastModified() {
		return propertyFile.lastModified();
	}

	/**
	 * Write the contents of this PropertyFile.
	 * @throws IOException thrown if there was a problem writing the file
	 */
	public void writeState() throws IOException {
		// NOTE: To avoid severe incompatibility with older versions of Ghidra this XML
		// schema should not be changed.
		PrintWriter writer = new PrintWriter(propertyFile);
		try {
			writer.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
			writer.println("<FILE_INFO>");
			writer.println("    <BASIC_INFO>");
			for (Entry<String, PropertyMapEntry> entry : basicInfoMap.entrySet()) {
				String propertyName = entry.getKey();
				String propertyType = entry.getValue().entityType.rep;
				String propertyValue = entry.getValue().value;
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
	 * @throws InvalidObjectException if a file parse error occurs
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
				basicInfoMap.put(propertyName, new PropertyMapEntry(propertyType, propertyValue));
				parser.end(state);
			}
			parser.end(basic_info);
			parser.end(file_info);
		}
		catch (Exception e) {
			String msg = "XML parse error in properties file";
			Msg.error(this, msg + ": " + propertyFile);
			throw new InvalidObjectException(msg);
		}
		finally {
			if (parser != null) {
				parser.dispose();
			}
		}
	}

	/**
	 * Move this PropertyFile to the newParent file.
	 * @param newStorageParent new storage parent of the native file
	 * @param newStorageName new storage name for this property file
	 * @throws IOException thrown if there was a problem accessing the
	 * @throws DuplicateFileException thrown if a file with the newName
	 * already exists
	 */
	public void moveTo(File newStorageParent, String newStorageName)
			throws DuplicateFileException, IOException {
		if (!newStorageParent.equals(propertyFile.getParentFile()) ||
			!newStorageName.equals(storageName)) {
			File newPropertyFile = new File(newStorageParent, newStorageName + PROPERTY_EXT);
			if (newPropertyFile.exists()) {
				throw new DuplicateFileException(newPropertyFile + " already exists");
			}
			if (!propertyFile.renameTo(newPropertyFile)) {
				throw new IOException("move failed");
			}
			propertyFile = newPropertyFile;
			storageName = newStorageName;
		}
	}

	/**
	 * Return whether the file for this PropertyFile exists.
	 * @return true if this file exists
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
		return propertyFile.hashCode();
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
		ItemPropertyFile other = (ItemPropertyFile) obj;
		return propertyFile.equals(other.propertyFile);
	}

}
