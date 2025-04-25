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
package ghidra.framework.remote;

import java.io.IOException;
import java.io.InvalidClassException;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.store.FileSystem;

/**
 * <code>RepositoryItemStatus</code> provides status information for a 
 * repository folder item.
 */
public class RepositoryItem implements java.io.Serializable {

	// Serial version 2 supports an expandable schema which allows a newer repository server
	// to remain usable by older clients, and a newer client to deserialize data from an older
	// server.  The optional schema version if present can be used to identify the additional 
	// serialized data which may following the schema version number.

	public final static long serialVersionUID = 2L;

	private static final byte SERIALIZATION_SCHEMA_VERSION = 1;

	public final static int FILE = 1;			// DataFileItem (not yet supported)
	public final static int DATABASE = 2;       // DatabaseItem
	public final static int TEXT_DATA_FILE = 3; // TextDataItem

	//
	// Client use can support reading from older server which presents serialVersionUID==2
	//

	private String folderPath;
	private String itemName;
	private String fileID;
	private int itemType;
	private String contentType;
	private int version;
	private long versionTime;

	// Variables below were added after serialVersionUID == 2 was established and rely on 
	// additional serialization version byte to identify the optional data fields added
	// after original serialVersionUID == 2 fields.

	private String textData; // applies to TEXT_DATA_FILE introduced with GhidraServerHandle v12

	/**
	 * Default constructor needed for de-serialization
	 */
	protected RepositoryItem() {
	}

	/**
	 * Constructor.
	 * @param folderPath path of folder containing item.
	 * @param itemName name of item
	 * @param fileID unique file ID
	 * @param itemType type of item (FILE or DATABASE)
	 * @param contentType content type associated with item
	 * @param version repository item version or -1 if versioning not supported
	 * @param versionTime version creation time
	 * @param textData related text data (may be null)
	 */
	public RepositoryItem(String folderPath, String itemName, String fileID, int itemType,
			String contentType, int version, long versionTime, String textData) {
		this.folderPath = folderPath;
		this.itemName = itemName;
		this.fileID = fileID;
		this.itemType = itemType;
		this.contentType = contentType;
		this.version = version;
		this.versionTime = versionTime;
		this.textData = textData;
	}

	/**
	 * Serialization method
	 * @param out serialization output stream
	 * @throws IOException if an IO error occurs
	 */
	private void writeObject(java.io.ObjectOutputStream out) throws IOException {

		out.writeLong(serialVersionUID);
		out.writeUTF(folderPath);
		out.writeUTF(itemName);
		out.writeUTF(fileID != null ? fileID : "");
		out.writeInt(itemType);
		out.writeUTF(contentType != null ? contentType : "");
		out.writeInt(version);
		out.writeLong(versionTime);

		// Variables below were added after serialVersionUID == 2 was established

		out.writeByte(SERIALIZATION_SCHEMA_VERSION);
		out.writeUTF(textData != null ? textData : "");

	}

	/**
	 * Deserialization method
	 * @param in deserialization input stream
	 * @throws IOException if IO error occurs
	 * @throws ClassNotFoundException if unrecognized serialVersionUID detected
	 */
	private void readObject(java.io.ObjectInputStream in)
			throws IOException, ClassNotFoundException {
		long serialVersion = in.readLong();
		if (serialVersion != serialVersionUID) {
			throw new ClassNotFoundException("Unsupported version of RepositoryItem");
		}
		folderPath = in.readUTF();
		itemName = in.readUTF();
		fileID = in.readUTF();
		if (fileID.length() == 0) {
			fileID = null;
		}
		itemType = in.readInt();
		contentType = in.readUTF();
		if (contentType.length() == 0) {
			contentType = null;
		}
		version = in.readInt();
		versionTime = in.readLong();

		// Variable handling below was added after serialVersionUID == 2 was established

		int available = in.available();
		if (available == 0) {
			// assume original schema before serializationSchemaVersion was employed
			return;
		}

		// Since we do not serialize class implementations with RMI the older client must be able to 
		// read the initial data sequence that was previously supported.  Newer clients that have this 
		// class will use the presence of the version byte to handle communicating with either an 
		// older server (no version byte) or a newer server (version byte and subsequent data is read)
		byte serializationSchemaVersion = in.readByte();
		if (serializationSchemaVersion < 1 ||
			serializationSchemaVersion > SERIALIZATION_SCHEMA_VERSION) {
			throw new InvalidClassException("RepositoryItem",
				"RepositoryItem has incompatible serialization schema version: " +
					serializationSchemaVersion);
		}

		textData = in.readUTF();
		if (StringUtils.isBlank(textData)) {
			textData = null;
		}
	}

	/**
	 * Returns the item name.
	 */
	public String getName() {
		return itemName;
	}

	/**
	 * Returns the folder item path within the repository.
	 */
	public String getPathName() {
		return folderPath + FileSystem.SEPARATOR + itemName;
	}

	/**
	 * Returns path of the parent folder containing this item.
	 */
	public String getParentPath() {
		return folderPath;
	}

	/**
	 * Returns type of item.
	 */
	public int getItemType() {
		return itemType;
	}

	/**
	 * Returns content class
	 */
	public String getContentType() {
		return contentType;
	}

	public String getFileID() {
		return fileID;
	}

	/**
	 * Returns the current version of the item or 
	 * -1 if versioning not supported.
	 */
	public int getVersion() {
		return version;
	}

	/**
	 * Returns the time (UTC milliseconds) when the current version was created.
	 */
	public long getVersionTime() {
		return versionTime;
	}

	/**
	 * Get related text data
	 * @return text data or null
	 */
	public String getTextData() {
		return textData;
	}
}
