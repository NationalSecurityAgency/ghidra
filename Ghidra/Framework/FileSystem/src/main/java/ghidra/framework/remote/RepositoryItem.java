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

import ghidra.framework.store.FileSystem;

import java.io.IOException;

/**
 * <code>RepositoryItemStatus</code> provides status information for a 
 * repository folder item.
 */
public class RepositoryItem implements java.io.Serializable {

	public final static long serialVersionUID = 2L;

	public final static int FILE = 1;
	public final static int DATABASE = 2;

	protected String folderPath;
	protected String itemName;
	protected String fileID;
	protected int itemType;
	protected String contentType;
	protected int version;
	protected long versionTime;

	/**
	 * Default constructor needed for de-serialization
	 */
	protected RepositoryItem() {
	}

	/**
	 * Constructor.
	 * @param folderPath path of folder containing item.
	 * @param itemName name of item
	 * @param itemType type of item (FILE or DATABASE)
	 * @param contentType content type associated with item
	 * @param version repository item version or -1 if versioning not supported
	 * @param versionTime version creation time
	 */
	public RepositoryItem(String folderPath, String itemName, String fileID, int itemType,
			String contentType, int version, long versionTime) {
		this.folderPath = folderPath;
		this.itemName = itemName;
		this.fileID = fileID;
		this.itemType = itemType;
		this.contentType = contentType;
		this.version = version;
		this.versionTime = versionTime;
	}

	/**
	 * Serialization method
	 * @param out
	 * @throws IOException
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
	}

	/**
	 * Deserialization method
	 * @param in
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private void readObject(java.io.ObjectInputStream in) throws IOException,
			ClassNotFoundException {
		long serialVersion = in.readLong();
		if (serialVersion != serialVersionUID) {
			throw new ClassNotFoundException("Unsupported version of RepositoryItemStatus");
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

}
