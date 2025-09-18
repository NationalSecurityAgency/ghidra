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

import java.io.File;
import java.io.IOException;

import org.apache.commons.lang3.StringUtils;

import ghidra.framework.store.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LocalTextDataItem</code> provides a {@link LocalFolderItem} implementation
 * which stores text data within the associated propertyFile and without any other data storage.
 */
public class LocalTextDataItem extends LocalFolderItem implements TextDataItem {

	private static final String TEXT_PROPERTY = "TEXT";
	private static final String VERSION_CREATE_USER = "CREATE_USER";
	private static final String VERSION_CREATE_TIME = "CREATE_TIME";
	private static final String VERSION_CREATE_COMMENT = "CREATE_COMMENT";

	/**
	 * Constructor for an existing local link file item which corresponds to the specified 
	 * property file.
	 * @param fileSystem file system
	 * @param propertyFile database property file
	 * @throws IOException if an IO Error occurs
	 */
	public LocalTextDataItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile)
			throws IOException {
		super(fileSystem, propertyFile, false, false);
	}

	/**
	 * Create a new local text data file item.
	 * @param fileSystem file system
	 * @param propertyFile serialized data property file
	 * @param fileID file ID to be associated with new file or null
	 * @param contentType user content type
	 * @param textData text to be stored within associated property file
	 * @throws IOException if an IO Error occurs
	 */
	public LocalTextDataItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile,
			String fileID, String contentType, String textData) throws IOException {
		super(fileSystem, propertyFile, false, true);

		if (StringUtils.isBlank(contentType)) {
			abortCreate();
			throw new IllegalArgumentException("Missing content-type");
		}

		if (StringUtils.isBlank(textData)) {
			abortCreate();
			throw new IllegalArgumentException("Missing text data");
		}

		propertyFile.putInt(FILE_TYPE, LINK_FILE_TYPE);
		propertyFile.putBoolean(READ_ONLY, false);
		propertyFile.putString(CONTENT_TYPE, contentType);
		if (fileID != null) {
			propertyFile.setFileID(fileID);
		}

		propertyFile.putString(TEXT_PROPERTY, textData);

		propertyFile.writeState();
	}

	/**
	 * Get the text data that was stored with this item
	 * @return text data
	 */
	public String getTextData() {
		return propertyFile.getString(TEXT_PROPERTY, null);
	}

	@Override
	public long length() throws IOException {
		return 0;
	}

	@Override
	public void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException {
		throw new IOException("Versioning updates not supported");
	}

	@Override
	public void updateCheckout(FolderItem item, int checkoutVersion) throws IOException {
		throw new IOException("Versioning updates not supported");
	}

	@Override
	void deleteMinimumVersion(String user) throws IOException {
		throw new UnsupportedOperationException("Versioning updates not supported");
	}

	@Override
	void deleteCurrentVersion(String user) throws IOException {
		throw new UnsupportedOperationException("Versioning updates not supported");
	}

	@Override
	public void output(File outputFile, int version, TaskMonitor monitor) throws IOException {
		throw new IOException("Output not supported");
	}

	@Override
	int getMinimumVersion() {
		return getCurrentVersion();
	}

	@Override
	public int getCurrentVersion() {
		return 1; // only a single version of the file may exist
	}

	@Override
	public boolean canRecover() {
		return false;
	}

	/**
	 * Set the version info associated with this versioned file.  Only a single version is
	 * supported.
	 * @param version version information (only user, create time and comment is retained)
	 * @throws IOException if an IO error occurs
	 */
	public void setVersionInfo(Version version) throws IOException {
		synchronized (fileSystem) {
			if (!isVersioned()) {
				throw new UnsupportedOperationException("Versioning not supported");
			}
			propertyFile.putString(VERSION_CREATE_USER, version.getUser());
			propertyFile.putLong(VERSION_CREATE_TIME, version.getCreateTime());
			propertyFile.putString(VERSION_CREATE_COMMENT, version.getComment());
			propertyFile.writeState();
		}
	}

	@Override
	public synchronized Version[] getVersions() throws IOException {
		synchronized (fileSystem) {
			if (!isVersioned) {
				throw new UnsupportedOperationException(
					"Non-versioned item does not support getVersions");
			}
			String createUser = propertyFile.getString(VERSION_CREATE_USER, "");
			long createTime = propertyFile.getLong(VERSION_CREATE_TIME, 0);
			String comment = propertyFile.getString(VERSION_CREATE_COMMENT, null);
			return new Version[] { new Version(1, createTime, createUser, comment) };
		}
	}

}
