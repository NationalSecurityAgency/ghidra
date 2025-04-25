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

import ghidra.framework.store.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>UnknownFolderItem</code> acts as a LocalFolderItem place-holder for 
 * items of an unknown type.
 */
public class LocalUnknownFolderItem extends LocalFolderItem implements UnknownFolderItem {

	private final int fileType;

	/**
	 * Constructor.
	 * @param fileSystem local file system
	 * @param propertyFile property file associated with this item
	 */
	LocalUnknownFolderItem(LocalFileSystem fileSystem, ItemPropertyFile propertyFile) {
		super(fileSystem, propertyFile);
		fileType = propertyFile.getInt(FILE_TYPE, UNKNOWN_FILE_TYPE);
	}

	/**
	 * Get the file type
	 * @return file type or -1 if unspecified
	 */
	public int getFileType() {
		return fileType;
	}

	@Override
	public long length() throws IOException {
		return 0;
	}

	@Override
	public void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException {
		throw new UnsupportedOperationException();
	}

	@Override
	public void updateCheckout(FolderItem item, int checkoutVersion) throws IOException {
		throw new UnsupportedOperationException();
	}

	public synchronized ItemCheckoutStatus checkout(String user) throws IOException {
		throw new IOException(
			propertyFile.getName() + " may not be checked-out, item may be corrupt");
	}

	public synchronized void terminateCheckout(long checkoutId) {
		// Do nothing
	}

	@Override
	public void clearCheckout() throws IOException {
		// Do nothing
	}

	public void setCheckout(long checkoutId, int checkoutVersion, int localVersion) {
		// Do nothing
	}

	@Override
	public synchronized ItemCheckoutStatus getCheckout(long checkoutId) throws IOException {
		return null;
	}

	@Override
	public synchronized ItemCheckoutStatus[] getCheckouts() throws IOException {
		return new ItemCheckoutStatus[0];
	}

	@Override
	public synchronized Version[] getVersions() throws IOException {
		throw new IOException("History data is unavailable for " + propertyFile.getName());
	}

	@Override
	public String getContentType() {
		// NOTE: We could get the content type from the property file but we don't want any 
		// attempt to use it
		return UNKNOWN_CONTENT_TYPE;
	}

	@Override
	void deleteMinimumVersion(String user) throws IOException {
		throw new UnsupportedOperationException("Versioning not supported for UnknownFolderItems");
	}

	@Override
	void deleteCurrentVersion(String user) throws IOException {
		throw new UnsupportedOperationException("Versioning not supported for UnknownFolderItems");
	}

	@Override
	public void output(File outputFile, int version, TaskMonitor monitor) throws IOException {
		throw new UnsupportedOperationException("Output not supported for UnknownFolderItems");
	}

	@Override
	int getMinimumVersion() throws IOException {
		return -1;
	}

	@Override
	public int getCurrentVersion() {
		return -1;
	}

	@Override
	public boolean canRecover() {
		return false;
	}
}
