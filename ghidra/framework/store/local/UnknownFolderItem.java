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
import ghidra.util.PropertyFile;
import ghidra.util.task.TaskMonitor;

/**
 * <code>UnknownFolderItem</code> acts as a LocalFolderItem place-holder for 
 * items of an unknown type.
 */
public class UnknownFolderItem extends LocalFolderItem {

	public static final String UNKNOWN_CONTENT_TYPE = "Unknown";

	/**
	 * Constructor.
	 * @param fileSystem local file system
	 * @param propertyFile property file associated with this item
	 */
	UnknownFolderItem(LocalFileSystem fileSystem, PropertyFile propertyFile) {
		super(fileSystem, propertyFile);
	}

	@Override
	public long length() throws IOException {
		return 0;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#updateCheckout(ghidra.framework.store.FolderItem, boolean, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void updateCheckout(FolderItem versionedFolderItem, boolean updateItem,
			TaskMonitor monitor) throws IOException {
		throw new UnsupportedOperationException();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#updateCheckout(ghidra.framework.store.FolderItem, int)
	 */
	@Override
	public void updateCheckout(FolderItem item, int checkoutVersion) throws IOException {
		throw new UnsupportedOperationException();
	}

	/*
	 * @see ghidra.framework.store.FolderItem#checkout(java.lang.String)
	 */
	public synchronized ItemCheckoutStatus checkout(String user) throws IOException {
		throw new IOException(propertyFile.getName() +
			" may not be checked-out, item may be corrupt");
	}

	/*
	 * @see ghidra.framework.store.FolderItem#terminateCheckout(long)
	 */
	public synchronized void terminateCheckout(long checkoutId) {
		// Do nothing
	}

	/*
	 * @see ghidra.framework.store.FolderItem#clearCheckout()
	 */
	@Override
	public void clearCheckout() throws IOException {
		// Do nothing
	}

	/*
	 * @see ghidra.framework.store.FolderItem#setCheckout(long, int, int)
	 */
	public void setCheckout(long checkoutId, int checkoutVersion, int localVersion) {
		// Do nothing
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCheckout(long)
	 */
	@Override
	public synchronized ItemCheckoutStatus getCheckout(long checkoutId) throws IOException {
		return null;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCheckouts()
	 */
	@Override
	public synchronized ItemCheckoutStatus[] getCheckouts() throws IOException {
		return new ItemCheckoutStatus[0];
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getVersions()
	 */
	@Override
	public synchronized Version[] getVersions() throws IOException {
		throw new IOException("History data is unavailable for " + propertyFile.getName());
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getContentType()
	 */
	@Override
	public String getContentType() {
		return UNKNOWN_CONTENT_TYPE;
	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#deleteMinimumVersion(java.lang.String)
	 */
	@Override
	void deleteMinimumVersion(String user) throws IOException {

		throw new UnsupportedOperationException("Versioning not supported for UnknownFolderItems");

	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#deleteCurrentVersion(java.lang.String)
	 */
	@Override
	void deleteCurrentVersion(String user) throws IOException {

		throw new UnsupportedOperationException("Versioning not supported for UnknownFolderItems");

	}

	/*
	 * @see ghidra.framework.store.FolderItem#output(java.io.File, int, ghidra.util.task.TaskMonitor)
	 */
	public void output(File outputFile, int version, TaskMonitor monitor) throws IOException {

		throw new UnsupportedOperationException("Output not supported for UnknownFolderItems");

	}

	/*
	 * @see ghidra.framework.store.local.LocalFolderItem#getMinimumVersion()
	 */
	@Override
	int getMinimumVersion() throws IOException {
		return -1;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#getCurrentVersion()
	 */
	public int getCurrentVersion() {
		return -1;
	}

	/*
	 * @see ghidra.framework.store.FolderItem#canRecover()
	 */
	public boolean canRecover() {
		return false;
	}
}
