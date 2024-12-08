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
package ghidra.framework.store.remote;

import java.io.IOException;

import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.*;

/**
 * <code>RemoteFolderItem</code> provides an abstract FolderItem implementation
 * for an item contained within a remote Repository.  
 */
public abstract class RemoteFolderItem implements FolderItem {

	protected final String parentPath;
	protected final String itemName;
	protected final String contentType;
	protected final String fileID;

	protected int version;
	protected long versionTime;

	protected RepositoryAdapter repository;

	/**
	 * Construct a FolderItem for an existing repository item.
	 * @param repository repository which contains item
	 * @param item repository item
	 */
	RemoteFolderItem(RepositoryAdapter repository, RepositoryItem item) {
		this.repository = repository;
		parentPath = item.getParentPath();
		itemName = item.getName();
		contentType = item.getContentType();
		fileID = item.getFileID();

		version = item.getVersion();
		versionTime = item.getVersionTime();
	}

	/**
	 * Returns the item type as defined by RepositoryItem which corresponds to specific 
	 * implementation of this class.
	 * @return item type (Only {@link RepositoryItem#DATABASE} is supported).
	 * @see ghidra.framework.remote.RepositoryItem
	 */
	abstract int getItemType();

	@Override
	public String getName() {
		return itemName;
	}

	@Override
	public RemoteFolderItem refresh() throws IOException {
		RepositoryItem item = repository.getItem(parentPath, itemName);
		if (item == null) {
			return null;
		}
		version = item.getVersion();
		versionTime = item.getVersionTime();
		return this;
	}

	@Override
	public String getFileID() {
		return fileID;
	}

	@Override
	public String resetFileID() {
		throw new UnsupportedOperationException();
	}

	@Override
	public String getContentType() {
		return contentType;
	}

	@Override
	public String getParentPath() {
		return parentPath;
	}

	@Override
	public String getPathName() {
		String path = parentPath;
		if (path.length() != 1) {
			path += FileSystem.SEPARATOR;
		}
		return path + itemName;
	}

	@Override
	public boolean isReadOnly() {
		throw new UnsupportedOperationException("isReadOnly is not applicable to versioned item");
	}

	@Override
	public void setReadOnly(boolean state) {
		throw new UnsupportedOperationException("setReadOnly is not applicable to versioned item");
	}

	@Override
	public int getContentTypeVersion() {
		throw new UnsupportedOperationException(
			"getContentTypeVersion is not applicable to versioned item");
	}

	@Override
	public void setContentTypeVersion(int version) throws IOException {
		throw new UnsupportedOperationException(
			"setContentTypeVersion is not applicable to versioned item");
	}

	@Override
	public long lastModified() {
		return versionTime;
	}

	@Override
	public int getCurrentVersion() {
		return version;
	}

	@Override
	public boolean isVersioned() {
		return (version != -1);
	}

	@Override
	public Version[] getVersions() throws IOException {
		return repository.getVersions(parentPath, itemName);
	}

	@Override
	public void delete(int ver, String user) throws IOException {
		repository.deleteItem(parentPath, itemName, ver);
	}

	@Override
	public boolean isCheckedOut() {
		throw new UnsupportedOperationException("isCheckedOut is not applicable to versioned item");
	}

	@Override
	public boolean isCheckedOutExclusive() {
		throw new UnsupportedOperationException(
			"isCheckedOutExclusive is not applicable to versioned item");
	}

	@Override
	public ItemCheckoutStatus checkout(CheckoutType checkoutType, String user, String projectPath)
			throws IOException {
		return repository.checkout(parentPath, itemName, checkoutType, projectPath);
	}

	@Override
	public void terminateCheckout(long checkoutId, boolean notify) throws IOException {
		repository.terminateCheckout(parentPath, itemName, checkoutId, notify);
	}

	@Override
	public ItemCheckoutStatus getCheckout(long checkoutId) throws IOException {
		return repository.getCheckout(parentPath, itemName, checkoutId);
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts() throws IOException {
		return repository.getCheckouts(parentPath, itemName);
	}

	@Override
	public void clearCheckout() throws IOException {
		throw new UnsupportedOperationException(
			"clearCheckout is not applicable to versioned item");
	}

	@Override
	public long getCheckoutId() throws IOException {
		throw new UnsupportedOperationException(
			"getCheckoutId is not applicable to versioned item");
	}

	@Override
	public int getCheckoutVersion() throws IOException {
		throw new UnsupportedOperationException(
			"getCheckoutVersion is not applicable to versioned item");
	}

	@Override
	public int getLocalCheckoutVersion() {
		throw new UnsupportedOperationException(
			"getLocalCheckoutVersion is not applicable to versioned item");
	}

	@Override
	public void setCheckout(long checkoutId, boolean exclusive, int checkoutVersion,
			int localVersion) throws IOException {
		throw new UnsupportedOperationException("setCheckout is not applicable to versioned item");
	}

}
