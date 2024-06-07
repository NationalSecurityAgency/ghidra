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

import java.io.*;

import db.buffers.*;
import ghidra.framework.Application;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.DatabaseItem;
import ghidra.framework.store.local.ItemSerializer;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>RemoteDatabaseItem</code> provides a FolderItem implementation
 * for a remote database.  This item wraps an underlying versioned database
 * which corresponds to a repository item.
 */
public class RemoteDatabaseItem extends RemoteFolderItem implements DatabaseItem {

	/**
	 * Construct a FolderItem for an existing repository database item.
	 * @param repository repository which contains item
	 * @param item repository item
	 */
	RemoteDatabaseItem(RepositoryAdapter repository, RepositoryItem item) {
		super(repository, item);
	}

	@Override
	public long length() throws IOException {
		return repository.getLength(parentPath, itemName);
	}

	@Override
	int getItemType() {
		return RepositoryItem.DATABASE;
	}

	@Override
	public boolean canRecover() {
		return false;
	}

	@Override
	public ManagedBufferFileAdapter open(int fileVersion, int minChangeDataVer) throws IOException {
		return repository.openDatabase(parentPath, itemName, fileVersion, minChangeDataVer);
	}

	@Override
	public ManagedBufferFileAdapter open(int fileVersion) throws IOException {
		return repository.openDatabase(parentPath, itemName, fileVersion, -1);
	}

	@Override
	public ManagedBufferFileAdapter open() throws IOException {
		return repository.openDatabase(parentPath, itemName, LATEST_VERSION, -1);
	}

	@Override
	public ManagedBufferFileAdapter openForUpdate(long checkoutId) throws IOException {
		return repository.openDatabase(parentPath, itemName, checkoutId);
	}

	@Override
	public void updateCheckoutVersion(long checkoutId, int checkoutVersion, String user)
			throws IOException {
		repository.updateCheckoutVersion(parentPath, itemName, checkoutId, checkoutVersion);
	}

	@Override
	public boolean hasCheckouts() throws IOException {
		return repository.hasCheckouts(parentPath, itemName);
	}

	@Override
	public boolean isCheckinActive() throws IOException {
		return repository.isCheckinActive(parentPath, itemName);
	}

	@Override
	public void output(File outputFile, int fileVersion, TaskMonitor monitor)
			throws IOException, CancelledException {

		BufferFile bf = repository.openDatabase(parentPath, itemName, fileVersion, -1);
		try {
			File tmpFile = Application.createTempFile("ghidra", LocalBufferFile.TEMP_FILE_EXT);
			tmpFile.delete();
			BufferFile tmpBf = new LocalBufferFile(tmpFile, bf.getBufferSize());
			try {
				LocalBufferFile.copyFile(bf, tmpBf, null, monitor);
				tmpBf.close();

				try (InputStream itemIn = new FileInputStream(tmpFile)) {
					ItemSerializer.outputItem(getName(), getContentType(), DATABASE_FILE_TYPE,
						tmpFile.length(), itemIn, outputFile, monitor);
				}
			}
			finally {
				tmpBf.close();
				tmpFile.delete();
			}
		}
		finally {
			bf.close();
		}
	}

}
