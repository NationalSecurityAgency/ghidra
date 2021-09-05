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
import ghidra.framework.client.RemoteAdapterListener;
import ghidra.framework.client.RepositoryAdapter;
import ghidra.framework.remote.RepositoryItem;
import ghidra.framework.store.*;
import ghidra.framework.store.FileSystem;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>RemoteFileSystem</code> provides access to versioned FolderItem's which 
 * exist within a Repository-based directory structure.  FolderItem
 * caching is provided by the remote implementation which is intended
 * to be shared across multiple clients.
 * <p>
 * FolderItem's must be checked-out to create new versions.
 * <p>
 * FileSystemListener's will be notified of all changes made 
 * within the Repository.
 */
public class RemoteFileSystem implements FileSystem, RemoteAdapterListener {

	private RepositoryAdapter repository;
	private FileSystemEventManager eventManager = new FileSystemEventManager(true);

	/**
	 * Construct a new remote file system which corresponds to a remote repository.
	 * @param repository remote Repository
	 */
	public RemoteFileSystem(RepositoryAdapter repository) {
		this.repository = repository;
		repository.setFileSystemListener(eventManager);
		repository.addListener(this);
	}

	@Override
	public String getUserName() {
		try {
			return repository.getUser().getName();
		}
		catch (IOException e) {
			return null;
		}
	}

	@Override
	public void addFileSystemListener(FileSystemListener listener) {
		eventManager.add(listener);
	}

	@Override
	public void removeFileSystemListener(FileSystemListener listener) {
		eventManager.remove(listener);
	}

	@Override
	public boolean isVersioned() {
		return true;
	}

	@Override
	public boolean isOnline() {
		return repository.isConnected();
	}

	@Override
	public boolean isReadOnly() throws IOException {
		return repository.getUser().isReadOnly();
	}

	@Override
	public boolean isShared() {
		return true;
	}

	@Override
	public int getItemCount() throws IOException, UnsupportedOperationException {
		return repository.getItemCount();
	}

	@Override
	public synchronized String[] getItemNames(String folderPath) throws IOException {
		RepositoryItem[] items = repository.getItemList(folderPath);
		String[] names = new String[items.length];
		for (int i = 0; i < items.length; i++) {
			names[i] = items[i].getName();
		}
		return names;
	}

	@Override
	public synchronized FolderItem getItem(String folderPath, String name) throws IOException {
		RepositoryItem item = repository.getItem(folderPath, name);
		if (item == null) {
			return null;
		}
		if (item.getItemType() == RepositoryItem.DATABASE) {
			return new RemoteDatabaseItem(repository, item);
		}
		throw new IOException("Unsupported file type");
	}

	@Override
	public FolderItem getItem(String fileID) throws IOException, UnsupportedOperationException {
		RepositoryItem item = repository.getItem(fileID);
		if (item == null) {
			return null;
		}
		if (item.getItemType() == RepositoryItem.DATABASE) {
			return new RemoteDatabaseItem(repository, item);
		}
		throw new IOException("Unsupported file type");
	}

	@Override
	public String[] getFolderNames(String parentPath) throws IOException {
		return repository.getSubfolderList(parentPath);
	}

	@Override
	public void createFolder(String parentPath, String folderName) {
		throw new UnsupportedOperationException();
	}

	@Override
	public ManagedBufferFile createDatabase(String parentPath, String name, String fileID,
			String contentType, int bufferSize, String user, String projectPath)
			throws InvalidNameException, IOException {
		return repository.createDatabase(parentPath, name, bufferSize, contentType, fileID,
			projectPath);
	}

	@Override
	public DatabaseItem createDatabase(String parentPath, String name, String fileID,
			BufferFile bufferFile, String comment, String contentType, boolean resetDatabaseId,
			TaskMonitor monitor, String user)
			throws InvalidNameException, IOException, CancelledException {

		ManagedBufferFile newFile = repository.createDatabase(parentPath, name,
			bufferFile.getBufferSize(), contentType, fileID, null);

		boolean success = false;
		try {
			newFile.setVersionComment(comment);
			LocalBufferFile.copyFile(bufferFile, newFile, null, monitor);
			long checkinId = newFile.getCheckinID();
			newFile.close();
			repository.terminateCheckout(parentPath, name, checkinId, false);
			success = true;
		}
		finally {
			if (!success) {
				newFile.delete();
			}
			newFile.dispose();
		}

		return (DatabaseItem) getItem(parentPath, name);
	}

	@Override
	public DataFileItem createDataFile(String parentPath, String name, InputStream istream,
			String comment, String contentType, TaskMonitor monitor)
			throws InvalidNameException, IOException, CancelledException {
		repository.createDataFile(parentPath, name);
		return (DataFileItem) getItem(parentPath, name);
	}

	@Override
	public FolderItem createFile(String parentPath, String name, File packedFile,
			TaskMonitor monitor, String user)
			throws InvalidNameException, IOException, CancelledException {
		throw new UnsupportedOperationException("Versioned filesystem does not support createFile");
	}

	@Override
	public void deleteFolder(String folderPath) throws IOException {
		throw new UnsupportedOperationException(
			"Versioned filesystem does not support deleteFolder");
	}

	@Override
	public void moveFolder(String parentPath, String folderName, String newParentPath)
			throws InvalidNameException, IOException {
		repository.moveFolder(parentPath, newParentPath, folderName, folderName);
	}

	@Override
	public void renameFolder(String parentPath, String folderName, String newFolderName)
			throws InvalidNameException, IOException {
		repository.moveFolder(parentPath, parentPath, folderName, newFolderName);
	}

	@Override
	public void moveItem(String parentPath, String name, String newParentPath, String newName)
			throws InvalidNameException, IOException {
		repository.moveItem(parentPath, newParentPath, name, newName);
	}

	@Override
	public boolean folderExists(String folderPath) throws IOException {
		return repository.folderExists(folderPath);
	}

	@Override
	public boolean fileExists(String folderPath, String itemName) throws IOException {
		return repository.fileExists(folderPath, itemName);
	}

	@Override
	public void connectionStateChanged(Object adapter) {
		if (adapter == repository) {
			eventManager.syncronize();
		}
	}

	@Override
	public void dispose() {
		eventManager.dispose();
	}

}
