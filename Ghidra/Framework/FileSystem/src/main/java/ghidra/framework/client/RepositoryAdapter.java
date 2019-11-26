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
package ghidra.framework.client;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.rmi.*;

import db.buffers.ManagedBufferFileAdapter;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.*;
import ghidra.framework.store.*;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.UserAccessException;

/**
 * <code>RepositoryAdapter</code> provides a persistent wrapper for a remote RepositoryHandle 
 * which may become invalid if the remote connection were to fail.  Connection recovery is provided 
 * by any method call which must communicate with the server.
 */
public class RepositoryAdapter implements RemoteAdapterListener {

	private String name;
	private RepositoryServerAdapter serverAdapter;

	private WeakSet<RemoteAdapterListener> listenerList =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private RepositoryHandle repository;
	private User user;

	private boolean unexpectedDisconnect = false;
	private boolean noSuchRepository = false;
	private volatile int openFileHandleCount = 0;
	private boolean ignoreNextOpenFileCountEvent = false;

	private RepositoryChangeDispatcher changeDispatcher;

	/** 
	 * Construct.
	 * @param serverAdapter persistent server adapter
	 * @param name repository name
	 */
	public RepositoryAdapter(RepositoryServerAdapter serverAdapter, String name) {
		this.serverAdapter = serverAdapter;
		this.name = name;
		changeDispatcher = new RepositoryChangeDispatcher(this);
		serverAdapter.addListener(this);
	}

	/**
	 * Constructor using a connected repository handle.
	 * @param serverAdapter persistent server adapter
	 * @param name repository name
	 * @param repository connected repository handle.
	 */
	RepositoryAdapter(RepositoryServerAdapter serverAdapter, String name,
			RepositoryHandle repository) {
		this(serverAdapter, name);
		this.repository = repository;
		if (repository != null) {
			changeDispatcher.start();
		}
	}

	/**
	 * Returns true if connection recently was lost unexpectedly
	 */
	public boolean hadUnexpectedDisconnect() {
		return unexpectedDisconnect;
	}

	@Override
	public String toString() {
		return serverAdapter.toString() + "(" + name + ")";
	}

	RepositoryHandle getCurrentHandle() {
		return repository;
	}

	/**
	 * Set the file system listener associated with the remote repository.
	 * @param fsListener file system listener
	 */
	public void setFileSystemListener(FileSystemListener fsListener) {
		changeDispatcher.setFileChangeListener(fsListener);
	}

	/**
	 * Add a listener to this remote adapter
	 * @param listener
	 */
	public void addListener(RemoteAdapterListener listener) {
		listenerList.add(listener);
	}

	/**
	 * Remove a listener from this remote adapter
	 * @param listener
	 */
	public void removeListener(RemoteAdapterListener listener) {
		listenerList.remove(listener);
	}

	/**
	 * Notify listeners of repository connection state change.
	 */
	private void fireStateChanged() {
		for (RemoteAdapterListener listener : listenerList) {
			listener.connectionStateChanged(this);
		}
	}

	/**
	 * Notification callback when server connection state changes.
	 * @see ghidra.framework.client.RemoteAdapterListener#connectionStateChanged(java.lang.Object)
	 */
	@Override
	public void connectionStateChanged(Object adapter) {
		synchronized (serverAdapter) {
			if (!serverAdapter.isConnected()) {
				disconnect(serverAdapter.hadUnexpectedDisconnect(), true);
			}
			else {
				try {
					connect();
				}
				catch (IOException e) {
					// TODO: handle failed connect?
				}
			}
		}
	}

	/**
	 * Returns true if connected.
	 */
	public boolean isConnected() {
		return repository != null;
	}

	/**
	 * Attempt to connect to the server.
	 */
	public void connect() throws IOException {
		synchronized (serverAdapter) {
			if (repository != null) {
				try {
					repository.getName(); // just called to test the connection.
				}
				catch (NotConnectedException | RemoteException e) {
					if (recoverConnection(e)) {
						return;
					}
					throw e;
				}
			}
			if (repository == null) {
				serverAdapter.connect(); // may cause auto-reconnect of repository
			}
			if (repository == null) {
				repository = serverAdapter.getRepositoryHandle(name);
				unexpectedDisconnect = false;
				if (repository == null) {
					noSuchRepository = true;
					throw new IOException("Repository '" + name + "': not found");
				}
				Msg.info(this, "Connected to repository '" + name + "'");
				changeDispatcher.start();
				fireStateChanged();
			}
		}
	}

	/**
	 * Event reader for change dispatcher.
	 * @return
	 * @throws IOException 
	 * @throws InterruptedIOException if repository handle is closed
	 */
	RepositoryChangeEvent[] getEvents() throws InterruptedIOException {
		RepositoryHandle handle;
		synchronized (serverAdapter) {
			// Be careful with synchronization since getEvents will block
			// until an event occurs
			if (repository == null) {
				throw new InterruptedIOException();
			}
			handle = repository;
		}
		try {
			return handle.getEvents();
		}
		catch (NotConnectedException | RemoteException e) {
			// Initiate recover - dispatcher will be restarted
			recoverConnection(e);
			throw new InterruptedIOException();
		}
		catch (IOException e) {
			synchronized (serverAdapter) {
				if (!Thread.currentThread().isInterrupted()) {
					serverAdapter.verifyConnection();
					disconnect(true, true);
				}
			}
			throw new InterruptedIOException();
		}
	}

	/**
	 * Returns repository name
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns server adapter 
	 */
	public RepositoryServerAdapter getServer() {
		return serverAdapter;
	}

	/**
	 * Returns server information
	 */
	public ServerInfo getServerInfo() {
		return serverAdapter.getServerInfo();
	}

	boolean recoverConnection(IOException e) {
		synchronized (serverAdapter) {

			if (Thread.currentThread().isInterrupted()) {
				return false;
			}

			// TODO: does exception correspond to a connection or marshaling error?

			if (!serverAdapter.verifyConnection()) {
				disconnect(serverAdapter.hadUnexpectedDisconnect(), true);
				return false;
			}

			if (noSuchRepository || !(e instanceof NoSuchObjectException)) {
				return false;
			}

			disconnect(true, false);
			try {
				connect();
			}
			catch (IOException e1) {
				fireStateChanged();
				return false;
			}
			// fireStateChanged(); // force full refresh - NOTE: this could cause a flood of requests if server was bounced
			// TODO: without a full refresh lost events could cause a stale view 
			return true;
		}
	}

	/**
	 * Returns repository user object.
	 * @throws UserAccessException user no longer has any permission to use repository.
	 * @throws NotConnectedException if server/repository connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryHandle#getUser()
	 */
	public User getUser() throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				if (user == null) {
					user = repository.getUser();
				}
				return user;
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return getUser();
				}
				throw e;
			}
		}
	}

	/**
	 * @return true if anonymous access allowed by this repository
	 * @throws IOException
	 */
	public boolean anonymousAccessAllowed() throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.anonymousAccessAllowed();
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return anonymousAccessAllowed();
				}
				throw e;
			}
		}
	}

	/**
	 * Returns list of repository users.
	 * @throws IOException
	 * @throws UserAccessException user no longer has any permission to use repository.
	 * @throws NotConnectedException if server/repository connection is down (user already informed)
	 * @see RemoteRepositoryHandle#getUserList()
	 */
	public User[] getUserList() throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getUserList();
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getUserList();
				}
				throw e;
			}
		}
	}

	/**
	 * Returns list of all users known to server.
	 * @throws IOException
	 * @throws UserAccessException user no longer has any permission to use repository.
	 * @throws NotConnectedException if server/repository connection is down (user already informed)
	 * @see RemoteRepositoryHandle#getServerUserList()
	 */
	public String[] getServerUserList() throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getServerUserList();
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getServerUserList();
				}
				throw e;
			}
		}
	}

	/**
	 * Set the list of authorized users for this repository.
	 * @param users list of user and access permissions.
	 * @param anonymousAccessAllowed true to permit anonymous access (also requires anonymous
	 * access to be enabled for server)
	 * @throws UserAccessException
	 * @throws IOException
	 * @throws NotConnectedException if server/repository connection is down (user already informed)
	 * @see RemoteRepositoryHandle#setUserList(User[], boolean)
	 */
	public void setUserList(User[] users, boolean anonymousAccessAllowed) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				repository.setUserList(users, anonymousAccessAllowed);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					repository.setUserList(users, anonymousAccessAllowed);
					return;
				}
				throw e;
			}
		}
	}

	/**
	 * @see RepositoryHandle#createDatabase(String, String, String, int, String, String)
	 */
	public ManagedBufferFileAdapter createDatabase(String parentPath, String itemName,
			int bufferSize, String contentType, String fileID, String projectPath)
			throws IOException, InvalidNameException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				ManagedBufferFileAdapter bf =
					new ManagedBufferFileAdapter(repository.createDatabase(parentPath, itemName,
						fileID, bufferSize, contentType, projectPath));
				fileOpened();
				return bf;
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					ManagedBufferFileAdapter bf =
						new ManagedBufferFileAdapter(repository.createDatabase(parentPath,
							itemName, fileID, bufferSize, contentType, projectPath));
					fileOpened();
					return bf;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#openDatabase(java.lang.String, java.lang.String, int)
	 */
	public ManagedBufferFileAdapter openDatabase(String parentPath, String itemName, int version,
			int minChangeDataVer) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				ManagedBufferFileAdapter bf =
					new ManagedBufferFileAdapter(repository.openDatabase(parentPath, itemName,
						version, minChangeDataVer));
				fileOpened();
				return bf;
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					ManagedBufferFileAdapter bf =
						new ManagedBufferFileAdapter(repository.openDatabase(parentPath, itemName,
							version, minChangeDataVer));
					fileOpened();
					return bf;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#openDatabase(java.lang.String, java.lang.String, long)
	 */
	public ManagedBufferFileAdapter openDatabase(String parentPath, String itemName, long checkoutId)
			throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				ManagedBufferFileAdapter bf =
					new ManagedBufferFileAdapter(repository.openDatabase(parentPath, itemName,
						checkoutId));
				fileOpened();
				return bf;
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					ManagedBufferFileAdapter bf =
						new ManagedBufferFileAdapter(repository.openDatabase(parentPath, itemName,
							checkoutId));
					fileOpened();
					return bf;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#createDataFile(java.lang.String, java.lang.String)
	 */
	public void createDataFile(String parentPath, String itemName) throws IOException {
		throw new IOException("Data file not yet supported by repository");
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#openDataFile(java.lang.String, java.lang.String, int)
	 */
	public DataFileHandle openDataFile(String parentPath, String itemName, int version)
			throws IOException {
		throw new IOException("Data file not yet supported by repository");
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getSubfolderList(java.lang.String)
	 */
	public String[] getSubfolderList(String folderPath) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getSubfolderList(folderPath);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getSubfolderList(folderPath);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getItemCount()
	 */
	public int getItemCount() throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getItemCount();
			}
			catch (NotConnectedException | RemoteException e) {
				checkUnmarshalException(e, "getItemCount");
				if (recoverConnection(e)) {
					try {
						return repository.getItemCount();
					}
					catch (RemoteException e1) {
						checkUnmarshalException(e1, "getItemCount");
						throw e1;
					}
				}
				throw e;
			}
		}
	}

	/**
	 * Convert UnmarshalException into UnsupportedOperationException
	 * @param e
	 * @throws UnsupportedOperationException
	 */
	private void checkUnmarshalException(IOException e, String operation)
			throws UnsupportedOperationException {
		Throwable t = e.getCause();
		if (t instanceof UnmarshalException) {
			throw new UnsupportedOperationException(operation);
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getItemList(java.lang.String)
	 */
	public RepositoryItem[] getItemList(String folderPath) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getItemList(folderPath);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getItemList(folderPath);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getItem(java.lang.String, java.lang.String)
	 */
	public RepositoryItem getItem(String folderPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getItem(folderPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getItem(folderPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getItem(java.lang.String)
	 */
	public RepositoryItem getItem(String fileID) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getItem(fileID);
			}
			catch (NotConnectedException | RemoteException e) {
				checkUnmarshalException(e, "getItem by File-ID");
				if (recoverConnection(e)) {
					try {
						return repository.getItem(fileID);
					}
					catch (RemoteException e1) {
						checkUnmarshalException(e1, "getItem by File-ID");
						throw e1;
					}
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getVersions(java.lang.String, java.lang.String)
	 */
	public Version[] getVersions(String parentPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getVersions(parentPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getVersions(parentPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#deleteItem(java.lang.String, java.lang.String, int)
	 */
	public void deleteItem(String parentPath, String itemName, int version) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				repository.deleteItem(parentPath, itemName, version);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					repository.deleteItem(parentPath, itemName, version);
					return;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#moveFolder(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public void moveFolder(String oldParentPath, String newParentPath, String oldFolderName,
			String newFolderName) throws InvalidNameException, IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				repository.moveFolder(oldParentPath, newParentPath, oldFolderName, newFolderName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					repository.moveFolder(oldParentPath, newParentPath, oldFolderName,
						newFolderName);
					return;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#moveItem(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	public void moveItem(String oldParentPath, String newParentPath, String oldItemName,
			String newItemName) throws InvalidNameException, IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				repository.moveItem(oldParentPath, newParentPath, oldItemName, newItemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					repository.moveItem(oldParentPath, newParentPath, oldItemName, newItemName);
					return;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#checkout(java.lang.String, java.lang.String, ghidra.framework.store.CheckoutType, java.lang.String)
	 */
	public ItemCheckoutStatus checkout(String folderPath, String itemName,
			CheckoutType checkoutType, String projectPath) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.checkout(folderPath, itemName, checkoutType, projectPath);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.checkout(folderPath, itemName, checkoutType, projectPath);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#terminateCheckout(java.lang.String, java.lang.String, long, boolean)
	 */
	public void terminateCheckout(String folderPath, String itemName, long checkoutId,
			boolean notify) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				repository.terminateCheckout(folderPath, itemName, checkoutId, notify);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					repository.terminateCheckout(folderPath, itemName, checkoutId, notify);
					return;
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getCheckout(java.lang.String, java.lang.String, long, boolean)
	 */
	public ItemCheckoutStatus getCheckout(String parentPath, String itemName, long checkoutId)
			throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getCheckout(parentPath, itemName, checkoutId);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getCheckout(parentPath, itemName, checkoutId);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getCheckout(java.lang.String, java.lang.String)
	 */
	public ItemCheckoutStatus[] getCheckouts(String parentPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getCheckouts(parentPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getCheckouts(parentPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#folderExists(java.lang.String)
	 */
	public boolean folderExists(String folderPath) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.folderExists(folderPath);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.folderExists(folderPath);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#fileExists(java.lang.String, java.lang.String)
	 */
	public boolean fileExists(String folderPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.fileExists(folderPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.fileExists(folderPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#getLength(java.lang.String, java.lang.String)
	 */
	public long getLength(String parentPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.getLength(parentPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.getLength(parentPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#hasCheckouts(java.lang.String, java.lang.String)
	 */
	public boolean hasCheckouts(String parentPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.hasCheckouts(parentPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.hasCheckouts(parentPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#isCheckinActive(java.lang.String, java.lang.String)
	 */
	public boolean isCheckinActive(String parentPath, String itemName) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				return repository.isCheckinActive(parentPath, itemName);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					return repository.isCheckinActive(parentPath, itemName);
				}
				throw e;
			}
		}
	}

	/*
	 * @see ghidra.framework.remote.RepositoryHandle#updateCheckoutVersion(java.lang.String, java.lang.String, long, int)
	 */
	public void updateCheckoutVersion(String parentPath, String itemName, long checkoutId,
			int checkoutVersion) throws IOException {
		synchronized (serverAdapter) {
			checkRepository();
			try {
				repository.updateCheckoutVersion(parentPath, itemName, checkoutId, checkoutVersion);
			}
			catch (NotConnectedException | RemoteException e) {
				if (recoverConnection(e)) {
					repository.updateCheckoutVersion(parentPath, itemName, checkoutId,
						checkoutVersion);
					return;
				}
				throw e;
			}
		}
	}

	/**
	 * Verify that the connection is still valid.
	 * @return true if the connection is valid; false if the connection needs to be reestablished
	 */
	public boolean verifyConnection() {
		if (!serverAdapter.verifyConnection()) {
			return false;
		}
		return true;
	}

	public void disconnect() {
		disconnect(false, true);
	}

	void disconnect(boolean unexpected, boolean notify) {
		synchronized (serverAdapter) {
			if (repository != null) {
				unexpectedDisconnect = unexpected;
				Msg.info(this, "Disconnected from repository '" + name + "'");
				changeDispatcher.stop();
				try {
					repository.close();
				}
				catch (Throwable t) {
					// Failed to close...oh well.
				}
				repository = null;
				user = null;
				if (notify) {
					fireStateChanged();
				}
			}
		}
	}

	private void checkRepository() throws NotConnectedException {
		if (repository == null) {
			throw new NotConnectedException("Not connected to the server");
		}
	}

	private void fileOpened() {
		++openFileHandleCount; // force immediate change instead of waiting for delayed update event
		ignoreNextOpenFileCountEvent = true; // avoid race condition
	}

	void processOpenHandleCountUpdateEvent(RepositoryChangeEvent event) {
		synchronized (serverAdapter) {
			if (ignoreNextOpenFileCountEvent) {
				ignoreNextOpenFileCountEvent = false;
				return;
			}
			if (event.type != RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT) {
				throw new IllegalArgumentException("Expected REP_OPEN_HANDLE_COUNT event");
			}
			openFileHandleCount = Integer.parseInt(event.newName);
		}
	}

	public int getOpenFileHandleCount() {
		return openFileHandleCount;
	}

}
