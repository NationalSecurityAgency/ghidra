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
package ghidra.server.remote;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.NoSuchObjectException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.rmi.server.Unreferenced;
import java.util.HashMap;
import java.util.LinkedList;

import db.buffers.*;
import ghidra.framework.remote.*;
import ghidra.framework.store.*;
import ghidra.server.Repository;
import ghidra.server.RepositoryManager;
import ghidra.server.store.RepositoryFile;
import ghidra.server.store.RepositoryFolder;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.FileInUseException;

/**
 * <code>RepositoryHandleImpl</code> provides a Repository handle to a
 * remote user.
 */
public class RepositoryHandleImpl extends UnicastRemoteObject implements RemoteRepositoryHandle,
		Unreferenced {

//	private final RepositoryChangeEvent NULL_EVENT = new RepositoryChangeEvent(
//		RepositoryChangeEvent.REP_NULL_EVENT, null, null, null, null);

	private volatile boolean isValid = true;
	private boolean clientActive = true;
	private String currentUser;
	private Repository repository;
	private HashMap<String, ItemCheckoutStatus> transientCheckouts;
	private Object syncObject;

	private LinkedList<RepositoryChangeEvent> eventQueue = new LinkedList<RepositoryChangeEvent>();

	/**
	 * Construct a repository handle for a specific user.
	 * @param user
	 * @param repository
	 * @throws RemoteException
	 */
	RepositoryHandleImpl(String user, Repository repository) throws RemoteException {
		super(ServerPortFactory.getRMISSLPort(), GhidraServer.getRMIClientSocketFactory(),
			GhidraServer.getRMIServerSocketFactory());
		this.currentUser = user;
		this.repository = repository;
		this.syncObject = repository.getSyncObject();
		RepositoryManager.log(repository.getName(), null, "generated handle", user);
		repository.addHandle(this);
	}

	public Repository getRepository() {
		return repository;
	}

	/**
	 * RMI callback when instance becomes unreferenced by any remote client
	 */
	@Override
	public void unreferenced() {
		dispose();
	}

	/**
	 * Dispose handle
	 */
	public void dispose() {
		synchronized (syncObject) {
			if (!isValid) {
				return;
			}
			terminateTransientCheckouts();
			RepositoryManager.log(repository.getName(), null, "handle disposed", currentUser);
			if (eventQueue != null) {
				synchronized (eventQueue) {
					eventQueue.clear();
					eventQueue.notifyAll();
				}
			}
			try {
				unexportObject(this, true);
			}
			catch (NoSuchObjectException e) {
				// ignore
			}
			repository.dropHandle(this);
			RemoteBufferFileImpl.dispose(this);
			currentUser = null;
			isValid = false;
		}
	}

	private void terminateTransientCheckouts() {
		if (transientCheckouts == null || transientCheckouts.isEmpty()) {
			return;
		}
		try {
			repository.log(null, "Clearning " + transientCheckouts.size() + " transiet checkouts",
				currentUser);
			for (String pathname : transientCheckouts.keySet()) {
				int index = pathname.lastIndexOf(FileSystem.SEPARATOR_CHAR);
				String parentPath = FileSystem.SEPARATOR;
				if (index != 0) {
					parentPath = pathname.substring(0, index);
				}
				String itemName = pathname.substring(index + 1);

				ItemCheckoutStatus transientCheckout = transientCheckouts.get(pathname);

				// Since dropped transient checkouts could occur in large volume due to headless
				// processing, don't bother sending notification
				terminateCheckout(parentPath, itemName, transientCheckout.getCheckoutId(), false);
			}
		}
		catch (IOException e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			msg = "Failed to cleanup transient checkouts - server restart may be required: " + msg;
			RepositoryManager.log(repository.getName(), null, msg, currentUser);
		}
	}

	private void addTransientCheckout(String pathname, ItemCheckoutStatus checkoutStatus) {
		if (transientCheckouts == null) {
			transientCheckouts = new HashMap<String, ItemCheckoutStatus>();
		}
		transientCheckouts.put(pathname, checkoutStatus);
	}

	private void removeTransientCheckout(String pathname, long checkoutId) {
		if (transientCheckouts == null) {
			return;
		}
		ItemCheckoutStatus transientCheckout = transientCheckouts.get(pathname);
		if (transientCheckout != null && transientCheckout.getCheckoutId() == checkoutId) {
			transientCheckouts.remove(pathname);
		}
	}

	private void validate() throws RemoteException {
		if (!isValid) {
			throw new RemoteException("bad repository handle");
		}
	}

	/**
	 * Post repository change events to the client.
	 * @param event change event
	 */
	public void dispatchEvents(RepositoryChangeEvent[] events) {
		synchronized (eventQueue) {
			if (!isValid) {
				return;
			}
			for (RepositoryChangeEvent event : events) {
				eventQueue.addLast(event);
			}
			eventQueue.notifyAll();
		}
	}

	/**
	 * Verify that the client is active and continuing to read events
	 */
	public void checkHandle() {
		if (!isValid) {
			return;
		}

		RepositoryChangeEvent openFileCountEvent =
			new RepositoryChangeEvent(RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT, null, null,
				null, Integer.toString(RemoteBufferFileImpl.getOpenFileCount(this)));

		synchronized (eventQueue) {
			if (clientActive) {
				clientActive = false;
				if (eventQueue.isEmpty()) {

					//eventQueue.add(0, NULL_EVENT);

					// Send open-file count periodically instead of null event
					eventQueue.add(openFileCountEvent);

					eventQueue.notifyAll();
				}
				return;
			}
		}
		RepositoryManager.log(repository.getName(), null, "not listening!", currentUser);
		dispose();
	}

	public void fireOpenFileCountChanged() {
//		if (!isValid) {
//			return;
//		}
//
//		RepositoryChangeEvent event =
//			new RepositoryChangeEvent(RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT, null, null,
//				null, Integer.toString(RemoteBufferFileImpl.getOpenFileCount(this)));
//		synchronized (eventQueue) {
//
//			// Remove existing queued event
//			Iterator<RepositoryChangeEvent> iterator = eventQueue.iterator();
//			while (iterator.hasNext()) {
//				RepositoryChangeEvent queuedEvent = iterator.next();
//				if (queuedEvent.type == RepositoryChangeEvent.REP_OPEN_HANDLE_COUNT) {
//					iterator.remove();
//					break;
//				}
//			}
//
//			eventQueue.add(event);
//			eventQueue.notifyAll();
//		}
	}

	@Override
	public RepositoryChangeEvent[] getEvents() throws IOException {
		synchronized (eventQueue) {
			clientActive = true;
			if (eventQueue.isEmpty()) {
				try {
					eventQueue.wait();
				}
				catch (InterruptedException e) {
					throw new IOException("Event wait cancelled");
				}
			}
			if (eventQueue.isEmpty()) {
				throw new IOException("Handle disposed by server");
			}
			RepositoryChangeEvent[] events = new RepositoryChangeEvent[eventQueue.size()];
			eventQueue.toArray(events);
			eventQueue.clear();
			return events;
		}
	}

	@Override
	public void close() {
		dispose();
	}

	@Override
	public String getName() throws RemoteException {
		synchronized (syncObject) {
			validate();
			return repository.getName();
		}
	}

	@Override
	public User[] getUserList() throws IOException {
		synchronized (syncObject) {
			validate();
			return repository.getUserList(currentUser);
		}
	}

	@Override
	public boolean anonymousAccessAllowed() throws IOException {
		synchronized (syncObject) {
			validate();
			return repository.anonymousAccessAllowed();
		}
	}

	@Override
	public void setUserList(User[] users, boolean anonymousAccessAllowed) throws IOException {
		synchronized (syncObject) {
			validate();
			repository.setUserList(currentUser, users, anonymousAccessAllowed);
		}
	}

	@Override
	public User getUser() throws RemoteException {
		synchronized (syncObject) {
			validate();
			return repository.getUser(currentUser);
		}
	}

	public String getUserName() {
		return currentUser;
	}

	@Override
	public String[] getServerUserList() throws IOException {
		synchronized (syncObject) {
			validate();
			return repository.getServerUserList(currentUser);
		}
	}

	@Override
	public String[] getSubfolderList(String folderPath) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFolder folder;
			try {
				folder = repository.getFolder(currentUser, folderPath, false);
			}
			catch (InvalidNameException e) {
				throw new AssertException();
			}
			if (folder == null) {
				return new String[0];
			}
			RepositoryFolder[] subfolders = folder.getFolders();
			String[] subfolderNames = new String[subfolders.length];
			for (int i = 0; i < subfolders.length; i++) {
				subfolderNames[i] = subfolders[i].getName();
			}
			return subfolderNames;
		}
	}

	@Override
	public int getItemCount() throws IOException {
		synchronized (syncObject) {
			validate();
			return repository.getItemCount();
		}
	}

	@Override
	public RepositoryItem[] getItemList(String folderPath) throws IOException {
		synchronized (syncObject) {
			validate();
			try {
				RepositoryFolder folder = repository.getFolder(currentUser, folderPath, false);
				if (folder == null) {
					return new RepositoryItem[0];
				}
				RepositoryFile[] files = folder.getFiles();
				RepositoryItem[] items = new RepositoryItem[files.length];
				for (int i = 0; i < files.length; i++) {
					items[i] = files[i].getItem();
				}
				return items;
			}
			catch (InvalidNameException e) {
				throw new AssertException();
			}
		}
	}

	@Override
	public RepositoryItem getItem(String folderPath, String name) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(folderPath, name);
			return rf != null ? rf.getItem() : null;
		}
	}

	@Override
	public RepositoryItem getItem(String fileID) throws IOException {
		throw new UnsupportedOperationException("getItem by File-ID");
	}

	private RepositoryFile getFile(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			try {
				RepositoryFolder folder = repository.getFolder(currentUser, parentPath, false);
				if (folder != null) {
					RepositoryFile rf = folder.getFile(itemName);
					if (rf != null) {
						return rf;
					}
				}
			}
			catch (InvalidNameException e) {
				throw new AssertException();
			}
			return null;
		}
	}

	@Override
	public RemoteManagedBufferFileHandle createDatabase(String parentPath, String itemName,
			String fileID, int bufferSize, String contentType, String projectPath)
			throws InvalidNameException, IOException {
		synchronized (syncObject) {
			validate();
			repository.validateWritePrivilege(currentUser);
			RepositoryFolder folder = repository.getFolder(currentUser, parentPath, true);
			if (folder == null) {
				throw new IOException("Failed to create repository Folder " + parentPath);
			}
			LocalManagedBufferFile bf =
				folder.createDatabase(itemName, fileID, bufferSize, contentType, currentUser,
					projectPath);
			return new RemoteManagedBufferFileImpl(bf, this, getPathname(parentPath, itemName));
		}
	}

	@Override
	public RemoteManagedBufferFileImpl openDatabase(String parentPath, String itemName,
			int version, int minChangeDataVer) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			LocalManagedBufferFile bf = rf.openDatabase(version, minChangeDataVer, currentUser);
			return new RemoteManagedBufferFileImpl(bf, this, getPathname(parentPath, itemName));
		}
	}

	@Override
	public RemoteManagedBufferFileImpl openDatabase(String parentPath, String itemName,
			long checkoutId) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			LocalManagedBufferFile bf = rf.openDatabase(checkoutId, currentUser);
			return new RemoteManagedBufferFileImpl(bf, this, getPathname(parentPath, itemName));
		}
	}

	@Override
	public Version[] getVersions(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			return rf.getVersions(currentUser);
		}
	}

	@Override
	public void deleteItem(String parentPath, String itemName, int version) throws IOException {
		synchronized (syncObject) {
			validate();
			repository.validateWritePrivilege(currentUser);
			checkFileInUse(parentPath, itemName);
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf != null) {
				rf.delete(version, currentUser);
			}
		}
	}

	@Override
	public void moveFolder(String oldParentPath, String newParentPath, String oldFolderName,
			String newFolderName) throws InvalidNameException, IOException {
		synchronized (syncObject) {
			validate();
			repository.validateWritePrivilege(currentUser);
			checkFolderInUse(oldParentPath, oldFolderName);
			RepositoryFolder folder =
				repository.getFolder(currentUser, oldParentPath + FileSystem.SEPARATOR +
					oldFolderName, false);
			RepositoryFolder newParent = repository.getFolder(currentUser, newParentPath, true);
			if (folder != null) {
				folder.moveTo(newParent, newFolderName, currentUser);
			}
		}
	}

	@Override
	public void moveItem(String oldParentPath, String newParentPath, String oldItemName,
			String newItemName) throws InvalidNameException, IOException {
		synchronized (syncObject) {
			validate();
			repository.validateWritePrivilege(currentUser);
			checkFileInUse(oldParentPath, oldItemName);
			RepositoryFile rf = getFile(oldParentPath, oldItemName);
			if (rf == null) {
				throw new FileNotFoundException(oldItemName + " not found in repository");
			}
			RepositoryFolder folder = repository.getFolder(currentUser, newParentPath, true);
			if (folder == null) {
				throw new IOException("Failed to create repository Folder " + newParentPath);
			}
			rf.moveTo(folder, newItemName, currentUser);
		}
	}

	private void checkFileInUse(String parentPath, String itemName) throws FileInUseException {
		String[] openFileUsers =
			RemoteBufferFileImpl.getOpenFileUsers(repository.getName(),
				getPathname(parentPath, itemName));
		if (openFileUsers != null) {
			StringBuffer buf = new StringBuffer("");
			for (String user : openFileUsers) {
				if (buf.length() != 0) {
					buf.append(", ");
				}
				buf.append(user);
			}
			throw new FileInUseException(itemName + " in use by: " + buf.toString());
		}
	}

	private void checkFolderInUse(String parentPath, String folderName) throws IOException {
		RepositoryFolder folder;
		try {
			folder = repository.getFolder(currentUser, getPathname(parentPath, folderName), false);
			if (folder == null) {
				return;
			}
			if (isFolderInUse(folder)) {
				throw new FileInUseException("Repository folder " + folderName +
					" contains one or more files that are checked-out by one or more users.");
			}
		}
		catch (InvalidNameException e) {
			// ignore
		}
	}

	private boolean isFolderInUse(RepositoryFolder folder) throws IOException {
		for (RepositoryFolder f : folder.getFolders()) {
			if (isFolderInUse(f)) {
				return true;
			}
		}
		for (RepositoryFile rf : folder.getFiles()) {
			if (rf.hasCheckouts()) {
				return true;
			}
			String[] openFileUsers =
				RemoteBufferFileImpl.getOpenFileUsers(repository.getName(),
					getPathname(folder.getPathname(), rf.getName()));
			if (openFileUsers != null) {
				return true;
			}
		}
		return false;
	}

	@Override
	public ItemCheckoutStatus checkout(String parentPath, String itemName,
			CheckoutType checkoutType, String projectPath) throws IOException {
		synchronized (syncObject) {
			validate();
			repository.validateWritePrivilege(currentUser);
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			ItemCheckoutStatus checkoutStatus = rf.checkout(checkoutType, currentUser, projectPath);
			if (checkoutStatus != null &&
				checkoutStatus.getCheckoutType() == CheckoutType.TRANSIENT) {
				addTransientCheckout(rf.getPathname(), checkoutStatus);
			}
			return checkoutStatus;
		}
	}

	@Override
	public void updateCheckoutVersion(String parentPath, String itemName, long checkoutId,
			int checkoutVersion) throws IOException {
		synchronized (syncObject) {
			validate();
			repository.validateWritePrivilege(currentUser);
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf != null) {
				rf.updateCheckoutVersion(checkoutId, checkoutVersion, currentUser);
			}
		}
	}

	@Override
	public void terminateCheckout(String parentPath, String itemName, long checkoutId,
			boolean notify) throws IOException {
		synchronized (syncObject) {
			validate(); // relax read-only restriction
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf != null) {
				rf.terminateCheckout(checkoutId, currentUser, notify);
				removeTransientCheckout(rf.getPathname(), checkoutId);
			}
		}
	}

	@Override
	public ItemCheckoutStatus getCheckout(String parentPath, String itemName, long checkoutId)
			throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			return rf.getCheckout(checkoutId, currentUser);
		}
	}

	@Override
	public ItemCheckoutStatus[] getCheckouts(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			return rf.getCheckouts(currentUser);
		}
	}

	@Override
	public boolean folderExists(String folderPath) throws IOException {
		synchronized (syncObject) {
			validate();
			try {
				return (repository.getFolder(currentUser, folderPath, false) != null);
			}
			catch (InvalidNameException e) {
				throw new AssertException();
			}
		}
	}

	@Override
	public boolean fileExists(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf;
			try {
				rf = getFile(parentPath, itemName);
			}
			catch (FileNotFoundException e) {
				return false;
			}
			return rf != null;
		}
	}

	@Override
	public long getLength(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf;
			try {
				rf = getFile(parentPath, itemName);
				if (rf == null) {
					return 0;
				}
				return rf.length();
			}
			catch (FileNotFoundException e) {
				return 0;
			}
		}
	}

	@Override
	public boolean hasCheckouts(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			return rf.hasCheckouts();
		}
	}

	@Override
	public boolean isCheckinActive(String parentPath, String itemName) throws IOException {
		synchronized (syncObject) {
			validate();
			RepositoryFile rf = getFile(parentPath, itemName);
			if (rf == null) {
				throw new FileNotFoundException(itemName + " not found in repository");
			}
			return rf.isCheckinActive();
		}
	}

	private static String getPathname(String parentPath, String itemName) {
		StringBuffer path = new StringBuffer(parentPath);
		if (path.charAt(path.length() - 1) != FileSystem.SEPARATOR_CHAR) {
			path.append(FileSystem.SEPARATOR_CHAR);
		}
		path.append(itemName);
		return path.toString();
	}

}
