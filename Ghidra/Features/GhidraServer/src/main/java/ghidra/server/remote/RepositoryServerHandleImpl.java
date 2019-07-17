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

import java.io.IOException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

import ghidra.framework.remote.RemoteRepositoryHandle;
import ghidra.framework.remote.RemoteRepositoryServerHandle;
import ghidra.server.Repository;
import ghidra.server.RepositoryManager;
import ghidra.util.exception.UserAccessException;

/**
 * <code>RepositoryServerHandleImpl</code> provides a Respository Server handle to a
 * remote user.
 */
public class RepositoryServerHandleImpl extends UnicastRemoteObject
		implements RemoteRepositoryServerHandle {

	private final String currentUser;
	private final RepositoryManager mgr;
	private final boolean supportPasswordChange;
	private final boolean readOnly;

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#anonymousAccessAllowed()
	 */
	@Override
	public boolean anonymousAccessAllowed() {
		return mgr.anonymousAccessAllowed();
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#isReadOnly()
	 */
	@Override
	public boolean isReadOnly() {
		return readOnly;
	}

	/**
	 * Construct a repository server handle for a specific user.
	 * @param user remote user
	 * @param mgr repository manager
	 * @throws RemoteException
	 */
	public RepositoryServerHandleImpl(String user, boolean readOnly, RepositoryManager mgr,
			boolean supportPasswordChange) throws RemoteException {
		super(ServerPortFactory.getRMISSLPort(), GhidraServer.getRMIClientSocketFactory(),
			GhidraServer.getRMIServerSocketFactory());
		this.currentUser = user;
		this.readOnly = readOnly;
		this.mgr = mgr;
		this.supportPasswordChange = supportPasswordChange;
		mgr.addHandle(this);
	}

	/**
	 * RMI callback when instance becomes unreferenced by any remote client
	 */
	public void unreferenced() {
		mgr.dropHandle(this);
	}

	/*
	 * @see rmitest.RepositoryServerHandle#createRepository(java.lang.String)
	 */
	@Override
	public RemoteRepositoryHandle createRepository(String name) throws IOException {
		Repository repository = mgr.createRepository(currentUser, name);
		return new RepositoryHandleImpl(currentUser, repository);
	}

	/*
	 * @see rmitest.RepositoryServerHandle#getRepository(java.lang.String)
	 */
	@Override
	public RemoteRepositoryHandle getRepository(String name) throws IOException {

		System.gc();

		Repository repository = mgr.getRepository(currentUser, name);
		if (repository == null) {
			return null;
		}
		return new RepositoryHandleImpl(currentUser, repository);
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#deleteRepository(java.lang.String)
	 */
	@Override
	public void deleteRepository(String name) throws UserAccessException, IOException {
		mgr.deleteRepository(currentUser, name);
	}

	/*
	 * @see rmitest.RepositoryServerHandle#getRepositoryNames()
	 */
	@Override
	public String[] getRepositoryNames() {
		return mgr.getRepositoryNames(currentUser);
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#getUser()
	 */
	@Override
	public String getUser() throws IOException {
		return currentUser;
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#getAllUsers()
	 */
	@Override
	public String[] getAllUsers() throws IOException {
		if (readOnly) {
			return new String[0];
		}
		return mgr.getAllUsers(currentUser);
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#canSetPassword()
	 */
	@Override
	public boolean canSetPassword() throws RemoteException {
		return supportPasswordChange && mgr.getUserManager().canSetPassword(currentUser);
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#getPasswordExpiration()
	 */
	@Override
	public long getPasswordExpiration() throws IOException {
		if (canSetPassword()) {
			return mgr.getUserManager().getPasswordExpiration(currentUser);
		}
		return -1;
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#setPassword(char[])
	 */
	@Override
	public boolean setPassword(char[] saltedSHA256PasswordHash) throws IOException {
		if (!canSetPassword()) {
			return false;
		}
		return mgr.getUserManager().setPassword(currentUser, saltedSHA256PasswordHash, false);
	}

	/*
	 * @see ghidra.framework.remote.RepositoryServerHandle#connected()
	 */
	@Override
	public void connected() {
		// do nothing
	}
}
