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

	/**
	 * Construct a repository server handle for a specific user.
	 * @param user remote user
	 * @param readOnly true if restricted to read-only use
	 * @param mgr repository manager
	 * @param supportPasswordChange true if password change is allowed
	 * @throws RemoteException if failed to instantiate remote object
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

	@Override
	public boolean anonymousAccessAllowed() {
		return mgr.anonymousAccessAllowed();
	}

	@Override
	public boolean isReadOnly() {
		return readOnly;
	}

	@Override
	public RemoteRepositoryHandle createRepository(String name) throws IOException {
		try {
			Repository repository = mgr.createRepository(currentUser, name);
			RemoteLoggingUtil.log(name, null, "repository created", currentUser, false);
			return new RepositoryHandleImpl(currentUser, repository);
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t, name,
				null, "Create repository", currentUser);
		}
	}

	@Override
	public RemoteRepositoryHandle getRepository(String name)
			throws UserAccessException, IOException {

		System.gc();

		try {
			Repository repository = mgr.getRepository(currentUser, name);
			if (repository == null) {
				return null;
			}
			return new RepositoryHandleImpl(currentUser, repository);
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t, name,
				null, "Get repository", currentUser);
		}
	}

	@Override
	public void deleteRepository(String name) throws UserAccessException, IOException {
		try {
			mgr.deleteRepository(currentUser, name);
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t, name,
				null, "Delete repository", currentUser);
		}
	}

	@Override
	public String[] getRepositoryNames() {
		return mgr.getRepositoryNames(currentUser);
	}

	@Override
	public String getUser() {
		return currentUser;
	}

	@Override
	public String[] getAllUsers() {
		if (readOnly) {
			return new String[0];
		}
		return mgr.getAllUsers(currentUser);
	}

	@Override
	public boolean canSetPassword() {
		return supportPasswordChange && mgr.getUserManager().canSetPassword(currentUser);
	}

	@Override
	public long getPasswordExpiration() {
		if (canSetPassword()) {
			return mgr.getUserManager().getPasswordExpiration(currentUser);
		}
		return -1;
	}

	@Override
	public boolean setPassword(char[] saltedSHA256PasswordHash) throws IOException {
		try {
			if (!canSetPassword()) {
				return false;
			}
			return mgr.getUserManager().setPassword(currentUser, saltedSHA256PasswordHash, false);
		}
		catch (Throwable t) {
			throw RemoteExceptionUtil.dispatchIOException(t, "Set password", currentUser);
		}
	}

	@Override
	public void connected() {
		// do nothing
	}
}
