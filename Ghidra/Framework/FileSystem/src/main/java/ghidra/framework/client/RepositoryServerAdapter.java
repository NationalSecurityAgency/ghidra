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

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.rmi.RemoteException;
import java.security.GeneralSecurityException;

import javax.security.auth.login.LoginException;

import docking.widgets.OptionDialog;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.RepositoryHandle;
import ghidra.framework.remote.RepositoryServerHandle;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.*;

/**
 * <code>RepositoryServerAdapter</code> provides a persistent wrapper for a 
 * <code>RepositoryServerHandle</code> which may become invalid if the 
 * remote connection were to fail.
 */
public class RepositoryServerAdapter {

	private static final int HOUR = 60 * 60 * 1000;

	private final ServerInfo server;
	private final String serverInfoStr;
	private String currentUser = ClientUtil.getUserName();

	private RepositoryServerHandle serverHandle;
	private boolean unexpectedDisconnect = false;

	// Keeps track of whether the connection attempt was cancelled by the user
	private boolean connectCancelled = false;

	private WeakSet<RemoteAdapterListener> listenerList =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	/**
	 * Construct a repository server interface adapter.
	 * @param server provides server connection data
	 */
	RepositoryServerAdapter(ServerInfo server) {
		this.server = server;
		this.serverInfoStr = server.toString();
	}

	/**
	 * Construct a repository server interface adapter.
	 * @param serverHandle associated server handle (reconnect not supported)
	 */
	protected RepositoryServerAdapter(RepositoryServerHandle serverHandle,
			String serverInfoString) {
		this.server = null;
		this.serverHandle = serverHandle;
		this.serverInfoStr = serverInfoString;
	}

	@Override
	public String toString() {
		return serverInfoStr;
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
	 * Returns true if the connection was cancelled by the user.
	 * 
	 * @return try if cancelled by user
	 */
	public boolean isCancelled() {
		return connectCancelled;
	}

	/**
	 * Notify listeners of a connection state change.
	 */
	private void fireStateChanged() {
		for (RemoteAdapterListener listener : listenerList) {
			listener.connectionStateChanged(this);
		}
	}

	/**
	 * Returns true if connected.
	 */
	public boolean isConnected() {
		return serverHandle != null;
	}

	/**
	 * Attempt to connect or re-connect to the server.
	 * @return true if connect successful, false if cancelled by user
	 * @throws NotConnectedException if connect failed (error will be displayed to user)
	 */
	public synchronized boolean connect() throws NotConnectedException {
		connectCancelled = false;

		if (serverHandle != null) {
			if (verifyConnection()) {
				return true;
			}
		}

		Throwable cause = null;
		try {
			serverHandle = ClientUtil.connect(server);
			unexpectedDisconnect = false;
			if (serverHandle != null) {
				Msg.info(this, "Connected to Ghidra Server at " + serverInfoStr);
				currentUser = serverHandle.getUser();
				fireStateChanged();

				checkPasswordExpiration();

				return true;
			}

			// Connect operation cancelled by the user
			connectCancelled = true;
			return false;
		}
		catch (LoginException e) {
			Msg.showError(this, null, "Server Error",
				"Server access denied (" + serverInfoStr + ").");
			cause = e;
		}
		catch (GeneralSecurityException e) {
			Msg.showError(this, null, "Server Error",
				"Server access denied (" + serverInfoStr + "): " + e.getMessage());
			cause = e;
		}
		catch (SocketTimeoutException | java.net.ConnectException | java.rmi.ConnectException e) {
			Msg.showError(this, null, "Server Error",
				"Connection to server failed (" + server + ").");
			cause = e;
		}
		catch (java.net.UnknownHostException | java.rmi.UnknownHostException e) {
			Msg.showError(this, null, "Server Error",
				"Server Not Found (" + server.getServerName() + ").");
			cause = e;
		}
		catch (RemoteException e) {
			String msg = e.getMessage();
			Throwable t = e;
			while ((t = t.getCause()) != null) {
				String err = t.getMessage();
				msg = err != null ? err : t.toString();
				cause = t;
			}
			Msg.showError(this, null, "Server Error",
				"An error occurred on the server (" + serverInfoStr + ").\n" + msg, e);
		}
		catch (IOException e) {
			String err = e.getMessage();
			if (err == null && (e instanceof EOFException)) {
				err = "Ghidra Server process may have died";
			}
			String msg = err != null ? err : e.toString();
			Msg.showError(this, null, "Server Error",
				"An error occurred while connecting to the server (" + serverInfoStr + ").\n" + msg,
				e);
		}
		throw new NotConnectedException("Not connected to repository server", cause);
	}

	private void checkPasswordExpiration() {
		try {
			if (!serverHandle.canSetPassword()) {
				return;
			}
			final long expiration = serverHandle.getPasswordExpiration();
			if (expiration >= 0) {
				String msg;
				if (expiration == 0) {
					msg = "Your server password has expired!\nPlease change immediately.";
				}
				else {
					long hours = (expiration + HOUR - 1) / HOUR;
					msg = "Your password will expire in less than " + hours +
						" hour(s)!\nPlease change immediately.";
				}
				if (SystemUtilities.isInHeadlessMode()) {
					Msg.warn(this, msg);
				}
				else if (OptionDialog.OPTION_ONE == OptionDialog.showOptionDialog(null,
					"Password Change Required", msg, "OK", OptionDialog.WARNING_MESSAGE)) { // modal
					try {
						ClientUtil.changePassword(null, serverHandle, serverInfoStr);
					}
					catch (IOException e) {
						Msg.showError(ServerConnectTask.class, null, "Password Change Failed",
							"Password changed failed due to server error!", e);
					}
				}
			}
		}
		catch (Exception e) {
			// getPasswordExpiration method added without changing interface version
			// Ignore marshalling error which may occur
		}
	}

	/**
	 * Returns true if the server handle is already connected
	 * and functioning properly.  A simple remote call is made 
	 * to the handle's connected() method to verify the connection.
	 */
	synchronized boolean verifyConnection() {
		if (serverHandle == null) {
			return false;
		}
		try {
			serverHandle.connected();
		}
		catch (NotConnectedException | RemoteException e) {
			if (!recoverConnection(e)) {
				return false;
			}
		}
		catch (IOException e) {
			return false;
		}
		return true;
	}

	private boolean recoverConnection(IOException e) {
		if (server == null) {
			return false;
		}

		disconnect(true);
		return false;
	}

//	/**
//	 * Following an error, this method may be invoked to reestablish 
//	 * the remote connection if needed.  If the connection is not
//	 * down, the RemoteException passed in is simply re-thrown.
//	 * @param re remote exception which may have been caused by a 
//	 * broken connection.
//	 * @throws RemoteException re is re-thrown if connection is OK
//	 * @throws NotConnectedException thrown if connection recovery failed.
//	 */
//	void recover(RemoteException re) throws RemoteException, NotConnectedException {
//		if (verifyConnection()) {
////			Err.error(this, null, "Error", "Unexpected Exception: " + re.getMessage(), re); 
//			throw re;
//		}
//		serverHandle = null;
//		fireStateChanged();
//		if (error != null) {
//			Err.show(null, "Server Error", "A server communications error occurred!", error);
//			error = null;
//			throw new NotConnectedException("Not connected to repository server");
//		}
//		connect();
//		error = re;
//	}

	/**
	 * Create a new repository on the server.
	 * @param name repository name.
	 * @return handle to new repository.
	 * @throws DuplicateNameException
	 * @throws UserAccessException
	 * @throws IOException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#createRepository(String)
	 */
	public synchronized RepositoryAdapter createRepository(String name)
			throws DuplicateNameException, UserAccessException, IOException, NotConnectedException {
		checkServerHandle();
		try {
			return new RepositoryAdapter(this, name, serverHandle.createRepository(name));
		}
		catch (RemoteException e) {
			Throwable t = e.getCause();
			if (t instanceof DuplicateFileException) {
				throw new DuplicateNameException("Repository '" + name + "' already exists");
			}
			else if (t instanceof UserAccessException) {
				throw (UserAccessException) t;
			}
			if (recoverConnection(e)) {
				return new RepositoryAdapter(this, name, serverHandle.createRepository(name));
			}
			throw e;
		}
	}

	/**
	 * Get a handle to an existing repository.  The repository adapter is
	 * initially disconnected - the connect() method or another repository 
	 * action method must be invoked to establish a repository connection. 
	 * @param name repository name.
	 * @return repository handle or null if repository not found.
	 */
	public RepositoryAdapter getRepository(String name) {
		return new RepositoryAdapter(this, name);
	}

	/**
	 * Get a handle to an existing repository.
	 * @param name repository name.
	 * @return repository handle or null if repository not found.
	 * @throws UserAccessException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#getRepository(java.lang.String)
	 */
	synchronized RepositoryHandle getRepositoryHandle(String name)
			throws IOException, NotConnectedException {
		checkServerHandle();
		try {
			return serverHandle.getRepository(name);
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				return serverHandle.getRepository(name);
			}
			throw e;
		}
	}

	/**
	 * Delete a repository.
	 * @param name repository name.
	 * @throws UserAccessException
	 * @throws IOException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#deleteRepository(java.lang.String)
	 */
	public synchronized void deleteRepository(String name)
			throws UserAccessException, IOException, NotConnectedException {
		checkServerHandle();
		try {
			serverHandle.deleteRepository(name);
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				serverHandle.deleteRepository(name);
				return;
			}
			throw e;
		}
	}

	/**
	 * Returns a list of all repository names defined to the server.
	 * @throws IOException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#getRepositoryNames()
	 */
	public synchronized String[] getRepositoryNames() throws IOException, NotConnectedException {
		checkServerHandle();
		try {
			return serverHandle.getRepositoryNames();
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				return serverHandle.getRepositoryNames();
			}
			throw e;
		}
	}

	/**
	 * @return true if server allows anonymous access.
	 * Individual repositories must grant anonymous access separately.
	 * @throws IOException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#anonymousAccessAllowed()
	 */
	public synchronized boolean anonymousAccessAllowed() throws IOException, NotConnectedException {
		checkServerHandle();
		try {
			return serverHandle.anonymousAccessAllowed();
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				return serverHandle.anonymousAccessAllowed();
			}
			throw e;
		}
	}

	/**
	 * @return true if user has restricted read-only access to server (e.g., anonymous user)
	 * @throws IOException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#isReadOnly()
	 */
	public synchronized boolean isReadOnly() throws IOException, NotConnectedException {
		checkServerHandle();
		try {
			return serverHandle.isReadOnly();
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				return serverHandle.isReadOnly();
			}
			throw e;
		}
	}

	/**
	 * Returns user's server login identity
	 */
	public String getUser() {
		return currentUser;
	}

	/**
	 * Returns a list of all known users.
	 * @throws IOException
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#getAllUsers()
	 */
	public synchronized String[] getAllUsers() throws IOException, NotConnectedException {
		checkServerHandle();
		try {
			return serverHandle.getAllUsers();
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				return serverHandle.getAllUsers();
			}
			throw e;
		}
	}

	/**
	 * Set the simple password for the user.
	 * @param saltedSHA256PasswordHash hex character representation of salted SHA256 hash of the password
	 * @return true if password changed
	 * @throws IOException if user data can't be written to file
	 * @throws NotConnectedException if server connection is down (user already informed)
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#setPassword(char[])
	 * @see ghidra.util.HashUtilities#getSaltedHash(String, char[])  HashUtilities.getSaltedHash("SHA-256", char[])
	 */
	public synchronized boolean setPassword(char[] saltedSHA256PasswordHash)
			throws IOException, NotConnectedException {
		checkServerHandle();
		try {
			return serverHandle.setPassword(saltedSHA256PasswordHash);
		}
		catch (RemoteException e) {
			if (recoverConnection(e)) {
				return serverHandle.setPassword(saltedSHA256PasswordHash);
			}
			throw e;
		}
	}

	/**
	 * Returns true if this server allows the user to change their password.
	 * @see ghidra.framework.remote.RemoteRepositoryServerHandle#canSetPassword()
	 */
	public synchronized boolean canSetPassword() {
		try {
			checkServerHandle();
			try {
				return serverHandle.canSetPassword();
			}
			catch (RemoteException e) {
				if (recoverConnection(e)) {
					return serverHandle.canSetPassword();
				}
			}
		}
		catch (IOException e) {
			// just return false
		}
		return false;
	}

	/**
	 * Returns the amount of time in milliseconds until the 
	 * user's password will expire.
	 * @return time until expiration or -1 if it will not expire
	 * @throws IOException
	 */
//	public synchronized long getPasswordExpiration() {
//        try {
//            checkServerHandle();
//            try {
//            	return serverHandle.getPasswordExpiration();
//            }
//            catch (RemoteException e) {
//    			disconnect();
//            }
//        } catch (IOException e) {
//        }
//        return -1;
//	}

	/**
	 * Returns server information.  May be null if using fixed RepositoryServerHandle.
	 */
	public ServerInfo getServerInfo() {
		return server;
	}

	private void checkServerHandle() throws NotConnectedException {
		if (serverHandle == null) {
			throw new NotConnectedException("Not connected to the server");
		}
	}

	boolean hadUnexpectedDisconnect() {
		return unexpectedDisconnect;
	}

	/**
	 * Force disconnect with server
	 */
	public void disconnect() {
		disconnect(true);
	}

	private void disconnect(boolean unexpected) {
		if (server == null) {
			return; // disconnect/reconnect not supported (Project level URL mechanism)
		}
		unexpectedDisconnect = unexpected;
		Msg.warn(this, "Disconnected from Ghidra Server at " + serverInfoStr);
		serverHandle = null;
		fireStateChanged();
	}
}
