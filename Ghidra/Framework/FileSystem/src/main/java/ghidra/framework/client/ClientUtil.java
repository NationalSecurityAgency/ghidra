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

import java.awt.Component;
import java.io.IOException;
import java.net.Authenticator;
import java.net.UnknownHostException;
import java.rmi.*;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Hashtable;

import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;

import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.*;
import ghidra.framework.remote.security.SSHKeyManager;
import ghidra.net.*;
import ghidra.util.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.UserAccessException;
import ghidra.util.task.TaskLauncher;

/**
 * <code>ClientUtil</code> allows a user to connect to a Repository Server and obtain its handle.
 */
public class ClientUtil {

	private static ClientAuthenticator clientAuthenticator;

	private static Hashtable<ServerInfo, RepositoryServerAdapter> serverHandles = new Hashtable<>();

	private ClientUtil() {
	}

	/**
	 * Set client authenticator
	 * @param authenticator
	 */
	public static synchronized void setClientAuthenticator(ClientAuthenticator authenticator) {
		clientAuthenticator = authenticator;
		Authenticator.setDefault(authenticator.getAuthenticator());
		SSHKeyManager.setProtectedKeyStorePasswordProvider(clientAuthenticator);
		ApplicationKeyManagerFactory.setKeyStorePasswordProvider(clientAuthenticator);
	}

	/**
	 * Get the currently installed client authenticator.  If one has not been
	 * installed, this will trigger the installation of a default instance.
	 * @return current client authenticator
	 */
	public static ClientAuthenticator getClientAuthenticator() {
		if (clientAuthenticator == null) {
			if (SystemUtilities.isInHeadlessMode()) {
				setClientAuthenticator(new HeadlessClientAuthenticator());
			}
			else {
				setClientAuthenticator(new DefaultClientAuthenticator());
			}
		}
		return clientAuthenticator;
	}

	/**
	 * Connect to a Repository Server and obtain a handle to it.
	 * Based upon the server authentication requirements, the user may be
	 * prompted for a password via a Swing dialog.  If a previous connection
	 * attempt to this server failed, the adapter may be returned in a
	 * disconnected state.
	 * @param host server name or address
	 * @param port server port, 0 indicates that default port should be used.
	 * @return repository server adapter
	 */
	public static RepositoryServerAdapter getRepositoryServer(String host, int port) {
		return getRepositoryServer(host, port, false);
	}

	/**
	 * Connect to a Repository Server and obtain a handle to it.
	 * Based upon the server authentication requirements, the user may be
	 * prompted for a password via a Swing dialog.
	 * @param host server name or address
	 * @param port server port, 0 indicates that default port should be used.
	 * @param forceConnect if true and the server adapter is disconnected, an
	 * attempt will be made to reconnect.
	 * @return repository server handle
	 */
	public static RepositoryServerAdapter getRepositoryServer(String host, int port,
			boolean forceConnect) {

		// ensure that default callback is setup if possible
		getClientAuthenticator();

		host = host.trim().toLowerCase();
		try {
			host = InetNameLookup.getCanonicalHostName(host);
		}
		catch (UnknownHostException e) {
			Msg.warn(ClientUtil.class, "Failed to resolve hostname for " + host);
		}

		if (port <= 0) {
			port = GhidraServerHandle.DEFAULT_PORT;
		}

		ServerInfo server = new ServerInfo(host, port);

		RepositoryServerAdapter rsa;
		synchronized (serverHandles) {
			rsa = serverHandles.get(server);
			if (rsa == null) {
				rsa = new RepositoryServerAdapter(server);
				serverHandles.put(server, rsa);
				forceConnect = true;
			}
			if (forceConnect) {
				try {
					rsa.connect();
				}
				catch (NotConnectedException e) {
					// message already displayed by RepositoryServerAdapter, so don't handle here
				}
			}
		}

		return rsa;
	}

	/**
	 * Eliminate the specified repository server from the connection cache
	 * @param host host name or IP address
	 * @param port port (0: use default port)
	 * @throws IOException
	 */
	public static void clearRepositoryAdapter(String host, int port) throws IOException {
		host = host.trim().toLowerCase();
		String hostAddr = host;
		try {
			hostAddr = InetNameLookup.getCanonicalHostName(host);
		}
		catch (UnknownHostException e) {
			throw new IOException("Repository server lookup failed: " + host);
		}

		if (port == 0) {
			port = GhidraServerHandle.DEFAULT_PORT;
		}
		ServerInfo server = new ServerInfo(hostAddr, port);
		RepositoryServerAdapter serverAdapter = serverHandles.remove(server);
		if (serverAdapter != null) {
			serverAdapter.disconnect();
		}
	}

	/**
	 * Returns default user login name.  Actual user name used by repository
	 * should be obtained from RepositoryServerAdapter.getUser
	 */
	public static String getUserName() {
		String name = SystemUtilities.getUserName();
		// exclude domain prefix which may be included
		int slashIndex = name.lastIndexOf('\\');
		if (slashIndex >= 0) {
			name = name.substring(slashIndex + 1);
		}
		return name;
	}

	/**
	 *
	 * Displays an error dialog appropriate for the given exception. If the exception is a
	 * ConnectException or NotConnectedException, a prompt to reconnect to the Ghidra Server
	 * is displayed.
	 *
	 * @param repository may be null if the exception is not a RemoteException
	 * @param exc exception that occurred
	 * @param operation operation that was being done when the exception occurred; this string
	 * is be used in the message for the error dialog if one should be displayed
	 * @param mustRetry true if the message should state that the user should retry the operation
	 * because it may not have succeeded (if the exception was because a RemoteException); there
	 * may be cases where the operation succeeded; as a result of the operation, a bad connection
	 * to the server was detected (e.g., save a file). Note: this parameter is ignored if the
	 * exception is not a ConnectException or NotConnectedException.
	 * @param parent parent of the error dialog
	 */
	public static void handleException(RepositoryAdapter repository, Exception exc,
			String operation, boolean mustRetry, Component parent) {

		String title = "Error During " + operation;
		if ((exc instanceof ConnectException) || (exc instanceof NotConnectedException)) {
			Msg.debug(ClientUtil.class, "Server not connected (" + operation + ")");
			promptForReconnect(repository, operation, mustRetry, parent);
		}
		else if (exc instanceof UserAccessException) {
			Msg.showError(ClientUtil.class, parent, title,
				"Access denied: " + repository + "\n" + exc.getMessage());
		}
		else if ((exc instanceof ServerException) || (exc instanceof ServerError)) {
			Msg.showError(ClientUtil.class, parent, title,
				"Exception occurred on the Ghidra Server.", exc.getCause());
		}
		else if (exc instanceof RemoteException) {
			Msg.showError(ClientUtil.class, parent, title,
				"Exception occurred communicating with Ghidra Server.", exc.getCause());
		}
		else {
			String excMsg = exc.getMessage();
			if (excMsg == null) {
				excMsg = exc.toString();
			}
			if (exc instanceof IOException) {
				Msg.showError(ClientUtil.class, parent, title, excMsg, exc);
			}
			else {
				// show the stacktrace for non-IOException
				Msg.showError(ClientUtil.class, parent, title, excMsg, exc);
			}
		}
	}

	/**
	 * Displays an error dialog appropriate for the given exception. If the exception is a
	 * ConnectException or NotConnectedException, a prompt to reconnect to the Ghidra Server
	 * is displayed. The message states that the operation may have to be retried due to the
	 * failed connection.
	 *
	 * @param repository may be null if the exception is not a RemoteException
	 * @param exc exception that occurred
	 * @param operation operation that was being done when the exception occurred; this string
	 * is be used in the message for the error dialog if one should be displayed
	 * @param parent parent of the error dialog
	 */
	public static void handleException(RepositoryAdapter repository, Exception exc,
			String operation, Component parent) {
		handleException(repository, exc, operation, true, parent);
	}

	/**
	 * Prompt the user to reconnect to the Ghidra Server.
	 * @param repository repository to connect to
	 * @param parent parent of the dialog
	 */
	public static void promptForReconnect(RepositoryAdapter repository, Component parent) {
		promptForReconnect(repository, null, false, parent);
	}

	private static void promptForReconnect(final RepositoryAdapter rep, final String operation,
			final boolean mustRetry, final Component parent) {

		getClientAuthenticator();
		if (clientAuthenticator == null) {
			return;
		}

		final StringBuffer sb = new StringBuffer();
		if (mustRetry) {
			sb.append("The " + operation +
				" may have failed due to a lost connection with the Ghidra Server.\n");
			sb.append(
				"You may have to retry the operation after you have reconnected to the server.");
		}
		else {
			sb.append("The connection to the Ghidra Server has been lost.");
		}
		sb.append("\n \nWould you like to reconnect?");

		if (rep != null && clientAuthenticator.promptForReconnect(parent, sb.toString())) {
			try {
				rep.connect();
			}
			catch (NotConnectedException e) {
				// ignore
			}
			catch (IOException e) {
				ClientUtil.handleException(rep, e, "Server Reconnect", null);
			}
		}
	}

	/**
	 * Connect to a Ghidra Server and verify compatibility.  This method can be used
	 * to affectively "ping" the Ghidra Server to verify the ability to connect.
	 * NOTE: Use of this method when PKI authentication is enabled is not supported.
	 * @param host server hostname
	 * @param port first Ghidra Server port (0=use default)
	 * @throws IOException thrown if an IO Error occurs (e.g., server not found).
	 * @throws RemoteException if server interface is incompatible or another server-side
	 * error occurs.
	 */
	public static void checkGhidraServer(String host, int port) throws IOException {
		ServerConnectTask.getGhidraServerHandle(new ServerInfo(host, port));
	}

	/**
	 * Connect to a Repository Server and obtain a handle to it.
	 * Based upon the server authentication requirements, the user may be
	 * prompted for a name/password via a Swing dialog.  If null
	 * is returned, this indicates that the user cancelled the connect
	 * operation.
	 * @param server server address and port
	 * @return repository server handle
	 * @throws LoginException thrown if server fails to authenticate user or
	 * general access is denied.
	 * @throws GeneralSecurityException if server authentication fails due to
	 * credential access error (e.g., PKI cert failure)
	 * @throws IOException thrown if an IO Error occurs.
	 */
	static RemoteRepositoryServerHandle connect(ServerInfo server)
			throws LoginException, GeneralSecurityException, IOException {

		getClientAuthenticator();
		boolean allowLoginRetry = (clientAuthenticator instanceof DefaultClientAuthenticator);

		RemoteRepositoryServerHandle hdl = null;
		ServerConnectTask connectTask = new ServerConnectTask(server, allowLoginRetry);
		if (!SystemUtilities.isInHeadlessMode() && SystemUtilities.isEventDispatchThread()) {
			// Must be done in modal dialog to allow possible authentication prompts
			// from another thread.

			TaskLauncher.launch(connectTask);
		}
		else {
			connectTask.run(null);
		}
		hdl = connectTask.getRepositoryServerHandle();
		if (hdl == null) {
			Exception e = connectTask.getException();
			if (e == null) {
				return null; // cancelled by user
			}
			if (e instanceof IOException) {
				throw (IOException) e;
			}
			if (e instanceof LoginException) {
				throw (LoginException) e;
			}
			if (e instanceof GeneralSecurityException) {
				throw (GeneralSecurityException) e;
			}
			if (e instanceof RuntimeException) {
				throw (RuntimeException) e;
			}
			throw new AssertException(e);
		}
		return hdl;
	}

	/**
	 * Prompt user and change password on server (not initiated by user).
	 * @param parent dialog parent
	 * @param handle server handle
	 * @param serverInfo server information
	 * @throws IOException
	 */
	public static void changePassword(Component parent, RepositoryServerHandle handle,
			String serverInfo) throws IOException {
		getClientAuthenticator();
		if (clientAuthenticator == null) {
			return;
		}
		char[] pwd = null;
		try {
			pwd = clientAuthenticator.getNewPassword(parent, serverInfo, handle.getUser());
			if (pwd != null) {
				handle.setPassword(
					HashUtilities.getSaltedHash(HashUtilities.SHA256_ALGORITHM, pwd));
				Msg.showInfo(ClientUtil.class, parent, "Password Changed",
					"Password was changed successfully");
			}
		}
		finally {
			if (pwd != null) {
				// Attempt to remove traces of password in memory
				Arrays.fill(pwd, ' ');
			}
		}
	}

	static boolean processPasswordCallbacks(Callback[] callbacks, String serverName,
			String defaultUserID, String loginError) throws IOException {
		getClientAuthenticator();
		if (clientAuthenticator == null) {
			Msg.error(ClientUtil.class, "Unable to authenticate user without ClientAuthenticator");
			return false;
		}
		NameCallback nameCb = null;
		PasswordCallback passCb = null;
		ChoiceCallback choiceCb = null;
		AnonymousCallback anonymousCb = null;
		for (Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				nameCb = (NameCallback) callback;
				nameCb.setName(defaultUserID);
			}
			else if (callback instanceof PasswordCallback) {
				passCb = (PasswordCallback) callback;
			}
			else if (callback instanceof ChoiceCallback) {
				choiceCb = (ChoiceCallback) callback;
			}
			else if (callback instanceof AnonymousCallback) {
				anonymousCb = (AnonymousCallback) callback;
			}
		}
		if (passCb == null) {
			throw new IOException(
				"Unsupported authentication callback: " + callbacks[0].getClass().getName());
		}
		if (!clientAuthenticator.processPasswordCallbacks("Repository Server Authentication",
			"Repository Server", serverName, nameCb, passCb, choiceCb, anonymousCb, loginError)) {
			return false;
		}
		String name = defaultUserID;
		if (nameCb != null) {
			name = nameCb.getName();
			if (name == null) {
				name = nameCb.getDefaultName();
			}
		}
		Msg.info(ClientUtil.class,
			"Password authenticating to " + serverName + " as user '" + name + "'");
		return true;
	}

	static void processSignatureCallback(String serverName, SignatureCallback sigCb)
			throws IOException {
		try {
			SignedToken signedToken = ApplicationKeyManagerUtils.getSignedToken(
				sigCb.getRecognizedAuthorities(), sigCb.getToken());
			sigCb.sign(signedToken.certChain, signedToken.signature);
			Msg.info(ClientUtil.class, "PKI Authenticating to " + serverName + " as user '" +
				signedToken.certChain[0].getSubjectDN() + "'");
		}
		catch (Exception e) {
			String msg = e.getMessage();
			if (msg == null) {
				msg = e.toString();
			}
			throw new IOException(msg, e);
		}
	}

	static boolean processSSHSignatureCallback(Callback[] callbacks, String serverName,
			String defaultUserID) {
		NameCallback nameCb = null;
		SSHSignatureCallback sshCb = null;
		for (Callback callback : callbacks) {
			if (callback instanceof NameCallback) {
				nameCb = (NameCallback) callback;
				nameCb.setName(defaultUserID);
			}
			else if (callback instanceof SSHSignatureCallback) {
				sshCb = (SSHSignatureCallback) callback;
			}
		}
		if (sshCb == null || !clientAuthenticator.isSSHKeyAvailable()) {
			return false;
		}
		if (!clientAuthenticator.processSSHSignatureCallbacks(serverName, nameCb, sshCb)) {
			return false;
		}
		Msg.info(ClientUtil.class,
			"SSH Authenticating to " + serverName + " as user '" + defaultUserID + "'");
		return true;
	}

	public static boolean isSSHKeyAvailable() {
		return clientAuthenticator.isSSHKeyAvailable();
	}

}
