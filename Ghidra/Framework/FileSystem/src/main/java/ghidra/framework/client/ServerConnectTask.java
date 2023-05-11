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

import java.io.Closeable;
import java.io.IOException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.UnknownHostException;
import java.rmi.*;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.cert.Certificate;
import java.util.HashSet;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import ghidra.framework.Application;
import ghidra.framework.model.ServerInfo;
import ghidra.framework.remote.*;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;

/**
 * Task for connecting to server with Swing thread.
 */
class ServerConnectTask extends Task {

	private static final int LIVENESS_CHECK_TIMEOUT_MS = 3000;

	private ServerInfo server;
	//private String defaultUserID;
	private boolean allowLoginRetry;
	private RemoteRepositoryServerHandle hdl;
	private Exception exc;

	/**
	 * Server Connect Task constructor
	 * @param server server information
	 * @param allowLoginRetry true if login retry allowed during authentication
	 */
	ServerConnectTask(ServerInfo server, boolean allowLoginRetry) {
		super("Connecting to " + server.getServerName(), true, false, true);
		this.server = server;
		this.allowLoginRetry = allowLoginRetry;
	}

	/**
	 * Completes and necessary authentication and obtains a repository handle.
	 * If a connection error occurs, an exception will be stored ({@link #getException()}.
	 * @throws CancelledException if task cancelled
	 * @see ghidra.util.task.Task#run(ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor = TaskMonitor.dummyIfNull(monitor);
		try {
			hdl = getRepositoryServerHandle(ClientUtil.getUserName(), monitor);
		}
		catch (RemoteException e) {
			exc = e;
			Throwable t = e.getCause();
			if (t instanceof Exception) {
				exc = (Exception) t;
			}
		}
		catch (Exception e) {
			exc = e;
		}
		finally {
			if (monitor.isCancelled()) {
				exc = null;
				throw new CancelledException();
			}
		}
	}

	/**
	 * Returns an IOException, LoginException or RuntimeException
	 * if handle is null after running task.  If both the exception
	 * and handle are null, it implies the connection attempt was cancelled
	 * by the user.
	 * @return exception which occured during a failed connection attempt, or null
	 */
	Exception getException() {
		return exc;
	}

	/**
	 * After running the task, this method will return the server handle
	 * if the connection was successful.  If null, a connection error
	 * may have occurred ({@link #getException()}, or the task was cancelled
	 * by the user if both the exception and handle are null.
	 * @return server handle or null if connection attempt failed or was cancelled
	 */
	RemoteRepositoryServerHandle getRepositoryServerHandle() {
		return hdl;
	}

	private static Subject getLocalUserSubject() {
		String username = ClientUtil.getUserName();
		HashSet<GhidraPrincipal> pset = new HashSet<>();
		HashSet<Object> emptySet = new HashSet<>();
		pset.add(new GhidraPrincipal(username));
		Subject subj = new Subject(false, pset, emptySet, emptySet);
		return subj;
	}

	private static boolean isSSLHandshakeCancelled(SSLHandshakeException e) throws IOException {
		if (e.getMessage().indexOf("bad_certificate") > 0) {
			if (ApplicationKeyManagerFactory.getPreferredKeyStore() == null) {
				throw new IOException("User PKI Certificate not installed", e);
			}
			// assume user cancelled connect attempt when prompted for cert password
			// or other cert error occurred
			return true;
		}
// TODO: Translate SSL exceptions to more meaningful errors
//		else if (e.getMessage().indexOf("certificte_unknown") > 0) {
//			// cert issued by unrecognized authority
//		}
		return false;
	}

	/**
	 * Obtain a remote instance of the Ghidra Server Handle object
	 * @param server server information
	 * @param monitor cancellable monitor
	 * @return Ghidra Server Handle object
	 * @throws IOException if a connection error occurs
	 * @throws CancelledException if connection attempt was cancelled
	 */
	public static GhidraServerHandle getGhidraServerHandle(ServerInfo server, TaskMonitor monitor)
			throws IOException, CancelledException {

		GhidraServerHandle gsh = null;
		boolean canCancel = monitor.isCancelEnabled(); // original state
		try {

			// Test SSL Handshake to ensure that user is able to decrypt keystore.
			// This is intended to work around an RMI issue where a continuous
			// retry condition can occur when a user cancels the password entry
			// for their keystore which should cancel any connection attempt
			testServerSSLConnection(server, monitor);

			monitor.setCancelEnabled(false);
			monitor.setMessage("Connecting...");

			Registry reg =
				LocateRegistry.getRegistry(server.getServerName(), server.getPortNumber(),
					new SslRMIClientSocketFactory());
			checkServerBindNames(reg);

			gsh = (GhidraServerHandle) reg.lookup(GhidraServerHandle.BIND_NAME);
			gsh.checkCompatibility(GhidraServerHandle.INTERFACE_VERSION);
		}
		catch (NotBoundException e) {
			throw new IOException(e.getMessage());
		}
		catch (SSLHandshakeException e) {
			if (isSSLHandshakeCancelled(e)) {
				return null;
			}
			throw e;
		}
		catch (RemoteException e) {
			Throwable cause = e.getCause();
			if (cause instanceof UnmarshalException || cause instanceof ClassNotFoundException) {
				throw new RemoteException("Incompatible Ghidra Server interface version");
			}
			if (cause instanceof SSLHandshakeException) {
				if (isSSLHandshakeCancelled((SSLHandshakeException) cause)) {
					return null;
				}
			}
			throw e;
		}
		finally {
			monitor.setCancelEnabled(canCancel);
			monitor.setMessage("");
		}
		return gsh;
	}

	private static class ConnectCancelledListener implements CancelledListener, Closeable {

		private TaskMonitor monitor;
		private CancelledListener callback;

		ConnectCancelledListener(TaskMonitor monitor, CancelledListener callback) {
			this.monitor = monitor;
			this.callback = callback;
			monitor.addCancelledListener(this);
		}

		@Override
		public void cancelled() {
			if (callback != null) {
				callback.cancelled();
			}
		}

		@Override
		public void close() throws IOException {
			monitor.removeCancelledListener(this);
		}
	}

	/**
	 * Attempts server connection and completes any necessary authentication.
	 * @param defaultUserID default user ID (actual ID used established during authentication)
	 * @param monitor task monitor for connection cancellation
	 * @return server handle or null if authentication or connection attempt was cancelled by user
	 * @throws IOException if server connection fails
	 * @throws LoginException  login failure
	 */
	private RemoteRepositoryServerHandle getRepositoryServerHandle(String defaultUserID,
			TaskMonitor monitor)
			throws IOException, LoginException, CancelledException {

		GhidraServerHandle gsh = getGhidraServerHandle(server, monitor);

		Callback[] callbacks = null;
		try {
			boolean loopOK = allowLoginRetry;
			String loginError = null;
			callbacks = gsh.getAuthenticationCallbacks();

			SignatureCallback pkiSignatureCb = null;
			boolean hasSSHSignatureCallback = false;
			if (callbacks != null) {
				for (Callback cb : callbacks) {
					if (cb instanceof SignatureCallback) {
						pkiSignatureCb = (SignatureCallback) cb;
					}
					else if (cb instanceof SSHSignatureCallback) {
						hasSSHSignatureCallback = true;
					}
				}
			}

			AnonymousCallback onlyAnonymousCb = null;
			while (true) {
				try {
					if (callbacks != null) {
						if (onlyAnonymousCb != null) {
							// First try using no-authentication must have failed - 
							// go ahead and request anonymous access without asking
							onlyAnonymousCb.setAnonymousAccessRequested(true);
							loopOK = false; // final try
						}
						else if (callbacks.length == 1 &&
							callbacks[0] instanceof AnonymousCallback) {
							// Anonymous option available with No-Authentication mode
							// Give no-authentication a chance to work with user-id
							// If it fails, a second try will be done using anonymous access
							onlyAnonymousCb = (AnonymousCallback) callbacks[0];
							loopOK = true;
						}
						else if (hasSSHSignatureCallback && ClientUtil.isSSHKeyAvailable()) {
							// SSH option only available in conjunction with password
							// based authentication which will be used if SSH attempt fails
							hasSSHSignatureCallback = false; // only try SSH once
							ClientUtil.processSSHSignatureCallback(callbacks,
								server.getServerName(), defaultUserID);
						}
						else if (pkiSignatureCb != null) {
							// when using PKI - no other authentication callback will be used
							// if anonymous access allowed, let server validate certificate
							// first and assume anonymous access if user unknown but cert is valid

							if (!ApplicationKeyManagerFactory.initialize()) {
								throw new IOException(
									"Client PKI certificate has not been installed");
							}

							if (ApplicationKeyManagerFactory.usingGeneratedSelfSignedCertificate()) {
								Msg.warn(this,
									"Server connect - client is using self-signed PKI certificate");
							}

							loopOK = false; // only try once
							ClientUtil.processSignatureCallback(server.getServerName(),
								pkiSignatureCb);
						}
						else {
							// assume all other callback scenarios are password based
							// anonymous option must be explicitly chosen over username/password
							// when processing password callback
							if (!ClientUtil.processPasswordCallbacks(callbacks,
								server.getServerName(), defaultUserID, loginError)) {
								return null; // Cancelled by user
							}
						}
					}
					else {
						loopOK = false;
					}
					final RemoteRepositoryServerHandle rsh =
						gsh.getRepositoryServer(getLocalUserSubject(), callbacks);
					if (rsh.isReadOnly()) {
						Msg.showInfo(this, null, "Anonymous Server Login",
							"You have been logged-in anonymously to " + server.getServerName() +
								"\nRead-only permission is granted to repositories which allow anonymous access");
					}
					return rsh;
				}
				catch (FailedLoginException e) {
					if (loopOK) {
						loginError = "Access denied: " + server;
					}
					else {
						throw e;
					}
				}
			}
		}
		catch (AccessException e) {
			throw new IOException(e.getMessage());
		}
		finally {
			if (callbacks != null) {
				for (Callback callback : callbacks) {
					if (callback instanceof PasswordCallback) {
						((PasswordCallback) callback).clearPassword();
					}
				}
			}
		}
	}

	private static void forceClose(Socket s) {
		try {
			s.close();
		}
		catch (IOException e) {
			// ignore
		}
	}

	/**
	 * Socket implementation with very short connect timeout
	 */
	private static class FastConnectionFailSocket extends Socket {
		FastConnectionFailSocket(String host, int port) throws UnknownHostException, IOException {
			super(host, port);
		}

		public void connect(SocketAddress endpoint) throws IOException {
			connect(endpoint, LIVENESS_CHECK_TIMEOUT_MS);
		}
	}

	/**
	 * Initiate an SSLSocket connection in order to ensure that any neccesary client/server
	 * certificate validation is performed.
	 * @param server server to which connection should be verified.  For the Ghidra Server 
	 * this should correspond to the RMI Registry port {@link GhidraServerHandle#DEFAULT_PORT}.
	 * @param monitor connection task monitor
	 * @return certificate chain of server
	 * @throws IOException if connection failure occurs
	 * @throws CancelledException if connection attempt is cancelled
	 */
	private static Certificate[] testServerSSLConnection(ServerInfo server, TaskMonitor monitor)
			throws IOException, CancelledException {

		RMIServerPortFactory portFactory = new RMIServerPortFactory(server.getPortNumber());
		SslRMIClientSocketFactory factory = new SslRMIClientSocketFactory();
		String serverName = server.getServerName();
		int sslRmiPort = portFactory.getRMISSLPort();

		monitor.setCancelEnabled(true);
		monitor.setMessage("Checking Server Liveness...");
		
		// Perform simple socket test connection with short timeout to verify connectivity.
		try (Socket socket = new FastConnectionFailSocket(serverName, sslRmiPort);
				ConnectCancelledListener cancelListener =
					new ConnectCancelledListener(monitor, () -> forceClose(socket))) {
			// do nothing - connect occurs during instantiation
		}
		finally {
			monitor.checkCancelled(); // circumvent any IOException which may have occured
		}

		// Perform secure socket test connection to prime keystore use without RMI involvement
		try (SSLSocket socket = (SSLSocket) factory.createSocket(serverName, sslRmiPort);
				ConnectCancelledListener cancelListener =
					new ConnectCancelledListener(monitor, () -> forceClose(socket))) {
			// Complete SSL handshake to trigger client keystore access if required
			// which will give user ability to cancel without involving RMI which 
			// will avoid RMI reconnect attempts
			socket.startHandshake();
			return socket.getSession().getPeerCertificates();
		}
		finally {
			monitor.checkCancelled(); // circumvent any IOException which may have occured
		}
	}

	private static void checkServerBindNames(Registry reg) throws RemoteException {

		String requiredVersion = GhidraServerHandle.MIN_GHIDRA_VERSION;
		if (!Application.getApplicationVersion().startsWith(requiredVersion)) {
			requiredVersion = requiredVersion + " - " + Application.getApplicationVersion();
		}

		String[] regList = reg.list();
		RemoteException exc = null;
		int badVerCount = 0;

		for (String name : regList) {
			if (name.equals(GhidraServerHandle.BIND_NAME)) {
				return; // found it
			}
			else if (name.startsWith(GhidraServerHandle.BIND_NAME_PREFIX)) {
				String version = name.substring(GhidraServerHandle.BIND_NAME_PREFIX.length());
				if (version.length() == 0) {
					version = "4.3.x (or older)";
				}
				exc = new RemoteException(
					"Incompatible Ghidra Server interface, detected interface version " + version +
						",\nthis client requires server version " + requiredVersion);
				++badVerCount;
			}
		}
		if (exc != null) {
			if (badVerCount == 1) {
				throw exc;
			}
			throw new RemoteException("Incompatible Ghidra Server interface, detected " +
				badVerCount + " incompatible server versions" +
				",\nthis client requires server version " + requiredVersion);
		}
		throw new RemoteException("Ghidra Server not found.");
	}

}
