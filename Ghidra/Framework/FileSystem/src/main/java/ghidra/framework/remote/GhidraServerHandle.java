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
package ghidra.framework.remote;

import java.rmi.Remote;
import java.rmi.RemoteException;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.login.FailedLoginException;

/**
 * <code>GhidraServerHandle</code> provides access to a remote server.
 * This remote interface facilitates user login/authentication, providing
 * a more useful handle to the associated repository server.
 */
public interface GhidraServerHandle extends Remote {

	/**
	 * The collective interface version for all Ghidra Server remote interfaces.
	 * If any remote interface is modified, this value should be incremented.
	 * 
	 * Version Change History:
	 *   1: Original Version
	 *   2: Changed API to support NAT and firewalls
	 *   3: Allow user to login with alternate user ID
	 *   4: Added additional checkout data and database ID support (4.2)
	 *   5: Added support for quick update of checkout file following merged check-in on server,
	 *      also added alternate authentication via password file (4.4)
	 *   6: Refactored BufferFile related classes creating a ManagedBufferFile which
	 *      supports all the version-control capabilities. (5.2)
	 *   7: Added support for SSH authentication callback, anonymous user access (5.4)
	 *   8: Added salted local passwords, added LocalIndexedFilesystem V1 with ability to obtain file count (6.1)
	 *   9: Added support for transient checkouts (7.2)
	 *   10: Added BlockStreamServer (7.4)
	 *   11: Revised password hash to SHA-256 (9.0)
	 *       - version 9.1 switched to using SSL/TLS for RMI registry connection preventing
	 *         older clients the ability to connect to the server.  Remote interface remained
	 *         unchanged allowing 9.1 clients to connect to 9.0 server.
	 *   12: Revised RepositoryFile serialization to facilitate support for text-data used
	 *       for link-file storage (12.0).
	 *   13: Client-side serialization filters have been implemented and server-side thrown
	 *       exceptions reduced to be compliant with client-side filters.  Server still
	 *       supports older clients back to interface version 11.  Server may now BIND
	 *       to the RMI registery with two different names if needed.
	 */

	/**
	 * The server interface version that the server implements.  This corresponds to the maximum 
	 * supported client interface version.
	 */
	public static final int SERVER_INTERFACE_VERSION = 13;

	/**
	 * The minimum server interface version that the client can operate with.
	 */
	public static final int MIN_CLIENT_INTERFACE_VERSION = 13;

	/**
	 * The minimum interface version that the server will support for older client versions.  
	 * When this version is less than {@link #MIN_CLIENT_INTERFACE_VERSION} it allows the following:
	 * <ul>
	 * <li>Older ghidra client versions can continue using the current server version, while</li>
	 * <li>Current ghidra clients version cannot use an older version server.</li>
	 * </ul>
	 * When this version differs from {@link #MIN_CLIENT_INTERFACE_VERSION} the server will bind two
	 * both {@link #BIND_NAME} and {@value #ALT_BIND_NAME}.
	 * <p>
	 * NOTE: It is important that the server authentication interface not be modified between this
	 * version and {@value #MIN_CLIENT_INTERFACE_VERSION}.
	 */
	public static final int SERVER_MIN_CLIENT_INTERFACE_VERSION = 11;

	/**
	 * The server BIND version which the Ghidra client can communicate with.  
	 * This corresponds to {@value #MIN_CLIENT_INTERFACE_VERSION}.
	 */
	public static final String GHIDRA_BIND_VERSION = "12.0.5";

	/**
	 * Minimum version of a Ghidra client release which can communicate with the current 
	 * Ghidra Server.  This corresponds to {@value #SERVER_MIN_CLIENT_INTERFACE_VERSION}
	 * and {@link #ALT_BIND_NAME}.
	 * <p>
	 * This version is used only by the server only in publishing an alternate BIND name and
	 * identifies the oldest Ghidra client version that may connect.
	 */
	public static final String ALT_GHIDRA_BIND_VERSION = "9.0";

	/**
	 * Default RMI base port for Ghidra Server
	 */
	static final int DEFAULT_PORT = 13100;

	/**
	 * RMI registry binding name prefix for all versions of the remote GhidraServerHandle object.
	 */
	static final String BIND_NAME_PREFIX = "GhidraServer";

	/**
	 * Primary RMI registry binding name for the remote GhidraServerHandle object.
	 * This BIND name is used by both the server and client.
	 */
	static final String BIND_NAME = BIND_NAME_PREFIX + GHIDRA_BIND_VERSION;

	/**
	 * Alternate RMI registry binding name for the remote GhidraServerHandle object. 
	 * This alternate BIND name is used only by the server in support of older Ghidra clients
	 * and corresponds to {@link #SERVER_MIN_CLIENT_INTERFACE_VERSION}.
	 */
	static final String ALT_BIND_NAME = BIND_NAME_PREFIX + ALT_GHIDRA_BIND_VERSION;

	/**
	 * Returns user authentication proxy object.
	 * @throws RemoteException if failure occurs while generating authentication callbacks
	 * @return authentication callbacks which must be satisfied or null if authentication not
	 * required.
	 */
	Callback[] getAuthenticationCallbacks() throws RemoteException;

	/**
	 * Get a handle to the repository server.
	 * @param user user subject containing GhidraPrincipal
	 * @param authCallbacks valid authentication callback objects which have been satisfied, or
	 * null if server does not require authentication.
	 * @return repository server handle.
	 * @throws FailedLoginException if user authentication fails
	 * @throws RemoteException failed to create remote handle
	 * @see #getAuthenticationCallbacks()
	 */
	RemoteRepositoryServerHandle getRepositoryServer(Subject user, Callback[] authCallbacks)
			throws FailedLoginException, RemoteException;

	/**
	 * Check server interface compatibility with the specified client interface version.
	 * @param clientInterfaceVersion client/server interface version
	 * @throws RemoteException if requested server interface version not available
	 */
	void checkCompatibility(int clientInterfaceVersion) throws RemoteException;

}
