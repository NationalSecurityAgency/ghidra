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
import javax.security.auth.login.LoginException;

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
	 */
	public static final int INTERFACE_VERSION = 11;

	/**
	 * Minimum version of Ghidra which utilized the current INTERFACE_VERSION
	 */
	public static final String MIN_GHIDRA_VERSION = "9.0";

	/**
	 * Default RMI base port for Ghidra Server
	 */
	static final int DEFAULT_PORT = 13100;

	/**
	 * RMI registry binding name prefix for all versions of the remote GhidraServerHandle object.
	 */
	static final String BIND_NAME_PREFIX = "GhidraServer";

	/**
	 * RMI registry binding name for the supported version of the remote GhidraServerHandle object.
	 */
	static final String BIND_NAME = BIND_NAME_PREFIX + MIN_GHIDRA_VERSION;

	/**
	 * Returns user authentication proxy object.
	 * @throws RemoteException
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
	 * @throws LoginException if user authentication fails
	 * @throws RemoteException
	 * @see #getAuthenticationCallbacks()
	 */
	RemoteRepositoryServerHandle getRepositoryServer(Subject user, Callback[] authCallbacks)
			throws LoginException, RemoteException;

	/**
	 * Check server interface compatibility
	 * @param serverInterfaceVersion client/server interface version
	 * @throws RemoteException
	 * @see #INTERFACE_VERSION
	 */
	void checkCompatibility(int serverInterfaceVersion) throws RemoteException;

}
