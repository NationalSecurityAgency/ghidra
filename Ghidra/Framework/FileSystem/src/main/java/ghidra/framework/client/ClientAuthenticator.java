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
import java.net.Authenticator;

import javax.security.auth.callback.*;

import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.security.KeyStorePasswordProvider;

public interface ClientAuthenticator extends KeyStorePasswordProvider {

	/**
	 * Get a standard Java authenticator for HTTP and other standard network connections
	 * @return authenticator object
	 */
	public Authenticator getAuthenticator();

	/**
	 * Process Ghidra Server password authentication callbacks.
	 * @param title password prompt title if GUI is used
	 * @param serverType type of server (label associated with serverName)
	 * @param serverName name of server
	 * @param nameCb provides storage for user login name.  A null indicates
	 * that the default user name will be used, @see ClientUtil#getUserName()
	 * @param passCb provides storage for user password, @see PasswordCallback#setPassword(char[])
	 * @param choiceCb specifies choice between NT Domain authentication (index=0) and local password
	 * file authentication (index=1).  Set selected index to specify authenticator to be used, 
	 * @param anonymousCb may be used to request anonymous read-only access to 
	 * the server.  A null is specified if anonymous access has not been enabed on the server.
	 * @param loginError previous login error message or null for first attempt
	 * @see ChoiceCallback#setSelectedIndex(int)
	 * A null is specified if no choice is available (password authenticator determined by server configuration).
	 * @see AnonymousCallback#setAnonymousAccessRequested(boolean)
	 * @return
	 */
	public boolean processPasswordCallbacks(String title, String serverType, String serverName,
			NameCallback nameCb, PasswordCallback passCb, ChoiceCallback choiceCb,
			AnonymousCallback anonymousCb, String loginError);

	/**
	 * Prompt user for reconnect
	 * @param parent dialog parent component or null if not applicable
	 * @param message
	 * @return return true if reconnect should be attempted
	 */
	public boolean promptForReconnect(Component parent, final String message);

	/**
	 * Get new user password
	 * @param parent dialog parent component or null if not applicable
	 * @param serverInfo server host info
	 * @param username
	 * @return new password or null if password should not be changed, 
	 * if not null array will be cleared by caller
	 */
	public char[] getNewPassword(Component parent, String serverInfo, String username);

	/**
	 * @return true if SSH private key is available for authentication
	 */
	public boolean isSSHKeyAvailable();

	/**
	 * Process Ghidra Server SSH authentication callbacks.
	 * @param serverName name of server
	 * @param nameCb provides storage for user login name.  A null indicates
	 * that the default user name will be used, @see ClientUtil#getUserName().
	 * @param sshCb provides authentication token to be signed with private key, @see SSHAuthenticationCallback#sign(SSHPrivateKey)
	 * @return
	 */
	public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
			SSHSignatureCallback sshCb);

}
