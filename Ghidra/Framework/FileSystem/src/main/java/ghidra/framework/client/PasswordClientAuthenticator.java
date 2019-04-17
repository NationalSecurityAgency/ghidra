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
import java.net.PasswordAuthentication;

import javax.security.auth.callback.*;

import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.net.ApplicationKeyManagerFactory;

/**
 * <code>PasswordClientAuthenticator</code> provides a fixed username/password 
 * authentication response when connecting to any Ghidra Server or accessing
 * a protected PKI keystore.  The use of this authenticator is intended for
 * headless applications in which the user is unable to respond to such
 * prompts.  SSH authentication is not currently supported.  Anonymous user
 * access is not supported.
 * <p>
 * If a PKI certificate has been installed, a password may be required 
 * to access the certificate keystore independent of any other password which may be required
 * for accessing SSH keys or server password authentication.  In such headless situations,
 * the PKI certificate path/password should be specified via a property since it is unlikely
 * that the same password will apply.
 * @see ApplicationKeyManagerFactory 
 */
public class PasswordClientAuthenticator implements ClientAuthenticator {

	private char[] password;
	private String username;

	private Authenticator authenticator = new Authenticator() {
		@Override
		protected PasswordAuthentication getPasswordAuthentication() {
			return new PasswordAuthentication(username, password);
		}
	};

	@Override
	public Authenticator getAuthenticator() {
		return authenticator;
	}

	@Override
	public boolean isSSHKeyAvailable() {
		return false; // does not currently support SSH authentication
	}

	@Override
	public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
			SSHSignatureCallback sshCb) {
		return false;
	}

	public PasswordClientAuthenticator(String password) {
		this(null, password);
	}

	public PasswordClientAuthenticator(String username, String password) {
		this.password = password.toCharArray();
		this.username = username;
	}

	@Override
	public char[] getNewPassword(Component parent, String serverInfo, String user) {
		return null;
	}

	@Override
	public boolean processPasswordCallbacks(String title, String serverType,
			String serverName, NameCallback nameCb, PasswordCallback passCb,
			ChoiceCallback choiceCb, AnonymousCallback anonymousCb, String loginError) {
		if (choiceCb != null) {
			choiceCb.setSelectedIndex(1);
		}
		if (nameCb != null && username != null) {
			nameCb.setName(username);
		}
		passCb.setPassword(password.clone());
		return true;
	}

	@Override
	public boolean promptForReconnect(Component parent, String message) {
		// assumes connection attempt was immediately done when this 
		// ClientAuthenticator was installed
		return false;
	}

	@Override
	public char[] getKeyStorePassword(String keystorePath, boolean passwordError) {
		if (passwordError) {
			return null;
		}
		return password.clone();
	}

}
