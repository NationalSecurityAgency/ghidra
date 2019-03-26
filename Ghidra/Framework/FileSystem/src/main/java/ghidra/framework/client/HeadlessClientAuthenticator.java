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
import java.io.*;
import java.net.Authenticator;
import java.net.PasswordAuthentication;

import javax.security.auth.callback.*;

import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.framework.remote.security.SSHKeyManager;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.Msg;

/**
 * <code>HeadlessClientAuthenticator</code> provides the ability to install a Ghidra Server 
 * authenticator needed when operating in a headless mode.
 */
public class HeadlessClientAuthenticator implements ClientAuthenticator {

	private final static char[] BADPASSWORD = "".toCharArray();

	private static Object sshPrivateKey;
	private static String userID = ClientUtil.getUserName(); // default username
	private static boolean passwordPromptAlowed;

	private Authenticator authenticator = new Authenticator() {
		@Override
		protected PasswordAuthentication getPasswordAuthentication() {
			Msg.debug(this, "PasswordAuthentication requested for " + getRequestingURL());
			String prompt = getRequestingPrompt();
			if (prompt == null) {
				String host = getRequestingHost();
				prompt = (host != null ? (host + " ") : "") + "(" + userID + ") Password:";
			}
			return new PasswordAuthentication(userID, getPassword(null, prompt));
		}
	};

	HeadlessClientAuthenticator() {
	}

	@Override
	public Authenticator getAuthenticator() {
		return authenticator;
	}

	/**
	 * Install headless client authenticator for Ghidra Server
	 * @param username optional username to be used with a Ghidra Server which
	 * allows username to be specified
	 * @param keystorePath optional PKI or SSH keystore path.  May also be specified
	 * as resource path for SSH key.
	 * @param allowPasswordPrompt if true the user may be prompted for passwords
	 * via the console (stdin).  Please note that the Java console will echo 
	 * the password entry to the terminal which may be undesirable.
	 * @throws IOException if error occurs while opening specified keystorePath 
	 */
	public static void installHeadlessClientAuthenticator(String username, String keystorePath,
			boolean allowPasswordPrompt) throws IOException {
		passwordPromptAlowed = allowPasswordPrompt;
		if (username != null) {
			userID = username;
		}

		// clear existing key store settings
		sshPrivateKey = null;

		HeadlessClientAuthenticator authenticator = new HeadlessClientAuthenticator();
		ClientUtil.setClientAuthenticator(authenticator);

		if (keystorePath != null) {
			File f = new File(keystorePath);
			if (!f.exists()) {
				// If keystorePath file not found - try accessing as SSH key resource stream
				// InputStream keyIn = ResourceManager.getResourceAsStream(keystorePath);
				InputStream keyIn = keystorePath.getClass().getResourceAsStream(keystorePath);
				if (keyIn != null) {
					try {
						sshPrivateKey = SSHKeyManager.getSSHPrivateKey(keyIn);
						Msg.info(HeadlessClientAuthenticator.class,
							"Loaded SSH key: " + keystorePath);
						return;
					}
					catch (Exception e) {
						Msg.error(HeadlessClientAuthenticator.class,
							"Failed to open keystore for SSH use: " + keystorePath, e);
						throw new IOException("Failed to parse keystore: " + keystorePath);
					}
					finally {
						try {
							keyIn.close();
						}
						catch (IOException e) {
							// ignore
						}
					}
				}
				Msg.error(HeadlessClientAuthenticator.class, "Keystore not found: " + keystorePath);
				throw new FileNotFoundException("Keystore not found: " + keystorePath);
			}

			try {
				sshPrivateKey = SSHKeyManager.getSSHPrivateKey(new File(keystorePath));
				Msg.info(HeadlessClientAuthenticator.class, "Loaded SSH key: " + keystorePath);
			}
			catch (IOException e) {
				try {
					// try keystore as PKI keystore if failed as SSH keystore
					ApplicationKeyManagerFactory.setKeyStore(keystorePath, false);
					Msg.info(HeadlessClientAuthenticator.class, "Loaded PKI key: " + keystorePath);
				}
				catch (IOException e1) {
					Msg.error(HeadlessClientAuthenticator.class,
						"Failed to open keystore for PKI use: " + keystorePath, e1);
					Msg.error(HeadlessClientAuthenticator.class,
						"Failed to open keystore for SSH use: " + keystorePath, e);
					throw new IOException("Failed to parse keystore: " + keystorePath);
				}
			}
		}
		else {
			sshPrivateKey = null;
		}
	}

	private char[] getPassword(String usage, String prompt) {

		if (!passwordPromptAlowed) {
			Msg.warn(this, "Headless client not configured to supply required password");
			return BADPASSWORD;
		}

		char[] password = null;
		int c;
		try {

			String passwordPrompt = "";
			if (usage != null) {
				passwordPrompt += usage;
				passwordPrompt += "\n";
			}

			if (prompt == null) {
				prompt = "Password:";
			}

			// With the new GhidraClassLoader/GhidraLauncher it should be possible to get a Console 
			// object, which allow masking of passwords.
			Console cons = System.console();

			if (cons != null) {
				passwordPrompt += prompt + " ";
				password = cons.readPassword(passwordPrompt);
			}
			else {
				// Couldn't get console instance, passwords will be in the clear
				passwordPrompt += "*** WARNING! Password entry will NOT be masked ***\n" + prompt;

				System.out.print(passwordPrompt);

				while (true) {
					c = System.in.read();
					if (c <= 0 || (Character.isWhitespace((char) c) && c != ' ')) {
						break;
					}
					if (password == null) {
						password = new char[1];
					}
					else {
						char[] newPass = new char[password.length + 1];
						for (int i = 0; i < password.length; i++) {
							newPass[i] = password[i];
							password[i] = 0;
						}
						password = newPass;
					}
					password[password.length - 1] = (char) c;
				}
			}
		}
		catch (IOException e) {
			Msg.error(this, "Error reading standard-input for password", e);
		}
		return password;
	}

	@Override
	public char[] getNewPassword(Component parent, String serverInfo, String username) {
		throw new UnsupportedOperationException("Server password change not permitted");
	}

	@Override
	public boolean processPasswordCallbacks(String title, String serverType, String serverName,
			NameCallback nameCb, PasswordCallback passCb, ChoiceCallback choiceCb,
			AnonymousCallback anonymousCb, String loginError) {
		if (anonymousCb != null && !passwordPromptAlowed) {
			// Assume that login error will not occur with anonymous login
			anonymousCb.setAnonymousAccessRequested(true);
			return true;
		}
		if (choiceCb != null) {
			choiceCb.setSelectedIndex(1);
		}
		if (nameCb != null && userID != null) {
			nameCb.setName(userID);
		}
		String usage = null;
		if (serverName != null) {
			usage = serverType + ": " + serverName;
		}
		char[] password = getPassword(usage, passCb.getPrompt());
		passCb.setPassword(password);
		return password != null;
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
			if (passwordPromptAlowed) {
				Msg.error(this, "Incorrect keystore password specified: " + keystorePath);
			}
			else {
				Msg.error(this,
					"Keystore password required but password entry has been disabled: " +
						keystorePath);
			}
			return null;
		}
		return getPassword("Certificate keystore: " + keystorePath, "Keystore password: ");
	}

	@Override
	public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
			SSHSignatureCallback sshCb) {
		if (sshPrivateKey == null) {
			return false;
		}
		if (nameCb != null) {
			nameCb.setName(userID);
		}
		try {
			sshCb.sign(sshPrivateKey);
			return true;
		}
		catch (IOException e) {
			Msg.error(this, "Failed to authenticate with SSH private key", e);
		}
		return false;
	}

	@Override
	public boolean isSSHKeyAvailable() {
		return sshPrivateKey != null;
	}

}
