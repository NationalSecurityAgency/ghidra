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
package agent.gdb.pty.ssh;

import java.io.File;
import java.io.IOException;
import java.util.Objects;

import agent.gdb.pty.PtyFactory;
import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.KnownHosts;
import docking.DockingWindowManager;
import docking.widgets.PasswordDialog;
import ghidra.util.exception.CancelledException;

public class GhidraSshPtyFactory implements PtyFactory {
	private String hostname = "localhost";
	private int port = 22;
	private String username = "user";
	private String keyFile = "~/.ssh/id_rsa";

	private Connection sshConn;

	public String getHostname() {
		return hostname;
	}

	public void setHostname(String hostname) {
		this.hostname = Objects.requireNonNull(hostname);
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = Objects.requireNonNull(username);
	}

	public String getKeyFile() {
		return keyFile;
	}

	/**
	 * Set the keyfile path, or empty for password authentication only
	 * 
	 * @param keyFile the path
	 */
	public void setKeyFile(String keyFile) {
		this.keyFile = Objects.requireNonNull(keyFile);
	}

	public static char[] promptPassword(String hostname, String prompt) throws CancelledException {
		PasswordDialog dialog =
			new PasswordDialog("GDB via SSH", "SSH", hostname, prompt, null,
				"");
		DockingWindowManager.showDialog(dialog);
		if (dialog.okWasPressed()) {
			return dialog.getPassword();
		}
		throw new CancelledException();
	}

	protected Connection connectAndAuthenticate() throws IOException {
		boolean success = false;
		File knownHostsFile = new File(System.getProperty("user.home") + "/.ssh/known_hosts");
		KnownHosts knownHosts = new KnownHosts();
		if (knownHostsFile.exists()) {
			knownHosts.addHostkeys(knownHostsFile);
		}

		Connection sshConn = new Connection(hostname, port);
		try {
			sshConn.connect(new GhidraSshHostKeyVerifier(knownHosts));
			if ("".equals(keyFile.trim())) {
				// TODO: Find an API that uses char[] so I can clear it!
				String password = new String(promptPassword(hostname, "Password for " + username));
				if (!sshConn.authenticateWithPassword(username, password)) {
					throw new IOException("Authentication failed");
				}
			}
			else {
				File pemFile = new File(keyFile);
				if (!pemFile.canRead()) {
					throw new IOException("Key file " + keyFile +
						" cannot be read. Does it exist? Do you have permission?");
				}
				String password = new String(promptPassword(hostname, "Password for " + pemFile));
				if (!sshConn.authenticateWithPublicKey(username, pemFile, password)) {
					throw new IOException("Authentication failed");
				}
			}
			success = true;
			return sshConn;
		}
		catch (CancelledException e) {
			throw new IOException("User cancelled", e);
		}
		finally {
			if (!success) {
				sshConn.close();
			}
		}
	}

	@Override
	public SshPty openpty() throws IOException {
		if (sshConn == null || !sshConn.isAuthenticationComplete()) {
			sshConn = connectAndAuthenticate();
		}
		return new SshPty(sshConn.openSession());
	}

	@Override
	public String getDescription() {
		return "ssh:" + hostname + "(user=" + username + ",port=" + port + ")";
	}
}
