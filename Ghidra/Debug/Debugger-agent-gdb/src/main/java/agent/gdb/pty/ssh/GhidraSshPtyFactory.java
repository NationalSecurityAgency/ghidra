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

import java.io.IOException;
import java.util.Objects;

import javax.swing.JOptionPane;

import org.apache.commons.text.StringEscapeUtils;

import com.jcraft.jsch.*;
import com.jcraft.jsch.ConfigRepository.Config;

import agent.gdb.pty.PtyFactory;
import docking.DockingWindowManager;
import docking.widgets.PasswordDialog;
import ghidra.util.*;

public class GhidraSshPtyFactory implements PtyFactory {
	private static final String TITLE = "GDB via SSH";
	private static final int WRAP_LEN = 80;

	public static final String DEFAULT_HOSTNAME = "localhost";
	public static final int DEFAULT_PORT = 22;
	public static final String DEFAULT_USERNAME = "user";
	public static final String DEFAULT_CONFIG_FILE = "~/.ssh/config";

	private class RequireTTYAlwaysConfig implements Config {
		private final Config delegate;

		public RequireTTYAlwaysConfig(Config delegate) {
			this.delegate = delegate;

		}

		@Override
		public String getHostname() {
			return delegate.getHostname();
		}

		@Override
		public String getUser() {
			return delegate.getUser();
		}

		@Override
		public int getPort() {
			return delegate.getPort();
		}

		@Override
		public String getValue(String key) {
			if ("RequestTTY".equals(key)) {
				return "yes";
			}
			return delegate.getValue(key);
		}

		@Override
		public String[] getValues(String key) {
			if ("RequestTTY".equals(key)) {
				return new String[] { "yes" };
			}
			return delegate.getValues(key);
		}
	}

	private class RequireTTYAlwaysConfigRepo implements ConfigRepository {
		private final ConfigRepository delegate;

		public RequireTTYAlwaysConfigRepo(ConfigRepository delegate) {
			this.delegate = delegate;
		}

		@Override
		public Config getConfig(String host) {
			if (delegate == null) {
				return new RequireTTYAlwaysConfig(ConfigRepository.defaultConfig);
			}
			return new RequireTTYAlwaysConfig(delegate.getConfig(host));
		}
	}

	private class GhidraUserInfo implements UserInfo {
		private String password;
		private String passphrase;

		public String doPromptSecret(String prompt) {
			PasswordDialog dialog =
				new PasswordDialog(TITLE, "SSH", hostname, prompt, null, null);
			DockingWindowManager.showDialog(dialog);
			if (dialog.okWasPressed()) {
				return new String(dialog.getPassword());
			}
			return null;
		}

		public String html(String message) {
			// TODO: I shouldn't have to do this. Why won't swing wrap?
			String wrapped = StringUtilities.wrapToWidth(message, WRAP_LEN);
			return "<html><pre>" + StringEscapeUtils.escapeHtml4(wrapped).replace("\n", "<br>");
		}

		@Override
		public String getPassphrase() {
			return passphrase;
		}

		@Override
		public String getPassword() {
			return password;
		}

		@Override
		public boolean promptPassword(String message) {
			password = doPromptSecret(message);
			return password != null;
		}

		@Override
		public boolean promptPassphrase(String message) {
			passphrase = doPromptSecret(message);
			return passphrase != null;
		}

		@Override
		public boolean promptYesNo(String message) {
			return JOptionPane.showConfirmDialog(null, html(message), TITLE,
				JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION;
		}

		@Override
		public void showMessage(String message) {
			JOptionPane.showMessageDialog(null, html(message), TITLE,
				JOptionPane.INFORMATION_MESSAGE);
		}
	}

	private String hostname = DEFAULT_HOSTNAME;
	private int port = DEFAULT_PORT;
	private String username = DEFAULT_USERNAME;
	private String configFile = DEFAULT_CONFIG_FILE;

	private Session session;

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

	public String getConfigFile() {
		return configFile;
	}

	public void setConfigFile(String configFile) {
		this.configFile = configFile;
	}

	protected Session connectAndAuthenticate() throws IOException {
		JSch jsch = new JSch();
		ConfigRepository configRepo = null;
		try {
			configRepo = OpenSSHConfig.parseFile(configFile);
		}
		catch (IOException e) {
			Msg.warn(this, "ssh config file " + configFile + " could not be parsed.");
			// I guess the config file doesn't exist. Just go on
		}
		jsch.setConfigRepository(new RequireTTYAlwaysConfigRepo(configRepo));

		try {
			Session session =
				jsch.getSession(username.length() == 0 ? null : username, hostname, port);
			session.setUserInfo(new GhidraUserInfo());
			session.connect();
			return session;
		}
		catch (JSchException e) {
			Msg.error(this, "SSH connection error");
			throw new IOException("SSH connection error", e);
		}
	}

	@Override
	public SshPty openpty() throws IOException {
		if (session == null) {
			session = connectAndAuthenticate();
		}
		try {
			return new SshPty((ChannelExec) session.openChannel("exec"));
		}
		catch (JSchException e) {
			throw new IOException("SSH connection error", e);
		}
	}

	@Override
	public String getDescription() {
		return "ssh:" + hostname + "(user=" + username + ",port=" + port + ")";
	}
}
