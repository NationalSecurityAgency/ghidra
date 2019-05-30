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

import docking.DockingWindowManager;
import docking.widgets.*;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.remote.AnonymousCallback;
import ghidra.framework.remote.SSHSignatureCallback;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

public class DefaultClientAuthenticator extends PopupKeyStorePasswordProvider
		implements ClientAuthenticator {

	private Authenticator authenticator = new Authenticator() {
		@Override
		protected PasswordAuthentication getPasswordAuthentication() {
			Msg.debug(this, "PasswordAuthentication requested for " + getRequestingURL());
			NameCallback nameCb = null;
			if (!"NO_NAME".equals(getRequestingScheme())) {
				nameCb = new NameCallback("Name: ", ClientUtil.getUserName());
			}
			String prompt = getRequestingPrompt();
			if (prompt == null) {
				prompt = "Password:";
			}
			PasswordCallback passCb = new PasswordCallback(prompt, false);
			ServerPasswordPrompt pp = new ServerPasswordPrompt("Connection Authentication",
				"Server", getRequestingHost(), nameCb, passCb, null, null, null);
			SystemUtilities.runSwingNow(pp);
			if (pp.okWasPressed()) {
				return new PasswordAuthentication(nameCb != null ? nameCb.getName() : null,
					passCb.getPassword());
			}
			return null;
		}
	};

	@Override
	public Authenticator getAuthenticator() {
		return authenticator;
	}

	@Override
	public boolean isSSHKeyAvailable() {
		return false; // GUI does not currently support SSH authentication
	}

	@Override
	public boolean processSSHSignatureCallbacks(String serverName, NameCallback nameCb,
			SSHSignatureCallback sshCb) {
		return false;
	}

	@Override
	public boolean processPasswordCallbacks(String title, String serverType, String serverName,
			NameCallback nameCb, PasswordCallback passCb, ChoiceCallback choiceCb,
			AnonymousCallback anonymousCb, String loginError) {
		ServerPasswordPrompt pp = new ServerPasswordPrompt(title, serverType, serverName, nameCb,
			passCb, choiceCb, anonymousCb, loginError);
		SystemUtilities.runSwingNow(pp);
		return pp.okWasPressed();
	}

	@Override
	public boolean promptForReconnect(final Component parent, final String message) {

		return OptionDialog.showYesNoDialog(parent, "Lost Connection to Server",
			message) == OptionDialog.OPTION_ONE;
	}

	@Override
	public char[] getNewPassword(final Component parent, String serverInfo, String username) {
		final PasswordChangeDialog dlg =
			new PasswordChangeDialog("Change Password", "Repository Server", serverInfo, username);
		Runnable r = () -> DockingWindowManager.showDialog(parent, dlg);
		try {
			SystemUtilities.runSwingNow(r);
			return dlg.getPassword();
		}
		finally {
			dlg.dispose();
		}
	}

	private class ServerPasswordPrompt implements Runnable {

		private static final String NAME_PREFERENCE = "PasswordPrompt.Name";
		private static final String CHOICE_PREFERENCE = "PasswordPrompt.Choice";

		private String title;
		private String serverType; // label for serverName field 
		private String serverName;
		private NameCallback nameCb;
		private PasswordCallback passCb;
		private ChoiceCallback choiceCb;
		private AnonymousCallback anonymousCb;
		private String errorMsg;
		private boolean okPressed = false;

		ServerPasswordPrompt(String title, String serverType, String serverName,
				NameCallback nameCb, PasswordCallback passCb, ChoiceCallback choiceCb,
				AnonymousCallback anonymousCb, String errorMsg) {
			this.title = title;
			this.serverType = serverType;
			this.serverName = serverName;
			this.nameCb = nameCb;
			this.passCb = passCb;
			this.choiceCb = choiceCb;
			this.anonymousCb = anonymousCb;
			this.errorMsg = errorMsg;
		}

		private String getDefaultUserName() {
			if (nameCb == null) {
				return ClientUtil.getUserName();
			}
			return Preferences.getProperty(NAME_PREFERENCE, ClientUtil.getUserName(), true);
		}

		private int getDefaultChoice() {
			try {
				String choiceStr = Preferences.getProperty(CHOICE_PREFERENCE);
				if (choiceStr != null) {
					return Integer.parseInt(choiceStr);
				}
			}
			catch (NumberFormatException e) {
				// handled below
			}
			return 0;
		}

		@Override
		public void run() {
			PasswordDialog pwdDialog;
			String choicePrompt = null;
			String[] choices = null;
			if (choiceCb != null) {
				choicePrompt = choiceCb.getPrompt();
				choices = choiceCb.getChoices();
			}
			pwdDialog = new PasswordDialog(title, serverType, serverName, passCb.getPrompt(),
				nameCb != null ? nameCb.getPrompt() : null, getDefaultUserName(), choicePrompt,
				choices, getDefaultChoice(), anonymousCb != null);
			if (errorMsg != null) {
				pwdDialog.setErrorText(errorMsg);
			}
			DockingWindowManager winMgr = DockingWindowManager.getActiveInstance();
			Component rootFrame = winMgr != null ? winMgr.getRootFrame() : null;
			DockingWindowManager.showDialog(rootFrame, pwdDialog);
			if (pwdDialog.okWasPressed()) {
				if (anonymousCb != null && pwdDialog.anonymousAccessRequested()) {
					anonymousCb.setAnonymousAccessRequested(true);
				}
				else {
					passCb.setPassword(pwdDialog.getPassword());
					if (nameCb != null) {
						String username = pwdDialog.getUserID();
						nameCb.setName(username);
						Preferences.setProperty(NAME_PREFERENCE, username);
					}
					if (choiceCb != null) {
						int choice = pwdDialog.getChoice();
						choiceCb.setSelectedIndex(choice);
						Preferences.setProperty(CHOICE_PREFERENCE, Integer.toString(choice));
					}
				}
				okPressed = true;
			}
			pwdDialog.dispose();
		}

		boolean okWasPressed() {
			return okPressed;
		}
	}

}
