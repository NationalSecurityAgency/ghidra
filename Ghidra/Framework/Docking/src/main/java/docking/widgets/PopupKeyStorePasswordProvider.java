/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets;

import ghidra.security.KeyStorePasswordProvider;
import ghidra.util.SystemUtilities;

import java.awt.Component;
import java.util.Arrays;

import docking.DockingWindowManager;

public class PopupKeyStorePasswordProvider implements KeyStorePasswordProvider {

	@Override
	public char[] getKeyStorePassword(String keystorePath, boolean passwordError) {
		KeystorePasswordPrompt pp = new KeystorePasswordPrompt(keystorePath, passwordError);
		try {
			SystemUtilities.runSwingNow(pp);
			return pp.getPassword();
		}
		finally {
			pp.clearPassword();
		}
	}

	/**
	 * Swing runnable for prompting user for a keystore password.
	 */
	private static class KeystorePasswordPrompt implements Runnable {

		private String file;
		private boolean passwordError;
		private char[] password;

		/**
		 * Constructor.
		 * @param file keystore file
		 * @param passwordError true if previous password attempt was incorrect
		 */
		KeystorePasswordPrompt(String file, boolean passwordError) {
			this.file = file;
			this.passwordError = passwordError;
		}

		/*
		 * @see java.lang.Runnable#run()
		 */
		@Override
		public void run() {
			PasswordDialog pwdDialog =
				new PasswordDialog("Protected PKI Certificate", "Cert File", file, null, null, null);
			if (passwordError) {
				pwdDialog.setErrorText("Incorrect password");
			}
			DockingWindowManager winMgr = DockingWindowManager.getActiveInstance();
			Component rootFrame = winMgr != null ? winMgr.getRootFrame() : null;
			DockingWindowManager.showDialog(rootFrame, pwdDialog);
			if (pwdDialog.okWasPressed()) {
				password = pwdDialog.getPassword();
			}
			pwdDialog.dispose();
		}

		/**
		 * Returns password entered by user or null if dialog was cancelled.
		 */
		char[] getPassword() {
			return (password == null ? null : (char[]) password.clone());
		}

		/**
		 * Clear password field.
		 */
		void clearPassword() {
			if (password != null) {
				Arrays.fill(password, ' ');
			}
		}
	}

}
