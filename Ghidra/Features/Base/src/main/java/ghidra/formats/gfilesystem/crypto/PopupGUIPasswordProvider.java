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
package ghidra.formats.gfilesystem.crypto;

import java.util.Iterator;

import java.awt.Component;

import docking.DockingWindowManager;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.crypto.PasswordDialog.RESULT_STATE;

/**
 * Pops up up a GUI dialog prompting the user to enter a password for the specified file.
 * <p>
 * The dialog is presented to the user when the iterator's hasNext() is called.
 * <p>
 * Repeated requests to the same iterator will adjust the dialog's title with a "try count" to
 * help the user understand the previous password was unsuccessful.
 * <p>
 * Iterator's hasNext() will return false if the user has previously canceled the dialog,  
 */
public class PopupGUIPasswordProvider implements PasswordProvider {

	@Override
	public Iterator<PasswordValue> getPasswordsFor(FSRL fsrl, String prompt, Session session) {
		return new PasswordIterator(session, fsrl, prompt);
	}

	static class SessionState {
		boolean cancelAll;
	}

	class PasswordIterator implements Iterator<PasswordValue> {
		private SessionState sessionState;
		private FSRL fsrl;
		private boolean cancelled;
		private PasswordValue password;
		private String prompt;
		private int tryCount;

		PasswordIterator(Session session, FSRL fsrl, String prompt) {
			this.sessionState =
				session.getStateValue(PopupGUIPasswordProvider.this, SessionState::new);
			this.fsrl = fsrl;
			this.prompt = prompt;
		}

		private void showDlg() {
			String dlgPrompt = (prompt != null && !prompt.isBlank()) ? prompt : fsrl.getName();
			if (!dlgPrompt.endsWith(":")) {
				dlgPrompt += ":";
			}
			tryCount++;
			String dlgTitle =
				"Enter Password" + (tryCount > 1 ? " (Try " + tryCount + ")" : "");
			PasswordDialog pwdDialog = new PasswordDialog(dlgTitle, dlgPrompt);
			DockingWindowManager winMgr = DockingWindowManager.getActiveInstance();
			Component rootFrame = winMgr != null ? winMgr.getRootFrame() : null;
			DockingWindowManager.showDialog(rootFrame, pwdDialog);

			cancelled = pwdDialog.resultState == RESULT_STATE.CANCELED;
			password = cancelled ? null : PasswordValue.wrap(pwdDialog.passwordField.getPassword());
			sessionState.cancelAll |= cancelled && pwdDialog.cancelledAll;
			pwdDialog.dispose();
		}

		@Override
		public boolean hasNext() {
			if (cancelled || sessionState.cancelAll) {
				return false;
			}
			if (password == null) {
				showDlg();
			}
			return !cancelled;
		}

		@Override
		public PasswordValue next() {
			PasswordValue result = password;
			password = null;
			return result;
		}

	}

}
