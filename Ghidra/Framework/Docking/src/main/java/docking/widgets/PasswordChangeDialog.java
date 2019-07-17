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
package docking.widgets;

import java.awt.Toolkit;
import java.awt.event.*;
import java.util.Arrays;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.util.MessageType;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class PasswordChangeDialog extends DialogComponentProvider {

	JPasswordField passwordField1;
	JPasswordField passwordField2;
	char[] newPassword = null;

	public PasswordChangeDialog(String title, String serverType, String serverName, String userID) {
		super(title, true);
		createWorkPanel(serverType, serverName, userID);
	}

	private void createWorkPanel(String serverType, String serverName, String userID) {

		JPanel wp = new JPanel(new PairLayout(5, 5));
		wp.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 10));

		if (serverName != null) {
			wp.add(new GLabel(serverType + ":"));
			wp.add(new GLabel(serverName));
		}

		if (userID != null) {
			wp.add(new GLabel("User ID:"));
			JLabel nameLabel = new GLabel(userID);
			nameLabel.setName("NAME-COMPONENT");
			wp.add(nameLabel);
		}

		wp.add(new GLabel("New Password:"));
		passwordField1 = new JPasswordField(16);
		passwordField1.setName("PASSWORD-ENTRY1-COMPONENT");
		wp.add(passwordField1);

		wp.add(new GLabel("Repeat Password:"));
		passwordField2 = new JPasswordField(16);
		passwordField2.setName("PASSWORD-ENTRY2-COMPONENT");
		passwordField2.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				okCallback();
			}
		});
		wp.add(passwordField2);

		wp.add(new GLabel());

		KeyListener keyListener = new KeyListener() {

			@Override
			public void keyTyped(KeyEvent e) {
				// we care about ups and downs
			}

			private void displayWarning() {
				try {
					boolean capsLockOn =
						Toolkit.getDefaultToolkit().getLockingKeyState(KeyEvent.VK_CAPS_LOCK);
					if (capsLockOn) {
						setStatusText("Warning! Caps-Lock is on", MessageType.WARNING);
					}
					else {
						clearStatusText();
					}
				}
				catch (UnsupportedOperationException e) {
					// unable to detect caps-lock
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				displayWarning();
			}

			@Override
			public void keyPressed(KeyEvent e) {
				displayWarning();
			}
		};
		passwordField1.addKeyListener(keyListener);
		passwordField2.addKeyListener(keyListener);

		addWorkPanel(wp);
		addOKButton();
		addCancelButton();
	}

	public char[] getPassword() {
		return newPassword != null ? (char[]) newPassword.clone() : null;
	}

	/*
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {
		newPassword = passwordField1.getPassword();
		boolean success = false;
		try {
			if (newPassword.length < 6) {
				Msg.showError(this, getComponent(), "Password Error",
					"Password must be a minimum of 6 characters!");
				return;
			}
			if (!Arrays.equals(newPassword, passwordField2.getPassword())) {
				Msg.showError(this, getComponent(), "Password Error", "Passwords do not match!");
				return;
			}
			success = true;
		}
		finally {
			if (!success) {
				Arrays.fill(newPassword, ' ');
				newPassword = null;
			}
		}
		close();
	}

	public void dispose() {
		close();
		if (newPassword != null) {
			Arrays.fill(newPassword, ' ');
			newPassword = null;
		}
		if (passwordField1 != null) {
			getComponent().remove(passwordField1);
			passwordField1.setText("");
			passwordField1 = null;
			passwordField2.setText("");
			getComponent().remove(passwordField2);
			passwordField2 = null;
		}
	}

}
