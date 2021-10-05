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

import java.awt.Toolkit;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.label.GLabel;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;
import ghidra.util.layout.PairLayout;

/**
 * Simple dialog with single input field to prompt user for password.
 * <p>
 * User can cancel, or cancel-all, which can be determined by inspecting
 * the value of the semi-visible member variables.
 * <p>
 * Treat this as an internal detail of PopupGUIPasswordProvider.
 */
class PasswordDialog extends DialogComponentProvider {
	enum RESULT_STATE {
		OK, CANCELED
	}

	private JPanel workPanel;
	JPasswordField passwordField;
	RESULT_STATE resultState;
	boolean cancelledAll;

	PasswordDialog(String title, String prompt) {
		super(title, true, true, true, false);
		setRememberSize(false);
		setStatusJustification(SwingConstants.CENTER);
		setMinimumSize(300, 100);

		passwordField = new JPasswordField(16);
		passwordField.addKeyListener(new KeyListener() {
			@Override
			public void keyTyped(KeyEvent e) {
				if (e.getModifiersEx() == 0 && e.getKeyChar() == KeyEvent.VK_ENTER) {
					e.consume();
					okCallback();
				}
			}

			@Override
			public void keyReleased(KeyEvent e) {
				updateCapLockWarning();
			}

			@Override
			public void keyPressed(KeyEvent e) {
				updateCapLockWarning();
			}
		});
		
		workPanel = new JPanel(new PairLayout(5, 5));
		workPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 10));

		workPanel.add(new GLabel(prompt != null ? prompt : "Password:"));
		workPanel.add(passwordField);
		
		addWorkPanel(workPanel);
		addOKButton();
		addCancelButton();
		JButton cancelAllButton = new JButton("Cancel All");
		cancelAllButton.addActionListener(e -> {
			cancelledAll = true;
			cancelButton.doClick();
		});
		addButton(cancelAllButton);
		updateCapLockWarning();

		setFocusComponent(passwordField);

		setHelpLocation(
			new HelpLocation("FileSystemBrowserPlugin", "PasswordDialog"));
	}

	private void updateCapLockWarning() {
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
	protected void okCallback() {
		resultState = RESULT_STATE.OK;
		close();
	}

	@Override
	protected void cancelCallback() {
		resultState = RESULT_STATE.CANCELED;
		super.cancelCallback();
	}

	@Override
	public void dispose() {
		if (passwordField != null) {
			passwordField.setText("");
			workPanel.remove(passwordField);
			passwordField = null;
		}
	}

}
