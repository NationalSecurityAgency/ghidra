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

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GLabel;
import ghidra.util.MessageType;
import ghidra.util.layout.PairLayout;

/**
 * <code>PasswordDialog</code> is a modal dialog which 
 * prompts a user for a password. 
 */
public class PasswordDialog extends DialogComponentProvider {

	private JPanel workPanel;
	private JTextField nameField;
	private JPasswordField passwordField;
	private JComboBox<String> choiceCB;
	private JCheckBox anonymousAccess;
	private boolean okPressed = false;
	private String defaultUserId;

	/**
	 * Construct a new PasswordDialog which may include user ID specification/prompt, if either
	 * {@code allowUserIdEntry} is true or a non-null {@code defaultUserId} has been specified, and 
	 * other optional elements.  The dialog includes a message text area which supports the use 
	 * of {@link #setErrorText(String)}.
	 * 
	 * @param title title of the dialog
	 * @param serverType 'Server' or 'Key-store' designation
	 * @param serverName name of server or keystore pathname
	 * @param passPrompt password prompt to show in the dialog; may be null/empty, in which case
	 * "Password:" is displayed next to the password field
	 * @param allowUserIdEntry if true user ID entry will be supported
	 * @param userIdPrompt User ID / Name prompt to show in the dialog, if null "User ID:" is prompt
	 * if either {@code allowUserIdEntry} is true or a non-null {@code defaultUserId} has been specified.
	 * @param defaultUserId default name when prompting for a name
	 * @param choicePrompt namePrompt name prompt to show in the dialog, if null a name will not be prompted for.
	 * @param choices array of choices to present if choicePrompt is not null
	 * @param defaultChoice default choice index
	 * @param includeAnonymousOption true signals to add a checkbox to request anonymous login
	 */
	public PasswordDialog(String title, String serverType, String serverName, String passPrompt,
			boolean allowUserIdEntry, String userIdPrompt, String defaultUserId,
			String choicePrompt, String[] choices, int defaultChoice,
			boolean includeAnonymousOption) {
		this(title, serverType, serverName, passPrompt, allowUserIdEntry, userIdPrompt,
			defaultUserId, true);
		if (choicePrompt != null) {
			workPanel.add(new GLabel(choicePrompt));
			choiceCB = new GComboBox<>(choices);
			choiceCB.setName("CHOICES-COMPONENT");
			choiceCB.setSelectedIndex(defaultChoice);
			workPanel.add(choiceCB);
		}
		if (includeAnonymousOption) {
			anonymousAccess = new GCheckBox("Request Anonymous Access");
			anonymousAccess.setName("ANONYMOUS-COMPONENT");
			anonymousAccess.addChangeListener(e -> {
				boolean anonymousAccessRequested = anonymousAccess.isSelected();
				boolean enableOtherFields = !anonymousAccessRequested;
				if (anonymousAccessRequested) {
					passwordField.setText("");
				}
				passwordField.setEnabled(enableOtherFields);
				if (nameField != null) {
					nameField.setEnabled(enableOtherFields);
				}
				if (choiceCB != null) {
					choiceCB.setEnabled(enableOtherFields);
				}
			});
			workPanel.add(new GLabel(""));
			workPanel.add(anonymousAccess);
		}
	}

	/**
	 * Construct a new PasswordDialog which only prompts for a password for a specified server
	 * type and name.  The dialog will not include a User ID display, although server fields 
	 * may be used for a similar display purpose.  The dialog includes a message text area
	 * which supports the use of {@link #setErrorText(String)}.
	 * 
	 * @param title title of the dialog
	 * @param serverType 'Server' or 'Key-store' designation
	 * @param serverName name of server or keystore pathname
	 * @param passPrompt password prompt to show in the dialog; may be null, in which case
	 * "Password:" is prompt.
	 */
	public PasswordDialog(String title, String serverType, String serverName, String passPrompt) {
		this(title, serverType, serverName, passPrompt, true);
	}

	/**
	 * Construct a new PasswordDialog which only prompts for a password for a specified server
	 * type and name.  The dialog will not include a User ID display, although server fields 
	 * may be used for a similar display purpose.  The dialog optionally includes a message 
	 * text area which supports the use of {@link #setErrorText(String)}.
	 * 
	 * @param title title of the dialog
	 * @param serverType 'Server' or 'Key-store' designation
	 * @param serverName name of server or keystore pathname
	 * @param passPrompt password prompt to show in the dialog; may be null, in which case
	 * "Password:" is displayed next to the password field
	 * @param hasMessages true if a message text area should be included allowing for use of
	 * {@link #setErrorText(String)}
	 */
	public PasswordDialog(String title, String serverType, String serverName, String passPrompt,
			boolean hasMessages) {
		this(title, serverType, serverName, passPrompt, false, null, null, hasMessages);
	}

	/**
	 * Construct a new PasswordDialog which may include user ID specification/prompt if either
	 * {@code allowUserIdEntry} is true or a non-null {@code defaultUserId} has been specified.
	 * The dialog optionally includes a message text area area which supports the use of 
	 * {@link #setErrorText(String)}.
	 * 
	 * @param title title of the dialog
	 * @param serverType 'Server' or 'Key-store' designation
	 * @param serverName name of server or keystore pathname
	 * @param passPrompt password prompt to show in the dialog; may be null/empty, in which case
	 * "Password:" is displayed next to the password field
	 * @param allowUserIdEntry if true user ID entry will be supported
	 * @param userIdPrompt User ID / Name prompt to show in the dialog, if null "User ID:" is prompt
	 * if either {@code allowUserIdEntry} is true or a non-null {@code defaultUserId} has been specified.
	 * @param defaultUserId default name when prompting for a name
	 * @param hasMessages true if a message text area should be included allowing for use of
	 * {@link #setErrorText(String)}
	 */
	public PasswordDialog(String title, String serverType, String serverName, String passPrompt,
			boolean allowUserIdEntry, String userIdPrompt, String defaultUserId,
			boolean hasMessages) {
		super(title, true);

		this.defaultUserId = defaultUserId;

		setRememberSize(false);
		setTransient(true);

		if (hasMessages) {
			setMinimumSize(350, 150);
		}

		workPanel = new JPanel(new PairLayout(5, 5));
		workPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 0, 10));

		if (serverName != null) {
			workPanel.add(new GLabel(serverType + ":"));
			workPanel.add(new GLabel(serverName));
		}

		if (StringUtils.isBlank(userIdPrompt)) {
			userIdPrompt = "User ID:";
		}
		if (StringUtils.isBlank(passPrompt)) {
			passPrompt = "Password:";
		}

		if (allowUserIdEntry) {
			workPanel.add(new GLabel(userIdPrompt));
			nameField = new JTextField(defaultUserId, 16);
			nameField.setName("NAME-ENTRY-COMPONENT");
			workPanel.add(nameField);
		}
		else if (defaultUserId != null) {
			workPanel.add(new GLabel(userIdPrompt));
			JLabel nameLabel = new GLabel(defaultUserId);
			nameLabel.setName("NAME-COMPONENT");
			workPanel.add(nameLabel);
		}

		workPanel.add(new GLabel(passPrompt));
		passwordField = new JPasswordField(16);
		passwordField.setName("PASSWORD-ENTRY-COMPONENT");
		workPanel.add(passwordField);

		passwordField.addKeyListener(new KeyListener() {

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
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					displayWarning();
				}
			}

			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() != KeyEvent.VK_ENTER) {
					displayWarning();
				}
			}
		});

		addWorkPanel(workPanel);
		addOKButton();
		addCancelButton();

		setStatusJustification(SwingConstants.CENTER);

		setFocusComponent(passwordField);

		passwordField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				if (e.getModifiersEx() == 0 && e.getKeyChar() == KeyEvent.VK_ENTER) {
					okCallback();
				}
			}
		});

//		Point centerPoint = WindowUtilities.centerOnScreen( getPreferredSize() );
//		setInitialLocation( centerPoint.x, centerPoint.y );
	}

	/**
	 * Display error status
	 * @param text the text
	 */
	public void setErrorText(String text) {
		super.setStatusText(text, MessageType.ERROR);
	}

	/**
	 * Return the password entered in the password field.
	 * @return the password chars
	 */
	public char[] getPassword() {
		return passwordField.getPassword();
	}

	/**
	 * Returns true if anonymous access is requested
	 * @return true if anonymous access requested
	 */
	public boolean anonymousAccessRequested() {
		if (anonymousAccess != null) {
			return anonymousAccess.isSelected();
		}
		return false;
	}

	/**
	 * Return the user ID / Name entered in the password field
	 * @return the user ID / Name entered in the password field
	 */
	public String getUserID() {
		return nameField != null ? nameField.getText().trim() : defaultUserId;
	}

	/**
	 * Returns index of selected choice or -1 if no choice has been made
	 * @return index of selected choice or -1 if no choice has been made
	 */
	public int getChoice() {
		if (choiceCB != null) {
			return choiceCB.getSelectedIndex();
		}
		return -1;
	}

	/**
	 * Returns true if the OK button was pressed.
	 * @return true if the OK button was pressed.
	 */
	public boolean okWasPressed() {
		return okPressed;
	}

	@Override
	protected void okCallback() {
		okPressed = true;
		close();
	}

	@Override
	public void close() {
		// overridden to not call dispose, since this class does special cleanup on close
		closeDialog();
	}

	@Override
	public void dispose() {
		passwordField.setText("");
		rootPanel.remove(passwordField);
	}

}
