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
package pdb;

import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.dialogs.ObjectChooserDialog;
import docking.widgets.label.GDLabel;
import generic.jar.ResourceFile;
import generic.util.WindowUtilities;
import ghidra.framework.Application;
import ghidra.framework.preferences.Preferences;
import ghidra.util.MessageType;

public class AskPdbUrlDialog extends DialogComponentProvider {

	private boolean isCanceled;
	private JLabel label;
	private JTextField textField;
	private KeyListener keyListener;
	private List<URLChoice> choices = null;

	protected AskPdbUrlDialog(String dialogTitle, String message) {
		this(null, dialogTitle, message, null);
	}

	public AskPdbUrlDialog(String dialogTitle, String message, Object defaultValue) {
		this(null, dialogTitle, message, defaultValue);
	}

	public AskPdbUrlDialog(Component parent, String title, String message) {
		this(parent, title, message, null);
	}

	public AskPdbUrlDialog(final Component parent, String title, String message,
			Object defaultValue) {
		super(title, true, true, true, false);

		// create the key listener all the text fields will use
		keyListener = new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				int keyCode = e.getKeyCode();
				if (keyCode == KeyEvent.VK_ENTER) {
					okCallback();
				}
			}
		};

		JPanel panel = new JPanel(new BorderLayout(10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		label = new GDLabel(message);
		panel.add(label, BorderLayout.WEST);

		textField = new JTextField(40);
		textField.setName("JTextField");//for JUnits...
		textField.addKeyListener(keyListener);
		textField.setText(defaultValue == null ? "" : defaultValue.toString());
		textField.selectAll();
		panel.add(textField, BorderLayout.CENTER);

		if (urlFileAvailable()) {
			JButton urlButton = new JButton("Choose from known URLs");
			urlButton.addActionListener(e -> urlCallback());

			panel.add(urlButton, BorderLayout.EAST);
		}

		addWorkPanel(panel);

		addOKButton();
		addCancelButton();

		setDefaultButton(okButton);
		setRememberSize(false);

		DockingWindowManager.showDialog(parent, AskPdbUrlDialog.this);
	}

	@Override
	protected void addOKButton() {
		okButton = new JButton("Download from URL");
		okButton.setMnemonic('K');
		okButton.setName("OK");
		okButton.addActionListener(e -> okCallback());
		addButton(okButton);
	}

	private boolean urlFileAvailable() {
		List<ResourceFile> urlFiles = Application.findFilesByExtensionInApplication(".pdburl");

		if (urlFiles.size() == 0) {
			return false;
		}

		try {
			InputStream urlFileContents = null;
			String currentLine;
			choices = new ArrayList<>();

			for (ResourceFile urlFile : urlFiles) {
				urlFileContents = urlFile.getInputStream();

				Scanner scanner = new Scanner(urlFileContents);
				try {
					while (scanner.hasNextLine()) {

						currentLine = scanner.nextLine();

						// Find first comma, split on that
						int commaIndex = currentLine.indexOf(',');

						if (commaIndex > -1) {
							choices.add(new URLChoice(currentLine.substring(0, commaIndex).trim(),
								currentLine.substring(commaIndex + 1).trim()));
						}
					}
				}
				finally {
					scanner.close();
				}
			}
		}
		catch (IOException ioe) {
			return false;
		}
		return true;
	}

	private void saveCurrentDimensions() {
		Rectangle bounds = getBounds();
		Window window = WindowUtilities.windowForComponent(getComponent());

		if (window != null) {
			Point location = window.getLocation();
			bounds.x = location.x;
			bounds.y = location.y;
		}

		StringBuffer buffer = new StringBuffer();
		buffer.append(bounds.x).append(":");
		buffer.append(bounds.y).append(":");
		buffer.append(bounds.width).append(":");
		buffer.append(bounds.height).append(":");
		Preferences.setProperty("Ask Dialog Bounds", buffer.toString());
	}

	public Object getValue() {
		return textField.getText();
	}

	@Override
	protected void okCallback() {
		isCanceled = false;
		if (textField.getText().length() == 0) {
			setStatusText("Please enter a valid URL.");
			return;
		}
		saveCurrentDimensions();
		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		saveCurrentDimensions();
		close();
	}

	private void urlCallback() {

		ObjectChooserDialog<URLChoice> urlDialog = new ObjectChooserDialog<>("Choose a URL",
			URLChoice.class, choices, "getNetwork", "getUrl");

		DockingWindowManager activeInstance = DockingWindowManager.getActiveInstance();
		activeInstance.showDialog(urlDialog);

		URLChoice pickedUrl = urlDialog.getSelectedObject();

		if (pickedUrl != null) {
			textField.setText(pickedUrl.getUrl());

			if (pickedUrl.getNetwork().equalsIgnoreCase("internet")) {
				setStatusText(
					"WARNING: Check your organization's security policy before downloading files from the internet.",
					MessageType.ERROR);
			}
			else {
				setStatusText(null);
			}
		}
	}

	public boolean isCanceled() {
		return isCanceled;
	}

	public String getValueAsString() {
		Object val = getValue();
		if ("".equals(val)) {
			return null;
		}
		return val != null ? val.toString() : null;
	}

}
