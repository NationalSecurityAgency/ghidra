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
package ghidra.feature.vt.gui.wizard.session;

import static ghidra.framework.main.DataTreeDialogType.*;

import java.awt.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.button.BrowseButton;
import docking.widgets.label.GDLabel;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Ids.Fonts;
import generic.theme.Gui;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.util.StringUtilities;
import utility.function.Callback;

public class SessionConfigurationPanel extends JPanel {
	// The maximum length to allow for each program's name portion of the session name.
	// In the filesystem API, when saved, the session name is restricted to 60 characters.
	// The default VTSession name combines the two program names so split the length between them, 
	// minus text we add below.
	private static final int VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH = 28;
	private static final int TEXT_FIELD_LENGTH = 40;
	private static final Icon SWAP_ICON = new GIcon("icon.version.tracking.new.session.swap");
	private static final Icon INFO_ICON = new GIcon("icon.version.tracking.new.session.info");
	private JTextField sourceField;
	private JTextField destinationField;
	private JButton sourceBrowseButton;
	private JButton destinationBrowseButton;
	private JButton swapProgramsButton;
	private JTextField sessionNameField;
	private JTextField folderNameField;

	private DomainFile sourceFile;
	private DomainFile destinationFile;
	private DomainFolder sessionFolder;
	private Callback statusChangedCallback;

	SessionConfigurationPanel(Callback statusChangedCallback) {
		this.statusChangedCallback = statusChangedCallback;
		setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

		JLabel folderLabel = new GDLabel("Project folder ");
		folderLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		folderLabel.setToolTipText("The folder to store the new Version Tracking Session");
		folderNameField = new JTextField();
		Gui.registerFont(folderNameField, Fonts.MONOSPACED);
		folderNameField.setEditable(false); // force user to browse to choose

		JButton browseFolderButton = new BrowseButton();
		browseFolderButton.addActionListener(e -> browseDataTreeFolders());

		JLabel newSessionLabel = new GDLabel("New Session Name: ");
		newSessionLabel.setToolTipText("The name for the new Version Tracking Session");
		newSessionLabel.setHorizontalAlignment(SwingConstants.RIGHT);

		sessionNameField = new JTextField(TEXT_FIELD_LENGTH);
		sessionNameField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}
		});

		JLabel sourceLabel = new GDLabel("Source Program: ");
		sourceLabel.setIcon(INFO_ICON);
		sourceLabel.setToolTipText("Analyzed program with markup to transfer");
		sourceLabel.setHorizontalAlignment(SwingConstants.RIGHT);

		JLabel destinationLabel = new GDLabel("Destination Program: ");
		destinationLabel.setIcon(INFO_ICON);
		destinationLabel.setToolTipText("New program that receives the transferred markup");
		destinationLabel.setHorizontalAlignment(SwingConstants.RIGHT);

		sourceField = new JTextField(TEXT_FIELD_LENGTH);
		sourceField.setEditable(false);

		destinationField = new JTextField(TEXT_FIELD_LENGTH);
		destinationField.setEditable(false);

		sourceBrowseButton = createSourceBrowseButton();
		destinationBrowseButton = createDestinationBrowseButton();

		swapProgramsButton = new JButton(SWAP_ICON);
		swapProgramsButton.setText("swap");
		swapProgramsButton.setName("SWAP_BUTTON");
		swapProgramsButton.addActionListener(arg0 -> swapPrograms());

		JPanel mainPanel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();

		gbc.gridx = 0;
		gbc.gridy = 0;
		mainPanel.add(Box.createVerticalStrut(15), gbc);

		gbc.gridy++;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		mainPanel.add(folderLabel, gbc);

		gbc.gridx++;
		mainPanel.add(folderNameField, gbc);

		gbc.gridx++;
		mainPanel.add(Box.createHorizontalStrut(5), gbc);

		gbc.gridx++;
		mainPanel.add(browseFolderButton, gbc);

		gbc.gridx = 0;
		gbc.gridy++;
		mainPanel.add(Box.createVerticalStrut(10), gbc);

		gbc.gridy++;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		mainPanel.add(newSessionLabel, gbc);

		gbc.gridx++;
		mainPanel.add(sessionNameField, gbc);

		gbc.gridx = 0;
		gbc.gridy++;
		mainPanel.add(Box.createVerticalStrut(15), gbc);

		gbc.gridy++;
		gbc.gridwidth = 4;
		mainPanel.add(new JSeparator(), gbc);

		gbc.gridy++;
		gbc.gridwidth = 1;
		mainPanel.add(Box.createVerticalStrut(25), gbc);

		gbc.gridy++;
		mainPanel.add(sourceLabel, gbc);

		gbc.gridx++;
		mainPanel.add(sourceField, gbc);

		gbc.gridx += 2;
		mainPanel.add(sourceBrowseButton, gbc);

		gbc.gridx = 0;
		gbc.gridy++;
		gbc.fill = GridBagConstraints.NONE;
		gbc.gridwidth = 4;
		mainPanel.add(swapProgramsButton, gbc);

		gbc.gridwidth = 1;
		gbc.gridy++;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		mainPanel.add(destinationLabel, gbc);

		gbc.gridx++;
		mainPanel.add(destinationField, gbc);

		gbc.gridx += 2;
		mainPanel.add(destinationBrowseButton, gbc);

		gbc.gridx = 0;
		gbc.gridy++;
		mainPanel.add(Box.createVerticalStrut(25), gbc);

		gbc.gridy++;
		gbc.gridwidth = 4;
		mainPanel.add(new JSeparator(), gbc);

		gbc.gridy++;
		gbc.gridwidth = 1;
		mainPanel.add(Box.createVerticalStrut(60), gbc);

		setLayout(new BorderLayout());
		add(mainPanel, BorderLayout.NORTH);

	}

	public void setDestinationFile(DomainFile file) {
		destinationFile = file;
		if (destinationFile != null) {
			destinationField.setText(destinationFile.getPathname());
		}
		else {
			destinationField.setText("");
		}
		updateSessionNameIfBlank();
	}

	public void setSourceFile(DomainFile file) {
		sourceFile = file;
		if (sourceFile != null) {
			sourceField.setText(sourceFile.getPathname());
		}
		else {
			sourceField.setText("");
		}
		updateSessionNameIfBlank();
	}

	private JButton createSourceBrowseButton() {
		JButton button = new BrowseButton();
		button.setName("SOURCE_BUTTON");
		button.addActionListener(e -> {
			DomainFile programFile = VTWizardUtils.chooseProgramFile(SessionConfigurationPanel.this,
				"a source program", null);
			if (programFile != null) {
				setSourceFile(programFile);
				statusChangedCallback.call();
			}
		});
		return button;
	}

	private JButton createDestinationBrowseButton() {
		JButton button = new BrowseButton();
		button.setName("DESTINATION_BUTTON");
		button.addActionListener(e -> {
			DomainFile programFile = VTWizardUtils.chooseProgramFile(SessionConfigurationPanel.this,
				"a destination program", null);
			if (programFile != null) {
				setDestinationFile(programFile);
				statusChangedCallback.call();
			}
		});
		return button;
	}

	/**
	 * Presents the user with a tree of the existing project folders and allows
	 * them to pick one
	 */
	private void browseDataTreeFolders() {
		final DataTreeDialog dataTreeDialog =
			new DataTreeDialog(this, "Choose a project folder", CHOOSE_FOLDER);

		dataTreeDialog.addOkActionListener(e -> {
			dataTreeDialog.close();
			sessionFolder = dataTreeDialog.getDomainFolder();
			folderNameField.setText(sessionFolder.toString());
			statusChangedCallback.call();
		});
		dataTreeDialog.showComponent();
	}

	private void swapPrograms() {
		DomainFile newSourceFile = destinationFile;
		DomainFile newDestionationFile = sourceFile;
		setSourceFile(newSourceFile);
		setDestinationFile(newDestionationFile);
		statusChangedCallback.call();
	}

	public DomainFolder getSessionFolder() {
		return sessionFolder;
	}

	public String getSessionName() {
		return sessionNameField.getText().trim();
	}

	public DomainFile getSourceFile() {
		return sourceFile;
	}

	public DomainFile getDestinationFile() {
		return destinationFile;
	}

	private void updateSessionNameIfBlank() {
		if (!StringUtils.isBlank(sessionNameField.getText())) {
			return;
		}
		if (sourceFile == null || destinationFile == null || sourceFile == destinationFile) {
			return;
		}

		String defaultSessionName =
			createVTSessionName(sourceFile.getName(), destinationFile.getName());
		sessionNameField.setText(defaultSessionName);
	}

	private String createVTSessionName(String sourceName, String destinationName) {

		// if together they are within the bounds just return session name with both full names
		if (sourceName.length() + destinationName.length() <= 2 *
			VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH) {
			return "VT_" + sourceName + "_" + destinationName;
		}

		// give destination name all space not used by source name 
		if (sourceName.length() < VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH) {
			int leftover = VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH - sourceName.length();
			destinationName = StringUtilities.trimMiddle(destinationName,
				VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH + leftover);
			return "VT_" + sourceName + "_" + destinationName;
		}

		// give source name all space not used by destination name 
		if (destinationName.length() < VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH) {
			int leftover = VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH - destinationName.length();
			sourceName = StringUtilities.trimMiddle(sourceName,
				VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH + leftover);
			return "VT_" + sourceName + "_" + destinationName;
		}

		// if both too long, shorten both of them
		sourceName = StringUtilities.trimMiddle(sourceName, VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH);
		destinationName =
			StringUtilities.trimMiddle(destinationName, VTSESSION_NAME_PROGRAM_NAME_MAX_LENGTH);

		return "VT_" + sourceName + "_" + destinationName;
	}

	public void setSessionFolder(DomainFolder folder) {
		sessionFolder = folder;
		folderNameField.setText(sessionFolder.toString());
	}

}
