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
package ghidra.feature.vt.gui.wizard;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.options.editor.ButtonPanelFactory;
import docking.widgets.label.GDLabel;
import docking.wizard.*;
import ghidra.app.util.task.OpenProgramTask;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskLauncher;
import resources.ResourceManager;

public class NewSessionPanel extends AbstractMageJPanel<VTWizardStateKey> {

	private static final int MAX_LENGTH_FOR_VT_SESSION_NAME = 20;
	private static final Icon SWAP_ICON = ResourceManager.loadImage("images/doubleArrowUpDown.png");
	private static final Icon INFO_ICON = ResourceManager.loadImage("images/information.png");

	private DomainFile sourceProgramFile;
	private DomainFile destinationProgramFile;
	private JTextField placeholderForSourceProgram;
	private JTextField placeholderForDestinationProgram;
	private JButton sourceProgramBrowseButton;
	private JButton destinationProgramBrowseButton;
	private JButton swapProgramsButton;
	private JTextField sessionNameField;
	private JTextField folderNameField;
	private DomainFolder folder;
	private final PluginTool tool;
	private Program sourceProgram;
	private Program destinationProgram;

	NewSessionPanel(PluginTool tool) {

		this.tool = tool;
		setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

		JLabel folderLabel = new GDLabel("Project folder ");
		folderLabel.setHorizontalAlignment(SwingConstants.RIGHT);
		folderLabel.setToolTipText("The folder to store the new Version Tracking Session");
		folderNameField = new JTextField();
		folderNameField.setFont(new Font("Monospaced", Font.PLAIN, 12));
		folderNameField.setEditable(false); // force user to browse to choose

		JButton browseFolderButton =
			ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseFolderButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				browseDataTreeFolders();
			}
		});
		Font font = browseFolderButton.getFont();
		browseFolderButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));

		JLabel newSessionLabel = new GDLabel("New Session Name: ");
		newSessionLabel.setToolTipText("The name for the new Version Tracking Session");
		newSessionLabel.setHorizontalAlignment(SwingConstants.RIGHT);

		sessionNameField = new JTextField(25);
		sessionNameField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				// do nothing
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				notifyListenersOfValidityChanged();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				notifyListenersOfValidityChanged();
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

		placeholderForSourceProgram = new JTextField(25);
		placeholderForSourceProgram.setEditable(false);

		placeholderForDestinationProgram = new JTextField(25);
		placeholderForDestinationProgram.setEditable(false);

		sourceProgramBrowseButton = createSourceBrowseButton();
		destinationProgramBrowseButton = createDestinationBrowseButton();

		swapProgramsButton = new JButton(SWAP_ICON);
		swapProgramsButton.setText("swap");
		swapProgramsButton.setName("SWAP_BUTTON");
		swapProgramsButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent arg0) {
				swapPrograms();
			}
		});

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
		mainPanel.add(placeholderForSourceProgram, gbc);

		gbc.gridx += 2;
		mainPanel.add(sourceProgramBrowseButton, gbc);

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
		mainPanel.add(placeholderForDestinationProgram, gbc);

		gbc.gridx += 2;
		mainPanel.add(destinationProgramBrowseButton, gbc);

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

	private void initializePrograms(WizardState<VTWizardStateKey> state) {
		DomainFile source = (DomainFile) state.get(VTWizardStateKey.SOURCE_PROGRAM_FILE);
		DomainFile destintation = (DomainFile) state.get(VTWizardStateKey.DESTINATION_PROGRAM_FILE);

		if (source != null) {
			setSourceProgram(source);
		}
		if (destintation != null) {
			setDestinationProgram(destintation);
		}
	}

	/**
	 * Presents the user with a tree of the existing project folders and allows
	 * them to pick one
	 */
	private void browseDataTreeFolders() {
		final DataTreeDialog dataTreeDialog =
			new DataTreeDialog(this, "Choose a project folder", DataTreeDialog.CHOOSE_FOLDER);

		dataTreeDialog.addOkActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				dataTreeDialog.close();
				setFolder(dataTreeDialog.getDomainFolder());
			}
		});
		dataTreeDialog.showComponent();
	}

	/**
	 * Sets the destination domain folder
	 */
	void setFolder(DomainFolder folder) {
		this.folder = folder;

		if (folder != null) {
			folderNameField.setText(folder.toString());
		}
		else {
			folderNameField.setText("< Choose a folder >");
		}

		notifyListenersOfValidityChanged();
	}

	private void setSourceProgram(DomainFile programFile) {
		notifyListenersOfStatusMessage(" ");
		sourceProgramFile = programFile;
		String path = programFile == null ? "" : programFile.getPathname();
		placeholderForSourceProgram.setText(path);

		updateSessionNameIfBlank();
		notifyListenersOfValidityChanged();
	}

	private void updateSessionNameIfBlank() {
		if (sessionNameField.getText().trim().length() != 0) {
			return;
		}
		if (sourceProgramFile == null || destinationProgramFile == null) {
			return;
		}
		String sourceName = sourceProgramFile.getName();
		String destinationName = destinationProgramFile.getName();
		if (sourceName.length() > MAX_LENGTH_FOR_VT_SESSION_NAME) {
			sourceName = sourceName.substring(0, MAX_LENGTH_FOR_VT_SESSION_NAME);
		}
		if (destinationName.length() > MAX_LENGTH_FOR_VT_SESSION_NAME) {
			destinationName = destinationName.substring(0, MAX_LENGTH_FOR_VT_SESSION_NAME);
		}
		String defaultSessionName = "VT__" + sourceName + "__" + destinationName;

		sessionNameField.setText(defaultSessionName);
	}

	private void setDestinationProgram(DomainFile programFile) {
		notifyListenersOfStatusMessage(" ");
		destinationProgramFile = programFile;
		String path = programFile == null ? "" : programFile.getPathname();
		placeholderForDestinationProgram.setText(path);
		updateSessionNameIfBlank();
		notifyListenersOfValidityChanged();
	}

	private void swapPrograms() {
		notifyListenersOfStatusMessage(" ");
		DomainFile tmpFile = destinationProgramFile;
		Program tmpProgram = destinationProgram;

		destinationProgramFile = sourceProgramFile;
		destinationProgram = sourceProgram;

		sourceProgramFile = tmpFile;
		sourceProgram = tmpProgram;

		if (sourceProgramFile != null) {
			placeholderForSourceProgram.setText(sourceProgramFile.getPathname());
		}
		else {
			placeholderForSourceProgram.setText("");
		}
		if (destinationProgramFile != null) {
			placeholderForDestinationProgram.setText(destinationProgramFile.getPathname());
		}
		else {
			placeholderForDestinationProgram.setText("");
		}
		notifyListenersOfValidityChanged();
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", "New_Session_Panel");
	}

	private void releaseConsumers() {
		if (sourceProgram != null) {
			sourceProgram.release(tool);
			sourceProgram = null;
		}
		if (destinationProgram != null) {
			destinationProgram.release(tool);
			destinationProgram = null;
		}
	}

	@Override
	public void enterPanel(WizardState<VTWizardStateKey> state) {
		initializePrograms(state);
	}

	@Override
	public WizardPanelDisplayability getPanelDisplayabilityAndUpdateState(
			WizardState<VTWizardStateKey> state) {
		return WizardPanelDisplayability.MUST_BE_DISPLAYED;
	}

	@Override
	public void leavePanel(WizardState<VTWizardStateKey> state) {
		updateStateObjectWithPanelInfo(state);
	}

	@Override
	public void updateStateObjectWithPanelInfo(WizardState<VTWizardStateKey> state) {
		state.put(VTWizardStateKey.SOURCE_PROGRAM_FILE, sourceProgramFile);
		state.put(VTWizardStateKey.DESTINATION_PROGRAM_FILE, destinationProgramFile);
		state.put(VTWizardStateKey.SESSION_NAME, sessionNameField.getText());
		state.put(VTWizardStateKey.NEW_SESSION_FOLDER, folder);
		state.put(VTWizardStateKey.SOURCE_PROGRAM, sourceProgram);
		state.put(VTWizardStateKey.DESTINATION_PROGRAM, destinationProgram);
	}

	private Program updateProgram(DomainFile file, Program currentProgram) {
		if (currentProgram != null) {
			if (currentProgram.getDomainFile().equals(file)) {
				return currentProgram;
			}
			currentProgram.release(tool);
		}
		if (file == null) {
			return null;
		}
		OpenProgramTask openProgramTask = new OpenProgramTask(file, tool);
		new TaskLauncher(openProgramTask, tool.getActiveWindow());
		return openProgramTask.getOpenProgram();
	}

	@Override
	public String getTitle() {
		return "New Version Tracking Session";
	}

	@Override
	public void initialize() {
		sourceProgramFile = null;
		destinationProgramFile = null;
		sessionNameField.setText("");
		placeholderForSourceProgram.setText("");
		placeholderForDestinationProgram.setText("");
		setFolder(tool.getProject().getProjectData().getRootFolder());
	}

	@Override
	public boolean isValidInformation() {
		if (folder == null) {
			notifyListenersOfStatusMessage("Choose a project folder to continue!");
			return false;
		}
		if (sourceProgramFile == null || destinationProgramFile == null) {
			return false;
		}
		if (sourceProgramFile.equals(destinationProgramFile)) {
			notifyListenersOfStatusMessage("Source and Destination Programs must be different");
			releaseConsumers();
			return false;
		}

		String name = sessionNameField.getText().trim();
		if ("".equals(name)) {
			notifyListenersOfStatusMessage("Please enter a name for this session");
			return false;
		}
		try {
			tool.getProject().getProjectData().testValidName(name, false);
		}
		catch (InvalidNameException e) {
			notifyListenersOfStatusMessage("'" + name + "' contains invalid characters");
			return false;
		}
		DomainFile file = folder.getFile(name);
		if (file != null) {
			notifyListenersOfStatusMessage(
				"'" + file.getPathname() + "' is the name of an existing domain file");
			return false;
		}

		sourceProgram = updateProgram(sourceProgramFile, sourceProgram);

		if (sourceProgram == null) {
			notifyListenersOfStatusMessage(
				"Can't open source program " + sourceProgramFile.getName());
			return false;
		}

		destinationProgram = updateProgram(destinationProgramFile, destinationProgram);

		if (destinationProgram == null) {
			notifyListenersOfStatusMessage(
				"Can't open destination program " + destinationProgramFile.getName());
			return false;
		}

		notifyListenersOfStatusMessage(" ");
		return true;
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		// none; weird!
	}

	private JButton createSourceBrowseButton() {
		JButton button = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		button.setName("SOURCE_BUTTON");
		button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				DomainFile programFile = VTWizardUtils.chooseDomainFile(NewSessionPanel.this,
					"a source program", VTWizardUtils.PROGRAM_FILTER, null);
				if (programFile != null) {
					setSourceProgram(programFile);
				}
			}
		});
		return button;
	}

	private JButton createDestinationBrowseButton() {
		JButton button = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		button.setName("DESTINATION_BUTTON");
		button.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				DomainFile programFile = VTWizardUtils.chooseDomainFile(NewSessionPanel.this,
					"a destination program", VTWizardUtils.PROGRAM_FILTER, null);
				if (programFile != null) {
					setDestinationProgram(programFile);
				}
			}
		});
		return button;
	}

	@Override
	public void dispose() {
		releaseConsumers();
	}
}
