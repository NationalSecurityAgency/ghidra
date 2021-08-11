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
import java.util.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.lang3.StringUtils;

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

/**
 * Version tracking wizard panel to create a new session.
 */
public class NewSessionPanel extends AbstractMageJPanel<VTWizardStateKey> {

	private static final int MAX_LENGTH_FOR_VT_SESSION_NAME = 20;
	private static final Icon SWAP_ICON = ResourceManager.loadImage("images/doubleArrowUpDown.png");
	private static final Icon INFO_ICON = ResourceManager.loadImage("images/information.png");

	private JTextField sourceField;
	private JTextField destinationField;
	private JButton sourceBrowseButton;
	private JButton destinationBrowseButton;
	private JButton swapProgramsButton;
	private JTextField sessionNameField;
	private JTextField folderNameField;
	private DomainFolder folder;
	private PluginTool tool;

	// All program info objects that the user may have opened while using the wizard.  We keep 
	// these around to avoid reopening them and any accompanying upgrading that may be required.
	// These will be released when the wizard is finished.
	private Map<DomainFile, ProgramInfo> allProgramInfos = new HashMap<>();
	private ProgramInfo sourceProgramInfo;
	private ProgramInfo destinationProgramInfo;

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
		browseFolderButton.addActionListener(e -> browseDataTreeFolders());
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

		sourceField = new JTextField(25);
		sourceField.setEditable(false);

		destinationField = new JTextField(25);
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

		dataTreeDialog.addOkActionListener(e -> {
			dataTreeDialog.close();
			setFolder(dataTreeDialog.getDomainFolder());
		});
		dataTreeDialog.showComponent();
	}

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

		String path;
		if (programFile == null) {
			sourceProgramInfo = null;
			path = "";
		}
		else {
			sourceProgramInfo =
				allProgramInfos.computeIfAbsent(programFile, file -> new ProgramInfo(file));
			path = programFile.getPathname();
		}

		sourceField.setText(path);

		updateSessionNameIfBlank();
		notifyListenersOfValidityChanged();
	}

	private void updateSessionNameIfBlank() {
		if (!StringUtils.isBlank(sessionNameField.getText())) {
			return;
		}
		if (sourceProgramInfo == null || destinationProgramInfo == null) {
			return;
		}

		String sourceName = sourceProgramInfo.getName();
		String destinationName = destinationProgramInfo.getName();
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

		String path;
		if (programFile == null) {
			destinationProgramInfo = null;
			path = "";
		}
		else {
			destinationProgramInfo =
				allProgramInfos.computeIfAbsent(programFile, file -> new ProgramInfo(file));
			path = programFile.getPathname();
		}

		destinationField.setText(path);
		updateSessionNameIfBlank();
		notifyListenersOfValidityChanged();
	}

	private void swapPrograms() {
		notifyListenersOfStatusMessage(" ");

		ProgramInfo temp = destinationProgramInfo;
		destinationProgramInfo = sourceProgramInfo;
		sourceProgramInfo = temp;

		if (sourceProgramInfo != null) {
			sourceField.setText(sourceProgramInfo.getPathname());
		}
		else {
			sourceField.setText("");
		}

		if (destinationProgramInfo != null) {
			destinationField.setText(destinationProgramInfo.getPathname());
		}
		else {
			destinationField.setText("");
		}

		notifyListenersOfValidityChanged();
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("VersionTrackingPlugin", "New_Session_Panel");
	}

	private void releaseConsumers() {

		for (ProgramInfo info : allProgramInfos.values()) {
			info.release(tool);
		}

		allProgramInfos.clear();
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
		state.put(VTWizardStateKey.SOURCE_PROGRAM_FILE, sourceProgramInfo.getFile());
		state.put(VTWizardStateKey.DESTINATION_PROGRAM_FILE, destinationProgramInfo.getFile());
		state.put(VTWizardStateKey.SOURCE_PROGRAM, sourceProgramInfo.getProgram());
		state.put(VTWizardStateKey.DESTINATION_PROGRAM, destinationProgramInfo.getProgram());
		state.put(VTWizardStateKey.SESSION_NAME, sessionNameField.getText());
		state.put(VTWizardStateKey.NEW_SESSION_FOLDER, folder);
	}

	private void openProgram(ProgramInfo programInfo) {

		if (programInfo.hasProgram()) {
			return; // already open
		}

		OpenProgramTask openProgramTask = new OpenProgramTask(programInfo.getFile(), tool);
		new TaskLauncher(openProgramTask, tool.getActiveWindow());
		Program program = openProgramTask.getOpenProgram();
		programInfo.setProgram(program);
	}

	@Override
	public String getTitle() {
		return "New Version Tracking Session";
	}

	@Override
	public void initialize() {
		sourceProgramInfo = null;
		destinationProgramInfo = null;
		sessionNameField.setText("");
		sourceField.setText("");
		destinationField.setText("");
		setFolder(tool.getProject().getProjectData().getRootFolder());
	}

	@Override
	public boolean isValidInformation() {

		if (folder == null) {
			notifyListenersOfStatusMessage("Choose a project folder to continue!");
			return false;
		}

		if (sourceProgramInfo == null || destinationProgramInfo == null) {
			return false;
		}

		if (sourceProgramInfo.hasSameFile(destinationProgramInfo)) {
			notifyListenersOfStatusMessage("Source and Destination Programs must be different");
			releaseConsumers();
			return false;
		}

		String name = sessionNameField.getText().trim();
		if (StringUtils.isBlank(name)) {
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

		openProgram(sourceProgramInfo);
		if (!sourceProgramInfo.hasProgram()) {
			notifyListenersOfStatusMessage(
				"Can't open source program " + sourceProgramInfo.getName());
			return false;
		}

		openProgram(destinationProgramInfo);
		if (!destinationProgramInfo.hasProgram()) {
			notifyListenersOfStatusMessage(
				"Can't open destination program " + destinationProgramInfo.getName());
			return false;
		}

		notifyListenersOfStatusMessage(" ");
		return true;
	}

	@Override
	public void addDependencies(WizardState<VTWizardStateKey> state) {
		// none
	}

	private JButton createSourceBrowseButton() {
		JButton button = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		button.setName("SOURCE_BUTTON");
		button.addActionListener(e -> {
			DomainFile programFile = VTWizardUtils.chooseDomainFile(NewSessionPanel.this,
				"a source program", VTWizardUtils.PROGRAM_FILTER, null);
			if (programFile != null) {
				setSourceProgram(programFile);
			}
		});
		return button;
	}

	private JButton createDestinationBrowseButton() {
		JButton button = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		button.setName("DESTINATION_BUTTON");
		button.addActionListener(e -> {
			DomainFile programFile = VTWizardUtils.chooseDomainFile(NewSessionPanel.this,
				"a destination program", VTWizardUtils.PROGRAM_FILTER, null);
			if (programFile != null) {
				setDestinationProgram(programFile);
			}
		});
		return button;
	}

	@Override
	public void dispose() {
		releaseConsumers();
	}

	// simple object to track a domain file and its program
	private class ProgramInfo {

		private Program program;
		private DomainFile file;

		public ProgramInfo(DomainFile file) {
			this.file = Objects.requireNonNull(file);
		}

		void setProgram(Program program) {
			this.program = program;
		}

		Program getProgram() {
			return program;
		}

		DomainFile getFile() {
			return file;
		}

		String getPathname() {
			return file.getPathname();
		}

		String getName() {
			return file.getName();
		}

		void release(Object consumer) {
			if (program == null) {
				return;
			}

			if (program.getConsumerList().contains(consumer)) {
				program.release(consumer);
			}

			program = null;
		}

		boolean hasSameFile(ProgramInfo other) {
			return file.getPathname().equals(other.getPathname());
		}

		boolean hasProgram() {
			return program != null;
		}
	}
}
