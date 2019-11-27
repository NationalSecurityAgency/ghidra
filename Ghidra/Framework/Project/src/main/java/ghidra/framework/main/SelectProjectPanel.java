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
package ghidra.framework.main;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import docking.options.editor.ButtonPanelFactory;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GDLabel;
import docking.wizard.AbstractWizardJPanel;
import docking.wizard.WizardManager;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.NamingUtilities;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel that allows the project directory and name to be specified for a
 * new project. A checkbox indicates whether the project should be created
 * as a shared project.
 * 
 */
class SelectProjectPanel extends AbstractWizardJPanel {

	//remove the "." from the extension
	private static String PROJECT_EXTENSION = ProjectLocator.getProjectExtension().substring(1);

	private JTextField projectNameField;
	private JTextField directoryField;
	private JButton browseButton;
	private GhidraFileChooser fileChooser;
	private ProjectLocator projectLocator;
	private NewProjectPanelManager panelManager;
	private DocumentListener docListener;

	/**
	 * Construct a new panel.
	 * @param panelManager manager for the "new project" set of panels
	 */
	public SelectProjectPanel(NewProjectPanelManager panelManager) {
		super(new BorderLayout());
		this.panelManager = panelManager;
		buildMainPanel();
		setBorder(BorderFactory.createEmptyBorder(80, 80, 0, 80));
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getTitle()
	 */
	@Override
	public String getTitle() {
		if (panelManager.isSharedProject()) {
			return "Select Local Project Location for Repository " +
				panelManager.getProjectRepositoryName();
		}
		return "Select Project Location";
	}

	/* (non Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#initialize()
	 */
	@Override
	public void initialize() {
		projectLocator = null;
		Document doc = projectNameField.getDocument();
		doc.removeDocumentListener(docListener);
		projectNameField.setText("");
		doc.addDocumentListener(docListener);

	}

	/**
	 * Return true if the user has entered a valid project file
	 */
	@Override
	public boolean isValidInformation() {
		return projectLocator != null;
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.wizard.WizardPanel#getHelpLocation()
	 */
	@Override
	public HelpLocation getHelpLocation() {
		if (panelManager.isSharedProject()) {
			return new HelpLocation(GenericHelpTopics.FRONT_END, "SelectProjectLocation");
		}
		return new HelpLocation(GenericHelpTopics.FRONT_END, "CreateNonSharedProject");
	}

	ProjectLocator getProjectLocator() {
		return projectLocator;
	}

	void setProjectName(String projectName) {
		projectNameField.setText(projectName);
	}

	String getStatusMessage() {
		if (projectLocator == null) {
			return checkProjectFile(false);
		}
		return "";
	}

	private void buildMainPanel() {

		JPanel outerPanel = new JPanel();
		GridBagLayout gbl = new GridBagLayout();
		outerPanel.setLayout(gbl);

		JLabel dirLabel = new GDLabel("Project Directory:", SwingConstants.RIGHT);
		directoryField = new JTextField(25);
		directoryField.setName("Project Directory");

		String lastDirSelected = Preferences.getProperty(Preferences.LAST_NEW_PROJECT_DIRECTORY);
		if (lastDirSelected != null) {
			directoryField.setText(lastDirSelected);
		}
		else {
			File projectDirectory = new File(GenericRunInfo.getProjectsDirPath());
			directoryField.setText(projectDirectory.getAbsolutePath());
		}
		directoryField.setCaretPosition(directoryField.getText().length() - 1);
		JLabel projectNameLabel = new GDLabel("Project Name:", SwingConstants.RIGHT);
		projectNameField = new JTextField(25);
		projectNameField.setName("Project Name");
		projectNameField.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				setProjectFile();
			}
		});

		docListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				setProjectFile();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				setProjectFile();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				setProjectFile();
			}
		};
		projectNameField.getDocument().addDocumentListener(docListener);
		directoryField.getDocument().addDocumentListener(docListener);

		browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		browseButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				displayFileChooser();
			}
		});

//		sharedProjectCB = new GCheckBox("Project can be Shared with Others"); 
//		sharedProjectCB.addItemListener(new ItemListener() {
//			public void itemStateChanged(ItemEvent e) {
//				panelManager.getWizardManager().validityChanged();
//				checkProjectFile(false); // cause message to be displayed
//					// if project name is invalid
//			}
//		});

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.anchor = GridBagConstraints.EAST;
		gbl.setConstraints(dirLabel, gbc);
		outerPanel.add(dirLabel);

		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.insets.left = 5;
		gbc.insets.bottom = 5;
		gbc.weightx = 1.0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbl.setConstraints(directoryField, gbc);
		outerPanel.add(directoryField);

		gbc = new GridBagConstraints();
		gbc.gridx = 2;
		gbc.insets.left = 5;
		gbc.insets.bottom = 5;
		gbc.anchor = GridBagConstraints.EAST;
		gbl.setConstraints(browseButton, gbc);
		outerPanel.add(browseButton);

		gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.insets.left = 5;
		gbc.insets.bottom = 5;
		gbc.weightx = 1.0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbl.setConstraints(projectNameLabel, gbc);
		outerPanel.add(projectNameLabel);

		gbc = new GridBagConstraints();
		gbc.gridx = 1;
		gbc.gridy = 1;
		gbc.insets.left = 5;
		gbc.insets.bottom = 5;
		gbc.weightx = 1.0;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbl.setConstraints(projectNameField, gbc);
		outerPanel.add(projectNameField);

		JPanel p = new JPanel(new VerticalLayout(5));
		p.add(outerPanel);
		add(p, BorderLayout.CENTER);
	}

	private void setProjectFile() {
		checkProjectFile(true);
	}

	/**
	 * Check the validity of the project file name.
	 */
	private String checkProjectFile(boolean showMessage) {
		WizardManager wm = panelManager.getWizardManager();
		if (showMessage) {
			wm.setStatusMessage("");
		}
		projectLocator = null;
		ProjectLocator locator = null;
		String msg = null;
		String dir = directoryField.getText().trim();
		if (dir.length() == 0) {
			msg = "Please specify project directory";
		}
		else if (!new File(dir).isDirectory()) {
			msg = "Project directory does not exist.";
		}
		else {
			String projectName = projectNameField.getText().trim();
			if (projectName.endsWith(PROJECT_EXTENSION)) {
				projectName =
					projectName.substring(0, projectName.length() - PROJECT_EXTENSION.length());
			}
			if (!NamingUtilities.isValidProjectName(projectName)) {
				msg = "Please specify valid project name";
			}
			else {
				try {
					locator = new ProjectLocator(dir, projectName);
				}
				catch (IllegalArgumentException e) {
					msg = e.getMessage();
				}
			}
		}
		if (locator != null) {
			File parentDir = new File(dir);
			if (!parentDir.isDirectory()) {
				msg = "Please specify a Project Directory";
			}
			else if (locator.getMarkerFile().exists() || locator.getProjectDir().exists()) {
				msg = getProjectName("A project named " + locator.getName() +
					" already exists in " + parentDir.getAbsolutePath());
			}
			else {
				this.projectLocator = locator;
			}
		}
		wm.validityChanged();
		if (showMessage) {
			wm.setStatusMessage(msg);
		}
		return msg;
	}

	private void displayFileChooser() {
		if (fileChooser == null) {
			createFileChooser();
		}
		fileChooser.setTitle("Select a Ghidra Project Directory");
		fileChooser.setApproveButtonText("Select Project Directory");
		fileChooser.setApproveButtonToolTipText("Select a Ghidra Project Directory");

		File file = fileChooser.getSelectedFile();

		if (file != null) {
			directoryField.setText(file.getAbsolutePath());

			WizardManager wm = panelManager.getWizardManager();
			wm.setStatusMessage("");
			wm.validityChanged();

			checkProjectFile(true);
		}
	}

	private String getProjectName(String name) {
		if (name.endsWith(PROJECT_EXTENSION)) {
			name = name.substring(0, name.indexOf(PROJECT_EXTENSION) - 1);
		}
		return name;
	}

	private void createFileChooser() {
		WizardManager wm = panelManager.getWizardManager();

		fileChooser = new GhidraFileChooser(wm.getComponent());
		File projectDirectory = new File(GenericRunInfo.getProjectsDirPath());
		String lastDirSelected =
			Preferences.getProperty(Preferences.LAST_NEW_PROJECT_DIRECTORY, null, true);
		if (lastDirSelected != null) {
			projectDirectory = new File(lastDirSelected);
		}
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
		fileChooser.setFileFilter(new GhidraFileFilter() {
			@Override
			public String getDescription() {
				return "All Directories";
			}

			@Override
			public boolean accept(File f, GhidraFileChooserModel model) {
				return model.isDirectory(f) &&
					!f.getName().endsWith(ProjectLocator.getProjectDirExtension());
			}
		});
		fileChooser.setCurrentDirectory(projectDirectory);//start the browsing in the user's preferred project directory
	}
}
