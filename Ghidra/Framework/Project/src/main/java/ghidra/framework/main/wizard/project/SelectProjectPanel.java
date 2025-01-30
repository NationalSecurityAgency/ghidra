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
package ghidra.framework.main.wizard.project;

import java.awt.BorderLayout;
import java.io.File;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GDLabel;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.preferences.Preferences;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.PairLayout;
import utility.function.Callback;

/**
 * Panel that allows the project directory and name to be specified for a
 * new project. A checkbox indicates whether the project should be created
 * as a shared project. Used by the {@link SelectProjectStep} of the new project wizard.
 *
 */
public class SelectProjectPanel extends JPanel {

	//remove the "." from the extension
	private static String PROJECT_EXTENSION = ProjectLocator.getProjectExtension().substring(1);

	private JTextField projectNameField;
	private JTextField directoryField;
	private JButton browseButton;

	private Callback statusChangedCallback;

	/**
	 * Construct a new panel.
	 * @param statusChangedCallback callback
	 */
	public SelectProjectPanel(Callback statusChangedCallback) {
		super(new PairLayout(10, 10));
		setBorder(ProjectWizardModel.STANDARD_BORDER);

		this.statusChangedCallback = statusChangedCallback;
		buildMainPanel();
	}

	void setProjectName(String projectName) {
		projectNameField.setText(projectName);
	}

	String getProjectName() {
		String name = projectNameField.getText().trim();
		if (name.endsWith(PROJECT_EXTENSION)) {
			name = name.substring(0, name.length() - PROJECT_EXTENSION.length());
		}
		return name;
	}

	String getDirectoryName() {
		return directoryField.getText().trim();
	}

	private void buildMainPanel() {
		DocumentListener documentListener = createDocumentListener();

		add(new GDLabel("Project Directory:", SwingConstants.RIGHT));
		add(createDirectoryPanel(documentListener));
		add(new GDLabel("Project Name:", SwingConstants.RIGHT));
		add(createProjectNameField(documentListener));
	}

	private JTextField createProjectNameField(DocumentListener documentListener) {
		projectNameField = new JTextField(10);
		projectNameField.setName("Project Name");
		projectNameField.addActionListener(e -> statusChangedCallback.call());
		projectNameField.getDocument().addDocumentListener(documentListener);
		return projectNameField;
	}

	private JPanel createDirectoryPanel(DocumentListener listener) {
		JPanel panel = new JPanel(new BorderLayout());
		directoryField = new JTextField(10);
		directoryField.getDocument().addDocumentListener(listener);
		directoryField.setName("Project Directory");

		File projectDirectory = null;
		String projectDirPath = Preferences.getProperty(Preferences.LAST_NEW_PROJECT_DIRECTORY);
		if (projectDirPath != null) {
			// if it exists, use last directory where project was created
			projectDirectory = new File(projectDirPath);
			if (!projectDirectory.isDirectory()) {
				projectDirectory = null;
			}
		}
		if (projectDirectory == null) {
			// otherwise, use last project directory or default
			projectDirectory = new File(GenericRunInfo.getProjectsDirPath());
		}
		projectDirPath = projectDirectory.getAbsolutePath();
		directoryField.setText(projectDirPath);
		directoryField.setCaretPosition(projectDirPath.length() - 1);

		browseButton = new BrowseButton();
		browseButton.addActionListener(e -> displayFileChooser());
		JPanel buttonPanel = new JPanel(new BorderLayout());
		buttonPanel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 0));
		buttonPanel.add(browseButton, BorderLayout.CENTER);

		panel.add(directoryField, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.EAST);
		return panel;
	}

	private DocumentListener createDocumentListener() {
		return new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				statusChangedCallback.call();
			}
		};
	}

	private void displayFileChooser() {
		GhidraFileChooser fileChooser = createFileChooser();
		fileChooser.setTitle("Select a Ghidra Project Directory");
		fileChooser.setApproveButtonText("Select Project Directory");
		fileChooser.setApproveButtonToolTipText("Select a Ghidra Project Directory");

		File file = fileChooser.getSelectedFile();

		if (file != null) {
			directoryField.setText(file.getAbsolutePath());
			statusChangedCallback.call();
		}

		fileChooser.dispose();
	}

	private GhidraFileChooser createFileChooser() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(this);
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
		return fileChooser;
	}
}
