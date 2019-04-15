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
package ghidra.app.plugin.core.archive;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GDLabel;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * Dialog to prompt the user for the archive file to restore 
 * and where to restore it to.
 */
public class RestoreDialog extends DialogComponentProvider {
	/**
	 * Preference name for directory last selected to choose a jar file
	 * to restore.
	 */

	private static final int NUM_TEXT_COLUMNS = 40;

	private ArchivePlugin plugin;

	private boolean actionComplete;
	private JLabel archiveLabel;
	private JTextField archiveField;
	private JButton archiveBrowse;
	private JLabel restoreLabel;
	private JTextField restoreField;
	private JButton restoreBrowse;
	private JLabel projectNameLabel;
	private JTextField projectNameField;
	private GhidraFileChooser jarFileChooser;
	private GhidraFileChooser dirChooser;

	private String archivePathName;
	private ProjectLocator restoreURL;

	public RestoreDialog(ArchivePlugin plugin) {
		super("Restore Project Archive", true);
		this.plugin = plugin;
		initialize();

		setHelpLocation(new HelpLocation("FrontEndPlugin", "Restore_Project"));
	}

	protected void initialize() {
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	protected JPanel buildMainPanel() {

		// Create the individual components that make up the panel.
		archiveLabel = new GDLabel(" Archive File ");
		archiveField = new JTextField();
		archiveField.setColumns(NUM_TEXT_COLUMNS);
		archiveField.setName("archiveField");

		archiveBrowse = new JButton(ArchivePlugin.DOT_DOT_DOT);
		archiveBrowse.setName("archiveButton");
		archiveBrowse.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {

				String archivePath = chooseArchiveFile("Choose archive file",
					"Selects the project archive file to restore.");

				if ((archivePath != null) && (!archivePath.equals(""))) {
					// Make sure the archive has the correct suffix.
					if (!archivePath.endsWith(ArchivePlugin.ARCHIVE_EXTENSION)) {
						archivePath += ArchivePlugin.ARCHIVE_EXTENSION;
					}
					archiveField.setText(archivePath);

					String projectName = ArchivePlugin.getProjectName(archivePath);
					projectNameField.setText(projectName);

					String dir = restoreField.getText().trim();
					if (dir.equals("")) {
						dir = archivePath.substring(0, archivePath.lastIndexOf(File.separator));
						restoreField.setText(dir);
					}
					if ((projectName == null) || (projectName.equals(""))) {
						Msg.showError(this, getComponent(), ArchivePlugin.RESTORE_ERROR_TITLE,
							"Archive File is not a valid project archive.");
					}
				}
			}
		});
		Font font = archiveBrowse.getFont();
		archiveBrowse.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));

		restoreLabel = new GDLabel(" Restore Directory ");
		restoreField = new JTextField();
		restoreField.setName("restoreField");
		restoreField.setColumns(RestoreDialog.NUM_TEXT_COLUMNS);

		restoreBrowse = new JButton(ArchivePlugin.DOT_DOT_DOT);
		restoreBrowse.setName("restoreButton");
		restoreBrowse.addActionListener(e -> {
			String dirPath = chooseDirectory("Choose restore directory",
				"Select the directory for restoring the project.");
			if (dirPath != null) {
				restoreField.setText(dirPath);
			}
		});
		font = restoreBrowse.getFont();
		restoreBrowse.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));

		projectNameLabel = new GDLabel(" Project Name ");
		projectNameField = new JTextField();
		projectNameField.setName("projectNameField");
		projectNameField.setColumns(RestoreDialog.NUM_TEXT_COLUMNS);

		projectNameField.addActionListener(e -> {
			if (archiveField.getText().length() > 0 && restoreField.getText().length() > 0 &&
				projectNameField.getText().length() > 0) {
				okCallback();
			}
		});

		// Actually create the panel and arrange the components in it.

		GridBagLayout gbl = new GridBagLayout();
		JPanel outerPanel = new JPanel(gbl);

		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets.top = 5;
		gbc.insets.left = 5;
		gbc.insets.right = 5;

		// add the labels
		//
		gbc.anchor = GridBagConstraints.EAST;
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbl.setConstraints(archiveLabel, gbc);
		outerPanel.add(archiveLabel);

		gbc.gridy = 1;
		gbl.setConstraints(restoreLabel, gbc);
		outerPanel.add(restoreLabel);

		gbc.gridy = 2;
		gbl.setConstraints(projectNameLabel, gbc);
		outerPanel.add(projectNameLabel);

		// add the textFields
		//
		gbc.anchor = GridBagConstraints.CENTER;
		gbc.insets.left = 0;
		gbc.insets.right = 0;
		gbc.weightx = 1.0;
		gbc.gridwidth = 1;
		gbc.fill = GridBagConstraints.HORIZONTAL;
		gbc.gridx = 1;
		gbc.gridy = 0;
		gbl.setConstraints(archiveField, gbc);
		outerPanel.add(archiveField);
		gbc.gridy = 1;
		gbl.setConstraints(restoreField, gbc);
		outerPanel.add(restoreField);
		gbc.gridy = 2;
		gbl.setConstraints(projectNameField, gbc);
		outerPanel.add(projectNameField);

		gbc.weightx = 0.0;

		// add the browse buttons
		//
		gbc.anchor = GridBagConstraints.WEST;
		gbc.gridwidth = 1;
		gbc.insets.left = 5;
		gbc.insets.right = 5;
		gbc.gridx = 2;
		gbc.gridy = 0;
		gbl.setConstraints(archiveBrowse, gbc);
		outerPanel.add(archiveBrowse);

		gbc.gridy = 1;
		gbl.setConstraints(restoreBrowse, gbc);
		outerPanel.add(restoreBrowse);

		return outerPanel;
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	protected void okCallback() {
		if (checkInput()) {
			actionComplete = true;
			close();
		}
		else {
			getComponent().getToolkit().beep();
		}
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		setStatusText("");
		close();
	}

	/**
	 * Display this dialog.
	 * @param pathName The pathname of the archive file containing the data to restore.
	 * @param projectLocator The project URL of the location to which the restore archive will be
	 *        extracted.
	 *
	 * @return true if the user submitted a valid value, false if user cancelled.
	 */
	public boolean showDialog(String pathName, ProjectLocator projectLocator) {
		this.archivePathName = pathName;
		this.restoreURL = projectLocator;
		String projectName = projectNameField.getText();
		if (projectName == null || projectName.equals("")) {
			projectName = ArchivePlugin.getProjectName(pathName);
		}
		archiveField.setText(pathName);
		restoreField.setText((projectLocator != null) ? projectLocator.getLocation() : null);
		projectNameField.setText(projectName);
		actionComplete = false;
		plugin.getTool().showDialog(this);
		return actionComplete;
	}

	/**
	 * Returns the path name of the user specified archive file.
	 */
	public String getArchivePathName() {
		String archive = archiveField.getText().trim();
		if (archive.length() == 0) {
			return null;
		}

		File file = new File(archive);
		String pathName = file.getAbsolutePath();
		if (pathName == null || pathName.length() == 0) {
			return null;
		}
		if (!pathName.endsWith(ArchivePlugin.ARCHIVE_EXTENSION)) {
			pathName = pathName + ArchivePlugin.ARCHIVE_EXTENSION;
		}
		return pathName;
	}

	/**
	 * Get the URL for the restore directory.
	 * @return the URL for the restore directory.
	 */
	ProjectLocator getRestoreURL() {
		return restoreURL;
	}

	/////////////////////////////////////////////
	// *** private methods ***
	/////////////////////////////////////////////

	/**
	 * Check the entry to determine if the user input is valid for restoring
	 * a project archive.
	 *
	 * @return boolean true if input is OK
	 */
	private boolean checkInput() {
		String archiveName = getArchivePathName();
		if ((archiveName == null) || archiveName.equals("")) {
			setStatusText("Specify a valid archive file.");
			return false;
		}
		String restoreDir = restoreField.getText().trim();
		if (restoreDir == null || restoreDir.equals("") || !(new File(restoreDir)).isDirectory()) {
			setStatusText("Specify a valid project directory.");
			return false;
		}
		String restoreProjectName = projectNameField.getText().trim();
		if (restoreProjectName == null || restoreProjectName.equals("") ||
			!NamingUtilities.isValidName(restoreProjectName)) {
			setStatusText("Specify a valid project name.");
			return false;
		}

		archivePathName = archiveName;
		restoreURL = new ProjectLocator(restoreDir, restoreProjectName);

		File projFile = restoreURL.getMarkerFile();
		File projDir = restoreURL.getProjectDir();
		setStatusText("");
		if (projFile.exists() || projDir.exists()) {
			Msg.showInfo(getClass(), getComponent(), "Project Exists",
				"Cannot restore project because project named " + restoreProjectName +
					" already exists.");
			return false;
		}
		return true;
	}

	/**
	 * Creates a file chooser for selecting files with the specified extension.
	 * @param extension the file extension for valid files to choose.
	 * @param desc the description for the extension
	 * @param fileURL the URL indicating the default directory/file to select.
	 * @return the file chooser.
	 */
	private GhidraFileChooser createFileChooser(String extension, String desc,
			String filePathName) {
		String exampleExtension = extension;
		long lastIndex = extension.lastIndexOf(".");
		if (lastIndex >= 0) {
			exampleExtension = extension.substring((int) (lastIndex + 1));
		}

		GhidraFileChooser fileChooser = new GhidraFileChooser(null);
		// start the browsing in the user's preferred project directory
		File file = null;
		if (filePathName != null && filePathName.length() > 0) {
			file = new File(filePathName);
			if (file.isDirectory()) {
				fileChooser.setCurrentDirectory(file);
			}
			else {
				fileChooser.setSelectedFile(file);
			}
		}
		if (file == null) {
			file = new File(GenericRunInfo.getProjectsDirPath());
			fileChooser.setCurrentDirectory(file);
		}

		fileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		fileChooser.setFileFilter(new ExtensionFileFilter(exampleExtension, desc));

		return fileChooser;
	}

	/**
	 * Creates a directory chooser for selecting the directory where the 
	 * archive will be restored..
	 * @return the file chooser.
	 */
	private GhidraFileChooser createDirectoryChooser() {
		GhidraFileChooser fileChooser = new GhidraFileChooser(null);
		// start the browsing in the user's preferred project directory
		File projectDirectory = new File(GenericRunInfo.getProjectsDirPath());
		fileChooser.setFileSelectionMode(GhidraFileChooser.DIRECTORIES_ONLY);
		fileChooser.setCurrentDirectory(projectDirectory);
		fileChooser.setSelectedFile(projectDirectory);

		return fileChooser;
	}

	/**
	 * Brings up a file chooser for the user to specify a directory and 
	 * filename that are used for the Project location and name
	 * @param approveButtonText The label for the "Open" button on the file chooser
	 * @param approveToolTip The tool tip for the "Open" button on the file chooser
	 * @return the archive filepath.
	 */
	String chooseArchiveFile(String approveButtonText, String approveToolTip) {
		if (jarFileChooser == null) {
			jarFileChooser = createFileChooser(ArchivePlugin.ARCHIVE_EXTENSION, "Ghidra Archives",
				archivePathName);
			jarFileChooser.setTitle("Restore a Ghidra Project - Archive");
			String lastDirSelected = Preferences.getProperty(ArchivePlugin.LAST_ARCHIVE_DIR);
			if (lastDirSelected != null) {
				File file = new File(lastDirSelected);
				if (file.exists()) {
					jarFileChooser.setCurrentDirectory(file);
				}
			}
		}
		File jarFile = null;
		if (archivePathName != null && archivePathName.length() != 0) {
			jarFile = new File(archivePathName);
		}
		jarFileChooser.setSelectedFile(jarFile);
		jarFileChooser.setApproveButtonText(approveButtonText);
		jarFileChooser.setApproveButtonToolTipText(approveToolTip);

		String pathname = null;
		while (pathname == null) {
			File selectedFile = jarFileChooser.getSelectedFile();

			if (selectedFile == null) {
				return null; // user cancelled, get out
			}

			File file = selectedFile;
			String chosenName = file.getName();
			if (!NamingUtilities.isValidName(chosenName)) {
				Msg.showError(getClass(), null, "Invalid Archive Name",
					chosenName + " is not a valid archive name");
				continue;
			}

			Preferences.setProperty(ArchivePlugin.LAST_ARCHIVE_DIR, file.getParent());
			pathname = file.getAbsolutePath();
		}
		return pathname;
	}

	/**
	 * Brings up a file chooser for the user to specify a directory where the
	 * project archive will be restored.
	 * @param approveButtonText The label for the "Open" button on the file chooser
	 * @param approveToolTip The tool tip for the "Open" button on the file chooser
	 * @return the restore directory filepath.
	 */
	String chooseDirectory(String approveButtonText, String approveToolTip) {
		if (dirChooser == null) {
			dirChooser = createDirectoryChooser();
			dirChooser.setTitle("Restore a Ghidra Project - Directory");
		}
		if (restoreURL != null) {
			dirChooser.setSelectedFile(new File(restoreURL.getLocation()));
		}
		dirChooser.setApproveButtonText(approveButtonText);
		dirChooser.setApproveButtonToolTipText(approveToolTip);

		File selectedFile = dirChooser.getSelectedFile(true);
		if (selectedFile != null) {
			return selectedFile.getAbsolutePath();
		}

		return null;
	}

}
