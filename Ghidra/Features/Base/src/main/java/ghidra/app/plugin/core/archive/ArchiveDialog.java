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
import java.io.File;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GDLabel;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.*;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;

/**
 * Dialog to prompt the user for the project to archive and the file to archive
 * it to.
 */
public class ArchiveDialog extends DialogComponentProvider {
	private static final int NUM_TEXT_COLUMNS = 40;

	private boolean actionComplete;
	private JLabel archiveLabel;
	private JTextField archiveField;
	private JButton archiveBrowse;

	private GhidraFileChooser jarFileChooser;
	private ProjectLocator projectLocator;
	private String archivePathName;

	/**
	 * Constructor
	 *
	 * @param parent the parent frame of the NumberInputDialog.
	 * @param plugin the archive plugin using this dialog.
	 */
	ArchiveDialog(ArchivePlugin plugin) {
		super("Archive Current Project");
		initialize();
		setHelpLocation(new HelpLocation("FrontEndPlugin", "Archive_Project"));
	}

	/**
	 * Performs initialization of instance variables.
	 */
	protected void initialize() {
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
	}

	/**
	 * Define the Main panel for the dialog here.
	 * @return JPanel the completed <CODE>Main Panel</CODE>
	 */
	protected JPanel buildMainPanel() {
		GridBagLayout gbl = new GridBagLayout();
		JPanel outerPanel = new JPanel(gbl);

		archiveLabel = new GDLabel(" Archive File ");
		archiveField = new JTextField();
		archiveField.setName("archiveField");
		archiveField.setColumns(NUM_TEXT_COLUMNS);
		archiveBrowse = new JButton(ArchivePlugin.DOT_DOT_DOT);
		archiveBrowse.addActionListener(e -> {
			archivePathName = archiveField.getText().trim();
			String archName = chooseArchiveFile("Choose archive file", "Selects the archive file");
			if (archName != null) {
				// Make sure the archive has the correct suffix.
				if (!archName.endsWith(ArchivePlugin.ARCHIVE_EXTENSION)) {
					archName += ArchivePlugin.ARCHIVE_EXTENSION;
				}
				archivePathName = archName;
				archiveField.setText(archivePathName);
			}
		});
		Font font = archiveBrowse.getFont();
		archiveBrowse.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));
		archiveBrowse.setName("archiveBrowse");

		// Layout the components.
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

		return outerPanel;
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	protected void okCallback() {
		if (checkInput()) {
			// Check if archive file exists.
			String archive = archiveField.getText().trim();
			if (!archive.endsWith(ArchivePlugin.ARCHIVE_EXTENSION)) {
				archive += ArchivePlugin.ARCHIVE_EXTENSION;
			}
			File file = new File(archive);
			if (file.exists() && OptionDialog.showOptionDialog(rootPanel, "Archive File Exists",
				"File " + archive + " exists.\n " + "Do you want to overwrite existing file?",
				"Yes") != OptionDialog.OPTION_ONE) {
				return;
			}

			actionComplete = true;
			close();
		}
		else {
			rootPanel.getToolkit().beep();
		}
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	/**
	 * Display this dialog.
	 * @param pProjectLocator the project URL to display when the dialog pops up.
	 * @param pArchivePathName the archive file name to display when the dialog pops up.
	 *
	 * @return true if the user submitted valid values for the project and 
	 * archive file, false if user cancelled.
	 */
	public boolean showDialog(ProjectLocator pProjectLocator, String pArchivePathName,
			PluginTool tool) {
		this.projectLocator = pProjectLocator;
		if (pArchivePathName != null) {
			pArchivePathName = pArchivePathName.replace("/", File.separator);
		}

		this.archivePathName = pArchivePathName;
		archiveField.setText(pArchivePathName);
		actionComplete = false;
		tool.showDialog(this);
		return actionComplete;
	}

	/**
	 * Returns the path name of the user specified archive file.
	 * @return the archive file path name.
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

	/////////////////////////////////////////////
	// *** private methods ***
	/////////////////////////////////////////////

	/**
	 * Check the entry to determine if the user input is valid for archiving 
	 * a project.
	 *
	 * @return boolean true if input is OK
	 */
	private boolean checkInput() {
		String pathname = getArchivePathName();
		if ((pathname == null) || (pathname.equals(""))) {
			setStatusText("Specify an archive file.");
			return false;
		}

		File file = new File(pathname);
		String name = file.getName();
		if (!isValidName(name)) {
			setStatusText("Archive name contains invalid characters.");
			return false;
		}
		return true;
	}

	/**
	 * Creates a file chooser for selecting files with the specified extension.
	 * @param extension the file extension for valid files to choose.
	 * @param description the description for the extension
	 * @param filePathName the file path indicating the default directory/file
	 * to select.
	 * @return the file chooser.
	 */
	private GhidraFileChooser createFileChooser(String extension, final String description,
			String filePathName) {

		GhidraFileChooser fileChooser = new GhidraFileChooser(getComponent());

		fileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		fileChooser.setFileFilter(new GhidraFileFilter() {
			@Override
			public boolean accept(File file, GhidraFileChooserModel model) {
				if (file == null) {
					return false;
				}

				if (file.isDirectory()) {
					return true;
				}

				return file.getAbsolutePath().toLowerCase().endsWith(
					ArchivePlugin.ARCHIVE_EXTENSION);
			}

			@Override
			public String getDescription() {
				return description;
			}
		});

		// start the browsing in the user's preferred project directory
		File startDirectory = null;
		if ((filePathName != null) && (filePathName.length() > 0)) {
			startDirectory = new File(filePathName);
			if (startDirectory.isDirectory()) {
				fileChooser.setCurrentDirectory(startDirectory);
			}
			else {
				if (!filePathName.endsWith(extension)) {
					startDirectory = new File(filePathName + extension);
				}
				fileChooser.setSelectedFile(startDirectory);
			}
		}
		if (startDirectory == null) {
			startDirectory = new File(GenericRunInfo.getProjectsDirPath());
			fileChooser.setCurrentDirectory(startDirectory);
		}

		return fileChooser;
	}

	/**
	 * Brings up a file chooser for the user to specify a directory and 
	 * filename of the archive file.
	 * @param approveButtonText The label for the "Open" button on the file chooser
	 * @param approveToolTip The tool tip for the "Open" button on the file chooser
	 * @return the archive file path.
	 */
	String chooseArchiveFile(String approveButtonText, String approveToolTip) {
		if (jarFileChooser == null) {
			jarFileChooser = createFileChooser(ArchivePlugin.ARCHIVE_EXTENSION, "Ghidra Archives",
				archivePathName);
			jarFileChooser.setTitle("Archive a Ghidra Project");
		}
		File jarFile = null;
		if (archivePathName != null && archivePathName.length() != 0) {
			jarFile = new File(archivePathName);
		}
		else if (projectLocator != null) {
			jarFile = new File(projectLocator.toString() + ArchivePlugin.ARCHIVE_EXTENSION);
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
			String chosenPathname = file.getAbsolutePath();
			String name = file.getName();
			if (!NamingUtilities.isValidName(name)) {
				Msg.showError(getClass(), null, "Invalid Archive Name",
					name + " is not a valid archive name");
				continue;
			}

			File f = projectLocator.getProjectDir();
			String filename = f.getAbsolutePath();
			if (chosenPathname.indexOf(filename) >= 0) {
				Msg.showError(getClass(), null, "Invalid Archive Name",
					"Output file cannot be inside of Project");
				continue;
			}

			pathname = chosenPathname;
		}

		return pathname;
	}

	/**
	 * tests whether the given string is a valid name.
	 * @param name name to validate
	 */
	public boolean isValidName(String name) {
		if (name == null) {
			return false;
		}

		if ((name.length() < 1)) {
			return false;
		}

		for (int i = 0; i < name.length(); i++) {
			char c = name.charAt(i);
			if (!Character.isLetterOrDigit(c) && c != '.' && c != '-' && c != ' ' && c != '_' &&
				c != '\\' && c != '~' && c != '/' && c != ':') {
				return false;
			}
		}

		return true;
	}

}
