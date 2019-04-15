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
package ghidra.feature.fid.plugin;

import java.awt.*;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.combobox.GComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.script.SelectLanguageDialog;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.service.DefaultFidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.VersionException;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.Task;

/**
 * Dialog for gathering information to populate a fid database.
 */
public class PopulateFidDialog extends DialogComponentProvider {

	private JTextField libraryFamilyNameTextField;
	private JTextField versionTextField;
	private PluginTool tool;
	private JTextField domainFolderField;
	private JComboBox<FidFile> fidFileComboBox;
	private JComboBox<LibraryChoice> libraryComboBox;
	private JTextField variantTextField;
	private FidService fidService;
	private JTextField languageIdField;
	private JTextField symbolsFileTextField;

	protected PopulateFidDialog(PluginTool tool, FidService fidService) {
		super("Populate Fid Database");
		this.tool = tool;
		this.fidService = fidService;
		addWorkPanel(buildMainPanel());
		addOKButton();
		addCancelButton();
		updateOkEnablement();
		setRememberSize(false);
		setHelpLocation(new HelpLocation(FidPlugin.FID_HELP, "populatedialog"));
	}

	@Override
	protected void okCallback() {
		FidFile fidFile = (FidFile) fidFileComboBox.getSelectedItem();
		LibraryChoice libraryChoice = (LibraryChoice) libraryComboBox.getSelectedItem();
		LibraryRecord libraryRecord = libraryChoice.getLibraryRecord();
		String libraryFamilyName = libraryFamilyNameTextField.getText().trim();
		String libraryVersion = versionTextField.getText().trim();
		String libraryVariant = variantTextField.getText().trim();
		DomainFolder folder = getDomainFolder();
		String languageFilter = languageIdField.getText().trim();
		File commonSymbolsFile = getCommonSymbolsFile();

		Task task = new IngestTask("Populate Library Task", fidFile, libraryRecord, folder,
			libraryFamilyName, libraryVersion, libraryVariant, languageFilter, commonSymbolsFile,
			fidService, new DefaultFidPopulateResultReporter());
		close();
		tool.execute(task);
	}

	private File getCommonSymbolsFile() {
		String symbolsFilePath = symbolsFileTextField.getText().trim();
		if (symbolsFilePath.isEmpty()) {
			return null;
		}
		return new File(symbolsFilePath);
	}

	private DomainFolder getDomainFolder() {
		Project project = AppInfo.getActiveProject();
		ProjectData pd = project.getProjectData();
		return pd.getFolder(domainFolderField.getText().trim());
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		JLabel jLabel = new GDLabel("Fid Database: ", SwingConstants.RIGHT);
		jLabel.setToolTipText("Choose the Fid Database to populate");
		panel.add(jLabel);
		panel.add(buildFidCombo());

		panel.add(new GLabel("Library Family Name: ", SwingConstants.RIGHT));
		libraryFamilyNameTextField = new JTextField(20);
		libraryFamilyNameTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
		panel.add(libraryFamilyNameTextField);

		panel.add(new GLabel("Library Version: ", SwingConstants.RIGHT));
		versionTextField = new JTextField();
		versionTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
		panel.add(versionTextField);

		panel.add(new GLabel("Library Variant: ", SwingConstants.RIGHT));
		variantTextField = new JTextField();
		variantTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
		panel.add(variantTextField);

		panel.add(new GLabel("Base Library: ", SwingConstants.RIGHT));
		panel.add(buildLibraryCombo());

		panel.add(new GLabel("Root Folder: ", SwingConstants.RIGHT));
		panel.add(buildDomainFolderChooserField());

		panel.add(new GLabel("Language: ", SwingConstants.RIGHT));
		panel.add(buildLanguageField());

		panel.add(new GLabel("Common Symbols File: ", SwingConstants.RIGHT));
		panel.add(buildSymbolsFileField(), jLabel);

		return panel;
	}

	private JComponent buildSymbolsFileField() {
		JPanel panel = new JPanel(new BorderLayout());
		symbolsFileTextField = new JTextField();
		panel.add(symbolsFileTextField, BorderLayout.CENTER);
		JButton browseButton = createBrowseButton();
		browseButton.addActionListener(e -> {
			GhidraFileChooser chooser = new GhidraFileChooser(tool.getToolFrame());
			chooser.setTitle("Choose Common Symbols File");
			chooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
//			chooser.setFileFilter(null);
			File selectedFile = chooser.getSelectedFile();
			if (selectedFile != null) {
				symbolsFileTextField.setText(selectedFile.getAbsolutePath());
			}
		});
		symbolsFileTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
		panel.add(browseButton, BorderLayout.EAST);
		return panel;
	}

	private Component buildLanguageField() {
		JPanel panel = new JPanel(new BorderLayout());
		languageIdField = new JTextField();
		panel.add(languageIdField, BorderLayout.CENTER);
		JButton browseButton = createBrowseButton();
		browseButton.addActionListener(e -> {
			SelectLanguageDialog selectLanguageDialog =
				new SelectLanguageDialog("Select Language", "Ok");
			LanguageCompilerSpecPair selectedLanguage = selectLanguageDialog.getSelectedLanguage();
			if (selectedLanguage != null) {
				languageIdField.setText(selectedLanguage.languageID.toString());
			}
		});
		languageIdField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
		panel.add(browseButton, BorderLayout.EAST);
		return panel;

	}

	private Component buildLibraryCombo() {
		LibraryChoice[] choices = getChoicesForLibraryCombo();
		libraryComboBox = new GComboBox<>(choices);
		return libraryComboBox;
	}

	private LibraryChoice[] getChoicesForLibraryCombo() {
		List<LibraryChoice> list = new ArrayList<>();
		list.add(new LibraryChoice("None", null));
		FidFile selectedItem = (FidFile) fidFileComboBox.getSelectedItem();
		if (selectedItem != null) {
			try (FidDB fidDB = selectedItem.getFidDB(false)) {
				List<LibraryRecord> allLibraries = fidDB.getAllLibraries();
				for (LibraryRecord libraryRecord : allLibraries) {
					list.add(new LibraryChoice(libraryRecord.toString(), libraryRecord));
				}
			}
			catch (VersionException e) {
				// Version upgrades are not supported
				Msg.showError(this, null, "Failed to open FidDb",
					"Failed to open incompatible FidDb (may need to regenerate with this version of Ghidra): " +
						selectedItem.getPath());
			}
			catch (IOException e) {
				Msg.showError(this, null, "Failed to open FidDb",
					"Failed to open FidDb: " + selectedItem.getPath(), e);
			}
		}
		return list.toArray(new LibraryChoice[list.size()]);
	}

	private Component buildDomainFolderChooserField() {
		JPanel panel = new JPanel(new BorderLayout());
		domainFolderField = new JTextField();
		domainFolderField.setEditable(false);
		panel.add(domainFolderField, BorderLayout.CENTER);
		JButton browseButton = createBrowseButton();
		browseButton.addActionListener(e -> {
			final DataTreeDialog dialog = new DataTreeDialog(tool.getToolFrame(),
				"Choose Root Folder", DataTreeDialog.CHOOSE_FOLDER);
			tool.showDialog(dialog);
			DomainFolder domainFolder = dialog.getDomainFolder();
			if (domainFolder != null) {
				domainFolderField.setText(domainFolder.getPathname());
			}
			updateOkEnablement();
		});
		panel.add(browseButton, BorderLayout.EAST);
		return panel;
	}

	private Component buildFidCombo() {
		List<FidFile> fidFileList = FidFileManager.getInstance().getUserAddedFiles();
		FidFile[] files = fidFileList.toArray(new FidFile[fidFileList.size()]);
		fidFileComboBox = new GComboBox<>(files);
		fidFileComboBox.addActionListener(e -> updateLibraryChoices());
		return fidFileComboBox;
	}

	private void updateLibraryChoices() {
		LibraryChoice[] choices = getChoicesForLibraryCombo();
		libraryComboBox.setModel(new DefaultComboBoxModel<>(choices));
		updateOkEnablement();
	}

	private void updateOkEnablement() {
		setOkEnabled(isUserInputComplete());
	}

	private boolean isUserInputComplete() {
		if (fidFileComboBox.getSelectedItem() == null) {
			return false;
		}
		if (libraryFamilyNameTextField.getText().trim().isEmpty()) {
			return false;
		}
		if (versionTextField.getText().trim().isEmpty()) {
			return false;
		}
		if (variantTextField.getText().trim().isEmpty()) {
			return false;
		}
		if (domainFolderField.getText().trim().isEmpty()) {
			return false;
		}
		if (languageIdField.getText().trim().isEmpty()) {
			return false;
		}
		String symbolsFilePath = symbolsFileTextField.getText().trim();
		if (!symbolsFilePath.isEmpty() && !(new File(symbolsFilePath).exists())) {
			return false;
		}
		return true;
	}

	private JButton createBrowseButton() {
		JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		Font font = browseButton.getFont();
		browseButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));
		return browseButton;
	}

	private static class LibraryChoice {
		private final String name;
		private final LibraryRecord libraryRecord;

		LibraryChoice(String name, LibraryRecord libraryRecord) {
			this.name = name;
			this.libraryRecord = libraryRecord;
		}

		@Override
		public String toString() {
			return name;
		}

		public LibraryRecord getLibraryRecord() {
			return libraryRecord;
		}
	}
}
