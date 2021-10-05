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
package ghidra.plugin.importer;

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;

import docking.DialogComponentProvider;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.EmptyBorderButton;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.MultiLineMessageDialog;
import docking.widgets.label.GLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.*;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.formats.gfilesystem.*;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.local.LocalFileSystem;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.LanguageNotFoundException;
import ghidra.util.*;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.TaskBuilder;
import resources.ResourceManager;

/**
 * Dialog for importing a file into Ghidra as a program.
 */
public class ImporterDialog extends DialogComponentProvider {

	public static final String LAST_IMPORTFILE_PREFERENCE_KEY = "Importer.LastFile";

	protected PluginTool tool;
	private ProgramManager programManager;
	protected FSRL fsrl;
	protected List<Option> options;
	private LoaderMap loaderMap;
	protected LanguageCompilerSpecPair selectedLanguage;
	private DomainFolder destinationFolder;
	private boolean languageNeeded;
	private String suggestedDestinationPath;

	protected ByteProvider byteProvider;
	protected JTextField filenameTextField;
	private boolean userHasChangedName;
	protected JButton folderButton;
	protected JButton languageButton;
	protected JTextField languageTextField;
	protected JButton optionsButton;
	protected JTextField folderNameTextField;
	protected GhidraComboBox<Loader> loaderComboBox;

	/**
	 * Construct a new dialog for importing a file as a new program into Ghidra.
	 * @param tool the active tool that spawned this dialog.
	 * @param programManager program manager to open imported file with or null
	 * @param loaderMap the loaders and their corresponding load specifications
	 * @param byteProvider the ByteProvider for getting the bytes from the file to be imported.  The
	 *        dialog takes ownership of the ByteProvider and it will be closed when the dialog is closed
	 * @param suggestedDestinationPath optional string path that will be pre-pended to the destination
	 * filename.  Any path specified in the destination filename field will be created when
	 * the user performs the import (as opposed to the {@link #setDestinationFolder(DomainFolder) destination folder}
	 * option which requires the DomainFolder to already exist). The two destination paths work together
	 * to specify the final Ghidra project folder where the imported binary is placed.
	 */
	public ImporterDialog(PluginTool tool, ProgramManager programManager, LoaderMap loaderMap,
			ByteProvider byteProvider, String suggestedDestinationPath) {
		this("Import " + byteProvider.getFSRL().getPath(), tool, loaderMap, byteProvider,
			suggestedDestinationPath);
		this.programManager = programManager;
	}

	protected ImporterDialog(String title, PluginTool tool, LoaderMap loaderMap,
			ByteProvider byteProvider, String suggestedDestinationPath) {
		super(title);
		this.tool = tool;
		this.programManager = tool.getService(ProgramManager.class);
		this.fsrl = byteProvider.getFSRL();
		this.loaderMap = loaderMap;
		this.byteProvider = byteProvider;
		this.suggestedDestinationPath = suggestedDestinationPath;

		if (FileSystemService.getInstance().isLocal(fsrl)) {
			// only save the imported file's path if its a local filesystem path that
			// will be valid when used later.  FSRL paths that drill into container files
			// aren't widely supported yet.
			Preferences.setProperty(LAST_IMPORTFILE_PREFERENCE_KEY, fsrl.getPath());
		}

		addWorkPanel(buildWorkPanel());
		addOKButton();
		addCancelButton();
		setDefaultButton(okButton);
		setOkEnabled(false);

		setDestinationFolder(getProjectRootFolder());
		selectedLoaderChanged();
		setMinimumSize(new Dimension(500, getPreferredSize().height));
		setRememberSize(false);
		setHelpLocation(new HelpLocation("ImporterPlugin", "Importer_Dialog"));
	}

	/**
	 * Sets the destination folder for the imported program.
	 * @param folder the folder to store the imported program.
	 */
	public void setDestinationFolder(DomainFolder folder) {
		destinationFolder = folder;
		folderNameTextField.setText(destinationFolder.toString());
		validateFormInput();
	}

	private JComponent buildWorkPanel() {
		JPanel panel = new JPanel(new VerticalLayout(5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildMainPanel());
		panel.add(buildButtonPanel());
		return panel;
	}

	private Component buildMainPanel() {
		JPanel panel = new JPanel(new PairLayout(5, 5));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(new GLabel("Format: ", SwingConstants.RIGHT));
		panel.add(buildLoaderChooser());
		panel.add(new GLabel("Language: ", SwingConstants.RIGHT));
		panel.add(buildLanguagePanel());
		panel.add(new GLabel("Destination Folder: ", SwingConstants.RIGHT));
		panel.add(buildFolderPanel());
		panel.add(new GLabel("Program Name: ", SwingConstants.RIGHT));
		panel.add(buildFilenameTextField());
		return panel;
	}

	private Component buildFilenameTextField() {
		String initalSuggestedFilename =
			FSUtilities.appendPath(suggestedDestinationPath, getSuggestedFilename());
		int columns = (initalSuggestedFilename.length() > 50) ? 50 : 0;
		filenameTextField = new JTextField(initalSuggestedFilename, columns);

		// Use a key listener to track users edits.   We can't use the document listener, as
		// we change the name field ourselves when other fields are changed.
		filenameTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyTyped(KeyEvent e) {
				// tracking all key events; are there any that we don't want to track?
				userHasChangedName = true;
			}
		});
		filenameTextField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void changedUpdate(DocumentEvent e) {
				// don't care
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				validateFormInput();
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				validateFormInput();
			}
		});
		return filenameTextField;
	}

	private String getSuggestedFilename() {
		Loader loader = getSelectedLoader();
		if (loader != null) {
			return loader.getPreferredFileName(byteProvider);
		}
		return fsrl.getName();
	}

	private Component buildFolderPanel() {
		folderNameTextField = new JTextField();
		folderNameTextField.setEditable(false);
		folderNameTextField.setFocusable(false);
		folderButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		folderButton.addActionListener(e -> chooseProjectFolder());

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(folderNameTextField, BorderLayout.CENTER);
		panel.add(folderButton, BorderLayout.EAST);
		return panel;
	}

	private JComponent buildLanguagePanel() {
		languageTextField = new JTextField();
		languageTextField.setEditable(false);
		languageTextField.setFocusable(false);

		languageButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		languageButton.addActionListener(e -> {
			Object selectedItem = loaderComboBox.getSelectedItem();
			if (selectedItem instanceof Loader) {
				Loader loader = (Loader) selectedItem;
				ImporterLanguageDialog dialog =
					new ImporterLanguageDialog(loaderMap.get(loader), tool, selectedLanguage);
				dialog.show(getComponent());
				LanguageCompilerSpecPair dialogResult = dialog.getSelectedLanguage();
				if (dialogResult != null) {
					setSelectedLanguage(dialogResult);
				}
			}
			validateFormInput();
		});

		Font font = languageButton.getFont();
		languageButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(languageTextField, BorderLayout.CENTER);
		panel.add(languageButton, BorderLayout.EAST);
		return panel;
	}

	private Component buildLoaderChooser() {
		JPanel panel = new JPanel(new BorderLayout());

		Set<Loader> set = new LinkedHashSet<>(); // maintain order
		for (Loader loader : loaderMap.keySet()) {
			if (isSupported(loader)) {
				set.add(loader);
			}
		}
		loaderComboBox = new GhidraComboBox<>(new Vector<>(set));
		loaderComboBox.addItemListener(e -> selectedLoaderChanged());
		loaderComboBox.setEnterKeyForwarding(true);
		loaderComboBox.setRenderer(
			GListCellRenderer.createDefaultCellTextRenderer(loader -> loader.getName()));

		if (!set.isEmpty()) {
			loaderComboBox.setSelectedIndex(0);
		}

		panel.add(loaderComboBox, BorderLayout.CENTER);
		panel.add(buildLoaderInfoButton(), BorderLayout.EAST);
		return panel;
	}

	private Component buildLoaderInfoButton() {
		JPanel panel = new JPanel(new BorderLayout());
		EmptyBorderButton helpButton =
			new EmptyBorderButton(ResourceManager.loadImage("images/information.png"));
		helpButton.setToolTipText("Show list of supported format/loaders");

		helpButton.addActionListener(e -> showSupportedImportFormats());
		panel.add(helpButton);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 2));
		return panel;
	}

	private void showSupportedImportFormats() {
		String s = LoaderService.getAllLoaderNames().stream().collect(Collectors.joining("\n"));
		MultiLineMessageDialog.showModalMessageDialog(null, "Supported Formats", null, s,
			MultiLineMessageDialog.PLAIN_MESSAGE);
	}

	protected boolean isSupported(Loader loader) {
		// for full importing, all loaders are supported, but not true for addToProgram
		// which will override this method
		return true;
	}

	protected void selectedLoaderChanged() {
		// when selected item changes, clear out selected language and options...
		Loader loader = loaderComboBox.getItemAt(loaderComboBox.getSelectedIndex());
		if (loader != null) {
			languageNeeded = isLanguageNeeded(loader);
			setSelectedLanguage(getPreferredLanguage(loader));
			String newSuggestedFilename =
				FSUtilities.appendPath(suggestedDestinationPath, getSuggestedFilename());
			setFilename(newSuggestedFilename);
		}
		else {
			languageNeeded = true;
			setSelectedLanguage(null);
		}
		options = null;
		validateFormInput();
	}

	private boolean isLanguageNeeded(Loader loader) {
		return loaderMap.get(loader).stream().anyMatch(spec -> spec.requiresLanguageCompilerSpec());
	}

	private Component buildButtonPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		JPanel innerPanel = new JPanel(new VerticalLayout(5));
		innerPanel.add(buildOptionsButton());
		panel.add(innerPanel, BorderLayout.EAST);
		return panel;
	}

	private Component buildOptionsButton() {
		optionsButton = new JButton("Options...");
		optionsButton.addActionListener(e -> showOptions());
		return optionsButton;
	}

	@Override
	protected void okCallback() {
		if (validateFormInput()) {
			Loader loader = getSelectedLoader();
			LoadSpec loadSpec = getSelectedLoadSpec(loader);
			String programPath = removeTrailingSlashes(getName());
			DomainFolder importFolder = getOrCreateImportFolder(destinationFolder, programPath);
			String programName = FilenameUtils.getName(programPath);
			options = getOptions(loadSpec);  // make sure you get the options now, before the ByteProvider is closed.

			//@formatter:off
			new TaskBuilder("Import File", monitor -> {
				ImporterUtilities.importSingleFile(tool, programManager, fsrl, importFolder,
					loadSpec, programName, options, monitor);
			})
			.setLaunchDelay(0)
			.launchNonModal();
			//@formatter:on

			close();
		}
	}

	private String removeTrailingSlashes(String path) {
		while (path.endsWith("/")) {
			path = path.substring(0, path.length() - 1);
		}
		return path;
	}

	private DomainFolder getOrCreateImportFolder(DomainFolder parentFolder, String programPath) {
		int lastIndexOf = programPath.lastIndexOf("/");
		if (lastIndexOf < 0) {
			return parentFolder;
		}
		String folderPath = programPath.substring(0, lastIndexOf);
		try {
			return ProjectDataUtils.createDomainFolderPath(parentFolder, folderPath);
		}
		catch (InvalidNameException e) {
			Msg.showError(this, null, "Error Creating Folders", e.getMessage());
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error Creating Folders", "I/O Error" + e.getMessage(), e);
		}
		return parentFolder;
	}

	@Override
	public void close() {
		super.close();
		try {
			byteProvider.close();
		}
		catch (IOException e) {
			Msg.showError(this, null, "Unexpected exception closing byte provider.", e);
		}
	}

	protected List<Option> getOptions(LoadSpec loadSpec) {
		if (options == null) {
			options = loadSpec.getLoader().getDefaultOptions(byteProvider, loadSpec, null, false);
		}
		return options;
	}

	private void showOptions() {
		try {
			Loader loader = getSelectedLoader();
			AddressFactory addressFactory = selectedLanguage.getLanguage().getAddressFactory();
			LoadSpec loadSpec = getSelectedLoadSpec(loader);
			OptionValidator validator =
				optionList -> loader.validateOptions(byteProvider, loadSpec, optionList, null);

			AddressFactoryService service = () -> addressFactory;

			List<Option> currentOptions = getOptions(loadSpec);
			if (currentOptions.isEmpty()) {
				Msg.showInfo(this, null, "Options", "There are no options for this importer!");
				return;
			}

			OptionsDialog optionsDialog = new OptionsDialog(currentOptions, validator, service);
			optionsDialog.setHelpLocation(
				new HelpLocation("ImporterPlugin", getAnchorForSelectedLoader(loader)));
			tool.showDialog(optionsDialog);
			if (!optionsDialog.wasCancelled()) {
				options = optionsDialog.getOptions();
			}
			validateFormInput();
		}
		catch (LanguageNotFoundException e) {
			Msg.showError(this, null, "Language Error",
				"Can't get the language for " + selectedLanguage);
		}
	}

	private String getAnchorForSelectedLoader(Loader loader) {
		return "Options_" + loader.getName();
	}

	protected LoadSpec getSelectedLoadSpec(Loader loader) {
		Collection<LoadSpec> loadSpecs = loaderMap.get(loader);
		long imageBase = 0;
		if (loadSpecs != null && !loadSpecs.isEmpty()) {
			imageBase = loadSpecs.iterator().next().getDesiredImageBase();
		}
		return new LoadSpec(loader, imageBase, selectedLanguage, false);
	}

	protected Loader getSelectedLoader() {
		return (Loader) loaderComboBox.getSelectedItem();
	}

	protected boolean validateFormInput() {
		setOkEnabled(false);
		languageButton.setEnabled(languageNeeded);
		optionsButton.setEnabled(false);
		if (loaderComboBox.getSelectedIndex() == -1) {
			setStatusText("Please select a format.");
			return false;
		}
		if (languageNeeded && selectedLanguage == null) {
			setStatusText("Please select a language.");
			return false;
		}
		optionsButton.setEnabled(selectedLanguage != null);
		if (!validateFilename()) {
			return false;
		}
		setStatusText("");
		setOkEnabled(true);
		return true;
	}

	private boolean validateFilename() {
		if (getName().isEmpty()) {
			setStatusText("Please enter a destination file name.");
			return false;
		}
		if (warnedAboutInvalidFilenameChars()) {
			return false;
		}
		if (isMissingFilename()) {
			setStatusText("Destination path does not specify filename.");
			return false;
		}
		if (isDuplicateFilename()) {
			setStatusText("Destination file name already exists.");
			return false;
		}
		if (isFilenameTooLong()) {
			setStatusText("Destination file name is too long. ( >" +
				tool.getProject().getProjectData().getMaxNameLength() + ")");
			return false;
		}
		return true;
	}

	private boolean warnedAboutInvalidFilenameChars() {
		String filename = getName();
		for (int i = 0; i < filename.length(); i++) {
			char ch = filename.charAt(i);
			if (!LocalFileSystem.isValidNameCharacter(ch) && ch != '/') {
				setStatusText("Invalid character " + ch + " in filename.");
				return true;
			}
		}
		return false;
	}

	private boolean isMissingFilename() {
		String filename = FilenameUtils.getName(getName());
		return StringUtils.isBlank(filename);
	}

	private boolean isDuplicateFilename() {
		String pathFilename = getName();
		String parentPath = FilenameUtils.getFullPathNoEndSeparator(pathFilename);
		String filename = FilenameUtils.getName(pathFilename);
		DomainFolder localDestFolder =
			(parentPath != null) ? ProjectDataUtils.lookupDomainPath(destinationFolder, parentPath)
					: destinationFolder;
		if (localDestFolder != null) {
			if (localDestFolder.getFolder(filename) != null ||
				localDestFolder.getFile(filename) != null) {
				return true;
			}
		}
		return false;
	}

	private boolean isFilenameTooLong() {
		int maxNameLen = tool.getProject().getProjectData().getMaxNameLength();
		String fullPath = getName();
		String currentPath = fullPath;
		while (!StringUtils.isBlank(currentPath)) {
			String filename = FilenameUtils.getName(currentPath);
			if (filename.isEmpty()) {
				return false;
			}
			if (filename.length() >= maxNameLen) {
				return true;
			}
			currentPath = FilenameUtils.getFullPathNoEndSeparator(currentPath);
		}
		return false;
	}

	private String getName() {
		return filenameTextField.getText().trim();
	}

	private void setFilename(String s) {
		if (userHasChangedName && validateFilename()) {
			// Changing the user's text is really annoying. Keep the user's filename, if it is valid
			return;
		}

		filenameTextField.setText(s);
		filenameTextField.setCaretPosition(s.length());
	}

	protected void setSelectedLanguage(LanguageCompilerSpecPair lcsPair) {
		this.selectedLanguage = lcsPair;
		if (selectedLanguage == null) {
			languageTextField.setText("");
		}
		else {
			languageTextField.setText(selectedLanguage.toString());
		}
	}

	private LanguageCompilerSpecPair getPreferredLanguage(Loader loader) {
		LanguageCompilerSpecPair preferredSpecPair = null;
		for (LoadSpec loadSpec : loaderMap.get(loader)) {
			if (loadSpec.isPreferred()) {
				if (preferredSpecPair != null) {
					return null;
				}
				preferredSpecPair = loadSpec.getLanguageCompilerSpec();
			}
		}
		return preferredSpecPair;
	}

	private DomainFolder getProjectRootFolder() {
		Project project = AppInfo.getActiveProject();
		ProjectData projectData = project.getProjectData();
		return projectData.getRootFolder();
	}

	private void chooseProjectFolder() {
		DataTreeDialog dataTreeDialog = new DataTreeDialog(getComponent(),
			"Choose a project folder", DataTreeDialog.CHOOSE_FOLDER);
		dataTreeDialog.setSelectedFolder(destinationFolder);
		dataTreeDialog.showComponent();
		DomainFolder folder = dataTreeDialog.getDomainFolder();
		if (folder != null) {
			setDestinationFolder(folder);
		}
	}

	///////////////////////////////////////
	// Methods for testing              ///
	///////////////////////////////////////
	JComboBox<Loader> getFormatComboBox() {
		return loaderComboBox;
	}

	JTextField getLanguageTextField() {
		return languageTextField;
	}

	JTextField getFilenameTextField() {
		return filenameTextField;
	}

}
