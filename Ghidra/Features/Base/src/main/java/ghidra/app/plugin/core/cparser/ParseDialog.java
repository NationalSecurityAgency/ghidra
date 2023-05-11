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
package ghidra.app.plugin.core.cparser;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.TableModel;

import docking.*;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.button.BrowseButton;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GLabel;
import docking.widgets.pathmanager.PathnameTablePanel;
import docking.widgets.table.GTableCellRenderer;
import docking.widgets.table.GTableCellRenderingData;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.processors.SetLanguageDialog;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import resources.Icons;

/**
 * Dialog that shows files used for parsing C header files. The profile has a list of
 * source header files to parse, followed by parse options (compiler directives).
 * Ghidra supplies a Windows profile by default in core/parserprofiles. The user can do
 * "save as" on this default profile to create new profiles that will be written to the
 * user's <home>/userprofiles directory. The CParserPlugin creates this directory if it
 * doesn't exist.
 *
 * The data types resulting from the parse operation can either be added to the data type
 * manager in the current program, or written to an archive data file.
 *
 *
 *
 */
class ParseDialog extends ReusableDialogComponentProvider {
	final static String PROFILE_DIR = "parserprofiles";

	private static String FILE_EXTENSION = ".prf";

	private static String CURRENT_PROFILE = "CurrentProfile";
	private static String USER_DEFINED = "IsUserDefined";
	private static String LAST_IMPORT_C_DIRECTORY = "LastImportCDirectory";

	private JPanel mainPanel;
	private CParserPlugin plugin;
	private JButton parseButton;
	private JButton parseToFileButton;

	private PathnameTablePanel pathPanel;
	private JTextArea parseOptionsField;

	protected JComponent languagePanel;
	protected JTextField languageTextField;
	protected JButton languageButton;
	protected String languageIDString = null;
	protected String compilerIDString = null;

	private GhidraComboBox<ComboBoxItem> comboBox;
	private DefaultComboBoxModel<ComboBoxItem> comboModel;
	private DockingAction saveAction;
	private DockingAction saveAsAction;
	private DockingAction clearAction;
	private DockingAction deleteAction; // delete user's profiles
	private DockingAction refreshAction; // refresh list of user profiles
	private DocumentListener docListener;
	private TableModelListener tableListener;
	private ItemListener comboItemListener;
	private TableModel tableModel;

	private PathnameTablePanel includePathPanel;
	private TableModel parsePathTableModel;
	private TableModelListener parsePathTableListener;

	private ArrayList<ComboBoxItem> itemList;
	private ComboBoxItemComparator comparator;
	private ResourceFile parentUserFile;
	private boolean saveAsInProgress;
	private boolean initialBuild = true;

	private boolean userDefined = false;
	private String currentProfileName = null;

	ParseDialog(CParserPlugin plugin) {
		super("Parse C Source", false, true, true, false);

		this.plugin = plugin;
	}

	public void setupForDisplay() {
		if (initialBuild) {
			itemList = new ArrayList<>();
			comparator = new ComboBoxItemComparator();
			addWorkPanel(buildMainPanel());
			addDismissButton();
			createActions();
			setActionsEnabled();

			// setup based on save state
			if (currentProfileName != null) {
				for (int i = 0; i < itemList.size(); i++) {
					ComboBoxItem item = itemList.get(i);
					if (userDefined == item.isUserDefined &&
						currentProfileName.equals(item.file.getName())) {
						comboBox.setSelectedIndex(i);
						break;
					}
				}
			}
		}
		else {
			toFront();
		}
	}

	void writeState(SaveState saveState) {
		// Get the current state if the dialog has been displayed
		if (!initialBuild) {
			ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();

			currentProfileName = item.file.getName();
			userDefined = item.isUserDefined;

		}
		saveState.putString(CURRENT_PROFILE, currentProfileName);
		saveState.putBoolean(USER_DEFINED, userDefined);
	}

	void readState(SaveState saveState) {
		currentProfileName = saveState.getString(CURRENT_PROFILE, null);
		if (currentProfileName != null) {
			userDefined = saveState.getBoolean(USER_DEFINED, true);
		}
	}

	void closeProfile() {
		// dialog not built yet
		if (initialBuild) {
			return;
		}
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		if (item.isChanged) {
			processItemChanged(item);
		}
	}

	@Override
	protected TaskScheduler getTaskScheduler() {
		return super.getTaskScheduler();
	}

	protected JPanel buildMainPanel() {
		initialBuild = true;

		mainPanel = new JPanel(new BorderLayout(10, 5));

		comboModel = new DefaultComboBoxModel<>();
		populateComboBox();

		comboBox = new GhidraComboBox<>(comboModel);
		comboItemListener = e -> selectionChanged(e);
		comboBox.addItemListener(comboItemListener);

		JPanel cPanel = new JPanel(new BorderLayout());
		cPanel.setBorder(BorderFactory.createTitledBorder("Parse Configuration"));
		cPanel.add(comboBox);
		JPanel comboPanel = new JPanel(new BorderLayout());
		comboPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		comboPanel.add(cPanel);

		pathPanel = new PathnameTablePanel(null, true, false);
		pathPanel.setBorder(BorderFactory.createTitledBorder("Source files to parse"));
		String importDir = Preferences.getProperty(LAST_IMPORT_C_DIRECTORY);
		if (importDir == null) {
			importDir = Preferences.getProperty(Preferences.LAST_PATH_DIRECTORY);
			if (importDir != null) {
				Preferences.setProperty(LAST_IMPORT_C_DIRECTORY, importDir);
			}
		}
		pathPanel.setFileChooserProperties("Choose Source Files", LAST_IMPORT_C_DIRECTORY,
			GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		// Set default render to display red if file would not we found
		// Using include paths
		pathPanel.getTable().setDefaultRenderer(String.class, new GTableCellRenderer() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);
				Object value = data.getValue();

				String pathName = (String) value;
				pathName = (pathName == null ? "" : pathName.trim());

				if (pathName.length() == 0 || pathName.startsWith("#")) {
					return label;
				}

				boolean fileExists = true;
				File file = new File(pathName);
				fileExists = file.exists();

				// file not found directly, see if one of the include paths will find the file
				if (!fileExists) {
					fileExists = doesFileExist(pathName, fileExists);
				}

				label.setText(pathName.toString());
				if (!fileExists) {
					label.setForeground(getErrorForegroundColor(data.isSelected()));
				}

				return label;
			}
		});

		tableListener = e -> {
			ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
			item.isChanged = !initialBuild;
			setActionsEnabled();
		};
		tableModel = pathPanel.getTable().getModel();
		tableModel.addTableModelListener(tableListener);

		includePathPanel = new PathnameTablePanel(null, true, false);
		includePathPanel.setBorder(BorderFactory.createTitledBorder("Include paths"));
		includePathPanel.setFileChooserProperties("Choose Source Files", LAST_IMPORT_C_DIRECTORY,
			GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		parsePathTableListener = e -> {
			ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
			item.isChanged = !initialBuild;
			setActionsEnabled();
			pathPanel.getTable().repaint();
		};
		parsePathTableModel = includePathPanel.getTable().getModel();
		parsePathTableModel.addTableModelListener(parsePathTableListener);

		JPanel optionsPanel = new JPanel(new BorderLayout());
		optionsPanel.setBorder(BorderFactory.createTitledBorder("Parse Options"));

		// create options field
		// initialize it with windows options
		parseOptionsField = new JTextArea(5, 70);
		JScrollPane pane = new JScrollPane(parseOptionsField);
		pane.getViewport().setPreferredSize(new Dimension(300, 200));
		optionsPanel.add(pane, BorderLayout.CENTER);

		JPanel archPanel = new JPanel(new BorderLayout());
		archPanel.setBorder(BorderFactory.createTitledBorder("Program Architecture:"));
		archPanel.add(new GLabel(" ", SwingConstants.RIGHT));
		languagePanel = buildLanguagePanel();
		archPanel.add(languagePanel);

		// create Parse Button

		parseButton = new JButton("Parse to Program");
		parseButton.addActionListener(ev -> doParse(false));
		parseButton.setToolTipText("Parse files and add data types to current program");
		addButton(parseButton);

		parseToFileButton = new JButton("Parse to File...");
		parseToFileButton.addActionListener(ev -> doParse(true));
		parseToFileButton.setToolTipText("Parse files and output to archive file");
		addButton(parseToFileButton);

		mainPanel.add(comboPanel, BorderLayout.NORTH);

		includePathPanel.setPreferredSize(new Dimension(pathPanel.getPreferredSize().width, 200));
		JSplitPane optionsPane =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, includePathPanel, optionsPanel);
		optionsPane.setResizeWeight(0.50);

		pathPanel.setPreferredSize(new Dimension(pathPanel.getPreferredSize().width, 200));
		JSplitPane outerPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, pathPanel, optionsPane);
		outerPane.setResizeWeight(0.50);

		mainPanel.add(outerPane, BorderLayout.CENTER);

		mainPanel.add(archPanel, BorderLayout.SOUTH);

		setHelpLocation(new HelpLocation(plugin.getName(), "Parse_C_Source"));

		loadProfile();

		initialBuild = false;
		return mainPanel;
	}

	private boolean doesFileExist(String pathName, boolean fileExists) {
		String[] includePaths = includePathPanel.getPaths();
		for (String path : includePaths) {
			File file = CParserUtils.getFile(path, pathName);
			if (file == null) {
				continue;
			}
			fileExists = file.exists();
			if (fileExists) {
				break;
			}
		}
		return fileExists;
	}

	private JComponent buildLanguagePanel() {
		languageTextField = new JTextField();
		languageTextField.setEditable(false);
		languageTextField.setFocusable(false);

		languageButton = new BrowseButton();
		languageButton.addActionListener(e -> {
			SetLanguageDialog dialog = new SetLanguageDialog(plugin.getTool(), languageIDString,
				compilerIDString, "Select Program Architecture for File DataType Archive");
			LanguageID languageId = dialog.getLanguageDescriptionID();
			CompilerSpecID compilerSpecId = dialog.getCompilerSpecDescriptionID();
			if ((languageId == null) || (compilerSpecId == null)) {
				return;
			}

			String newLanguageIDString = languageId.getIdAsString();
			String newCompilerIDString = compilerSpecId.getIdAsString();

			if (!Objects.equals(newLanguageIDString, languageIDString) ||
				!Objects.equals(newCompilerIDString, compilerIDString)) {
				itemChanged();
			}

			languageIDString = newLanguageIDString;
			compilerIDString = newCompilerIDString;

			updateArchitectureDescription();
		});

		updateArchitectureDescription();

		languageButton.setName("Set Processor Architecture");
		Font font = languageButton.getFont();
		languageButton.setFont(font.deriveFont(Font.BOLD));

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(languageTextField, BorderLayout.CENTER);
		panel.add(languageButton, BorderLayout.EAST);
		return panel;
	}

	private void updateArchitectureDescription() {
		String newProgramArchitectureSummary = "64/32 (primarily for backward compatibility)";

		if (languageIDString != null) {
			StringBuilder buf = new StringBuilder();
			buf.append(languageIDString);
			buf.append("  /  ");
			buf.append(compilerIDString != null ? compilerIDString : "none");
			newProgramArchitectureSummary = buf.toString();
		}

		languageTextField.setText(newProgramArchitectureSummary);
	}

	private void selectionChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.DESELECTED) {
			ComboBoxItem item = (ComboBoxItem) e.getItem();
			if (item.isChanged && !saveAsInProgress && !initialBuild) {
				if (item.isUserDefined) {
					if (OptionDialog.showOptionDialog(rootPanel, "Save Changes to Profile?",
						"Profile " + item.file.getName() +
							" has changed.\nDo you want to save your changes?",
						"Yes", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
						save(item);
					}
				}
				else {
					if (OptionDialog.showOptionDialog(rootPanel, "Save Changes to Another Profile?",
						"You have made changes to the default profile " + item.file.getName() +
							",\nhowever, updating default profiles is not allowed." +
							"\nDo you want to save your changes to another profile?",
						"Yes", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
						saveAs(item);
					}
				}
			}
		}
		if (e.getStateChange() == ItemEvent.SELECTED) {
			loadProfile();
		}
	}

	private void processItemChanged(ComboBoxItem item) {
		if (item.isUserDefined) {
			if (OptionDialog.showOptionDialog(rootPanel, "Save Changes to Profile?",
				"Profile " + item.file.getName() +
					" has changed.\nDo you want to save your changes?",
				"Yes", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
				save(item);
			}
		}
		else {
			if (OptionDialog.showOptionDialog(rootPanel, "Save Changes to Another Profile?",
				"You have made changes to the default profile " + item.file.getName() +
					",\nhowever, updating default profiles is not allowed." +
					"\nDo you want to save your changes to another profile?",
				"Yes", OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
				saveAs(item);
			}
		}
	}

	private void addDocumentListener() {
		if (docListener == null) {
			docListener = new DocumentListener() {
				@Override
				public void changedUpdate(DocumentEvent e) {
					itemChanged();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					itemChanged();
				}

				@Override
				public void removeUpdate(DocumentEvent e) {
					itemChanged();
				}
			};
		}
		parseOptionsField.getDocument().addDocumentListener(docListener);
	}

	private void itemChanged() {
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		if (item == null) {
			return;
		}
		item.isChanged = true;
		setActionsEnabled();
	}

	private void createActions() {
		saveAction = new DockingAction("Save Profile", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				save((ComboBoxItem) comboBox.getSelectedItem());
			}
		};
		saveAction.setEnabled(false);
		Icon icon = Icons.SAVE_ICON;
		String saveGroup = "save";
		saveAction.setMenuBarData(new MenuData(new String[] { "Save" }, icon, saveGroup));
		saveAction.setToolBarData(new ToolBarData(icon, saveGroup));
		saveAction.setDescription("Save profile");
		addAction(saveAction);

		saveAsAction = new DockingAction("Save Profile As", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				saveAs((ComboBoxItem) comboBox.getSelectedItem());
			}
		};
		saveAsAction.setEnabled(true);
		icon = Icons.SAVE_AS_ICON;
		saveAsAction.setMenuBarData(new MenuData(new String[] { "Save As..." }, icon, saveGroup));
		saveAsAction.setToolBarData(new ToolBarData(icon, saveGroup));
		saveAsAction.setDescription("Save profile to new name");
		addAction(saveAsAction);

		clearAction = new DockingAction("Clear Profile", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};

		clearAction.setEnabled(true);
		icon = Icons.CLEAR_ICON;
		String clearGroup = "clear";
		clearAction
				.setMenuBarData(new MenuData(new String[] { "Clear Profile" }, icon, clearGroup));
		clearAction.setToolBarData(new ToolBarData(icon, clearGroup));
		clearAction.setDescription("Clear profile");
		addAction(clearAction);

		refreshAction = new DockingAction("Refresh User Profiles", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				refresh();
			}
		};
		refreshAction.setEnabled(true);
		icon = Icons.REFRESH_ICON;
		String refreshGroup = "refresh";
		refreshAction.setMenuBarData(new MenuData(new String[] { "Refresh" }, icon, refreshGroup));
		refreshAction.setToolBarData(new ToolBarData(icon, refreshGroup));
		refreshAction.setDescription("Refresh list of user profiles");

		addAction(refreshAction);

		deleteAction = new DockingAction("Delete Profile", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				delete();
			}
		};
		deleteAction.setEnabled(false);
		icon = Icons.DELETE_ICON;
		String deleteGroup = "Xdelete";
		deleteAction.setMenuBarData(new MenuData(new String[] { "Delete" }, icon, deleteGroup));
		deleteAction.setToolBarData(new ToolBarData(icon, deleteGroup));
		deleteAction.setDescription("Delete profile");
		addAction(deleteAction);
	}

	private void refresh() {
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		if (item.isChanged) {
			processItemChanged(item);
		}
		comboBox.removeItemListener(comboItemListener);
		itemList.clear();
		comboModel.removeAllElements();
		populateComboBox();
		comboBox.addItemListener(comboItemListener);
		if (itemList.contains(item)) {
			comboBox.setSelectedItem(item);
		}
		else {
			loadProfile();
		}
	}

	private void clear() {
		pathPanel.clear();
		parseOptionsField.setText("");
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		item.isChanged = true;
	}

	private void save(ComboBoxItem item) {
		if (!item.isUserDefined) {
			saveAs(item);
		}
		else {
			writeProfile(item.file);
			item.isChanged = false;
			setActionsEnabled();
		}
	}

	private void saveAs(ComboBoxItem item) {

		InputDialog d = new InputDialog("Enter Profile Name", "Profile Name");
		plugin.getTool().showDialog(d, getComponent());

		String name = d.getValue();
		if (name != null && name.length() > 0) {
			if (!name.endsWith(FILE_EXTENSION)) {
				name = name + FILE_EXTENSION;
			}
			ResourceFile file = new ResourceFile(parentUserFile, name);
			if (file.equals(item.file)) {
				save(item);
				return;
			}

			if (file.exists()) {
				if (OptionDialog.showOptionDialog(rootPanel, "Overwrite Existing File?",
					"The file " + file.getAbsolutePath() +
						" already exists.\nDo you want to overwrite it?",
					"Yes", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
					return;
				}
				file.delete();
			}
			saveAsInProgress = true;
			ComboBoxItem newItem = new ComboBoxItem(file, true);
			if (itemList.contains(newItem)) {
				itemList.remove(newItem);
				comboModel.removeElement(newItem);
			}
			int index = Collections.binarySearch(itemList, newItem, comparator);
			if (index < 0) {
				index = -index - 1;
			}
			itemList.add(index, newItem);
			writeProfile(newItem.file);
			newItem.isChanged = false;
			item.isChanged = false;
			try {
				comboModel.insertElementAt(newItem, index);
				comboBox.setSelectedIndex(index);
			}
			finally {
				saveAsInProgress = false;
			}
			setActionsEnabled();
		}
	}

	private void loadProfile() {
		if (docListener != null) {
			parseOptionsField.getDocument().removeDocumentListener(docListener);
		}
		tableModel.removeTableModelListener(tableListener);
		parsePathTableModel.removeTableModelListener(parsePathTableListener);
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		item.isChanged = false;

		StringBuffer sb = new StringBuffer();
		ArrayList<String> pathList = new ArrayList<>();
		ArrayList<String> includeList = new ArrayList<>();
		String langString = null;
		String compileString = null;
		try {
			BufferedReader br =
				new BufferedReader(new InputStreamReader(item.file.getInputStream()));
			String line = null;
			while ((line = br.readLine()) != null && line.trim().length() > 0) {
				line = line.trim();

				pathList.add(line);
			}

			while ((line = br.readLine()) != null && line.trim().length() > 0) {
				line = line.trim();

				sb.append(line + "\n");
			}

			// get paths
			while ((line = br.readLine()) != null && line.trim().length() > 0) {
				line = line.trim();

				includeList.add(line);
			}

			// get language
			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (line.length() > 0) {
					langString = (line.length() == 0 ? null : line);
					break;
				}
			}

			// get compiler spec
			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (line.length() > 0) {
					compileString = (line.length() == 0 ? null : line);
					break;
				}
			}

			String[] paths = new String[pathList.size()];
			paths = pathList.toArray(paths);
			pathPanel.setPaths(paths);

			String[] incpaths = new String[includeList.size()];
			incpaths = includeList.toArray(incpaths);
			includePathPanel.setPaths(incpaths);

			parseOptionsField.setText(sb.toString());

			languageIDString = langString;

			compilerIDString = compileString;

			updateArchitectureDescription();

			br.close();
		}
		catch (FileNotFoundException e) {
			Msg.showInfo(getClass(), getComponent(), "File Not Found",
				"Could not find file\n" + item.file.getAbsolutePath());
		}
		catch (IOException e) {
			Msg.showError(this, getComponent(), "Error Loading Profile",
				"Exception occurred while reading file\n" + item.file.getAbsolutePath() + ": " + e);
		}
		finally {
			// add a document listener to the options field
			addDocumentListener();
			tableModel.addTableModelListener(tableListener);
			parsePathTableModel.addTableModelListener(parsePathTableListener);
			setActionsEnabled();
		}
	}

	private void writeProfile(ResourceFile outputFile) {
		// write the pathnames
		try {
			BufferedWriter writer =
				new BufferedWriter(new OutputStreamWriter(outputFile.getOutputStream()));
			String[] paths = pathPanel.getPaths();
			for (String path : paths) {
				writer.write(path.trim());
				writer.newLine();
			}
			writer.newLine();
			// write the options
			String optStr = parseOptionsField.getText();
			StringTokenizer st = new StringTokenizer(optStr, "\n");
			while (st.hasMoreTokens()) {
				String tok = st.nextToken();
				writer.write(tok);
				writer.newLine();
			}
			writer.newLine();

			// Write paths
			String[] includePaths = includePathPanel.getPaths();
			for (String path : includePaths) {
				writer.write(path.trim());
				writer.newLine();
			}
			writer.newLine();

			// Write Language ID Spec
			if (languageIDString != null) {
				writer.write(languageIDString);
			}
			writer.newLine();
			writer.newLine();

			// Write Compiler ID Spec
			if (compilerIDString != null) {
				writer.write(compilerIDString);
			}
			writer.newLine();
			writer.newLine();

			writer.close();
		}
		catch (IOException e) {
			Msg.showError(this, getComponent(), "Error Writing Profile",
				"Writing profile " + outputFile.getName() + " failed", e);
		}
	}

	private void delete() {
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		if (item.isUserDefined) {
			if (OptionDialog.showOptionDialog(getComponent(), "Delete Profile?",
				"Are you sure you want to delete profile " + item.getName(), "Delete",
				OptionDialog.QUESTION_MESSAGE) == OptionDialog.OPTION_ONE) {
				item.file.delete();
				itemList.remove(item);
				comboModel.removeElement(item);
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#applyCallback()
	 */
	private void doParse(boolean parseToFile) {
		clearStatusText();
		String options = getParseOptions();
		String[] includePaths = includePathPanel.getPaths();
		String[] paths = pathPanel.getPaths();

		if (paths.length == 0) {
			Msg.showInfo(getClass(), rootPanel, "Source Files Not Specified",
				"Please specify source files to parse.");
			return;
		}

		paths = expandPaths(paths);
		pathPanel.setPaths(paths);

		if (languageIDString == null || compilerIDString == null) {
			Msg.showWarn(getClass(), rootPanel, "Program Architecture not Specified",
				"A Program Architecture must be specified in order to parse to a file.");
			return;
		}

		if (parseToFile) {
			File file = getSaveFile();
			if (file != null) {
				plugin.parse(paths, includePaths, options, languageIDString, compilerIDString,
					file.getAbsolutePath());
			}
		}
		else {
			plugin.parse(paths, includePaths, options, languageIDString, compilerIDString);
		}
	}

	private String[] expandPaths(String[] paths) {
		ArrayList<String> list = new ArrayList<>();

		for (String path : paths) {
			File file = new File(path);
			// process each header file in the directory
			if (file.isDirectory()) {
				IncludeFileFinder includeFileFinder = new IncludeFileFinder(file);
				try {
					List<String> includeFileRoots = includeFileFinder.getIncludeFileRoots(true);
					for (Object element : includeFileRoots) {
						String string = (String) element;
						if (string.endsWith(".h")) {
							list.add(string);
						}
					}
				}
				catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			else {
				list.add(path);
			}
		}

		// convert paths list to String[]
		return list.toArray(new String[0]);
	}

	private void populateComboBox() {
		ResourceFile parent = null;
		try {
			parent = Application.getModuleDataSubDirectory(PROFILE_DIR);
		}
		catch (IOException e) {
			Msg.error(this, "Couldn't find user parser profile dir: " + PROFILE_DIR, e);
		}
		addToComboModel(parent, false);
		parentUserFile = new ResourceFile(plugin.getUserProfileDir());
		addToComboModel(parentUserFile, true);
	}

	private void addToComboModel(ResourceFile parent, boolean isUserDefined) {
		ResourceFile[] children = parent.listFiles();
		List<ResourceFile> sorted = Arrays.asList(children);
		// sort each set of files, system will go first
		// User local files second
		// new files at the end
		Collections.sort(sorted);
		for (ResourceFile resourceFile : sorted) {
			if (resourceFile.getName().startsWith(".")) {
				continue;
			}
			ComboBoxItem item = new ComboBoxItem(resourceFile, isUserDefined);
			comboModel.addElement(item);
			itemList.add(item);
		}
	}

	private void setActionsEnabled() {
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		if (saveAction != null) {
			saveAction.setEnabled(item.isChanged && item.isUserDefined);
			deleteAction.setEnabled(item.isUserDefined);
		}
	}

	private File getSaveFile() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(rootPanel);
		fileChooser.setTitle("Choose Save Archive File");
		fileChooser.setApproveButtonText("Choose Save Archive File");
		fileChooser.setApproveButtonToolTipText("Choose filename for archive");
		fileChooser.setLastDirectoryPreference(Preferences.LAST_EXPORT_DIRECTORY);

		File file = fileChooser.getSelectedFile();
		fileChooser.dispose();
		if (file != null) {
			File parent = file.getParentFile();
			if (parent != null) {
				Preferences.setProperty(Preferences.LAST_EXPORT_DIRECTORY,
					parent.getAbsolutePath());
			}

			String name = file.getName();
			if (!file.getName().endsWith(FileDataTypeManager.SUFFIX)) {
				file = new File(file.getParentFile(), name + FileDataTypeManager.SUFFIX);
			}
			if (file.exists()) {
				if (OptionDialog.showOptionDialog(rootPanel, "Overwrite Existing File?",
					"The file " + file.getAbsolutePath() +
						" already exists.\nDo you want to overwrite it?",
					"Yes", OptionDialog.QUESTION_MESSAGE) != OptionDialog.OPTION_ONE) {
					file = null;
				}
				else {
					try {
						PackedDatabase.delete(file);
					}
					catch (IOException e) {
						Msg.showError(this, mainPanel, "Archive Overwrite Failed", e.getMessage());
						return null;
					}
				}
			}
		}
		return file;
	}

	/**
	 * Called when user selects Cancel Button
	 */
	@Override
	protected void dismissCallback() {
		close();
	}

	void setDialogText(String text) {
		this.setStatusText(text);
	}

	@Override
	public void close() {
		cancelCurrentTask();
		super.close();
	}

	public String getParseOptions() {
		return parseOptionsField.getText();
	}

	class ComboBoxItem {
		private ResourceFile file;
		private boolean isUserDefined;
		private boolean isChanged;

		ComboBoxItem(ResourceFile file, boolean isUserDefined) {
			this.file = file;
			this.isUserDefined = isUserDefined;
		}

		@Override
		public String toString() {
			String name = file.getName();
			return name + (isUserDefined ? "" : " (Default)");
		}

		public String getName() {
			return file.getName();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() == obj.getClass()) {
				ComboBoxItem item = (ComboBoxItem) obj;
				return file.equals(item.file) && isUserDefined == item.isUserDefined;
			}
			return false;
		}

		@Override
		public int hashCode() {
			return Objects.hash(file, isUserDefined);
		}

	}

	private class ComboBoxItemComparator implements Comparator<ComboBoxItem> {
		@Override
		public int compare(ComboBoxItem item1, ComboBoxItem item2) {
			if (item1.isUserDefined == item2.isUserDefined) {
				return item1.getName().compareToIgnoreCase(item2.getName());
			}
			if (!item1.isUserDefined) {
				return -1;
			}
			return 1;
		}
	}

	//==================================================================================================
	// Methods for Testing
	//==================================================================================================

	GhidraComboBox<ParseDialog.ComboBoxItem> getParseComboBox() {
		return comboBox;
	}

	PathnameTablePanel getSourceFiles() {
		return this.pathPanel;
	}

	PathnameTablePanel getIncludePaths() {
		return this.includePathPanel;
	}

	JTextArea getParseOptionsTextField() {
		return this.parseOptionsField;
	}

	JButton getLanguageButton() {
		return this.languageButton;
	}

	JTextField getLanguageText() {
		return this.languageTextField;
	}

	JButton getParseButton() {
		return this.parseButton;
	}

	JButton getParseToFileButton() {
		return this.parseToFileButton;
	}

	ArrayList<ComboBoxItem> getProfiles() {
		return this.itemList;
	}

	ComboBoxItem getCurrentItem() {
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();

		return item;
	}

	ResourceFile getUserProfileParent() {
		return parentUserFile;
	}
}
