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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.TableModel;

import docking.*;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.pathmanager.PathnameTablePanel;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.framework.preferences.Preferences;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import resources.Icons;
import resources.ResourceManager;

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
class ParseDialog extends DialogComponentProvider {
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
	private ArrayList<ComboBoxItem> itemList;
	private ComboBoxItemComparator comparator;
	private ResourceFile parentUserFile;
	private GhidraFileChooser fileChooser;
	private boolean saveAsInProgress;

	ParseDialog(CParserPlugin plugin) {
		super("Parse C Source", false);

		this.plugin = plugin;
		itemList = new ArrayList<>();
		comparator = new ComboBoxItemComparator();
		addWorkPanel(buildMainPanel());
		addDismissButton();
		createActions();
		setActionsEnabled();
	}

	void writeState(SaveState saveState) {
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
		saveState.putString(CURRENT_PROFILE, item.file.getName());
		saveState.putBoolean(USER_DEFINED, item.isUserDefined);
	}

	void readState(SaveState saveState) {
		String name = saveState.getString(CURRENT_PROFILE, null);
		if (name != null) {
			boolean userDefined = saveState.getBoolean(USER_DEFINED, true);
			for (int i = 0; i < itemList.size(); i++) {
				ComboBoxItem item = itemList.get(i);
				if (userDefined == item.isUserDefined && name.equals(item.file.getName())) {
					comboBox.setSelectedIndex(i);
					break;
				}
			}
		}
	}

	void closeProfile() {
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
			importDir = Preferences.getProperty(Preferences.LAST_IMPORT_DIRECTORY);
			if (importDir != null) {
				Preferences.setProperty(LAST_IMPORT_C_DIRECTORY, importDir);
			}
		}
		pathPanel.setFileChooserProperties("Choose Source Files", LAST_IMPORT_C_DIRECTORY,
			GhidraFileChooserMode.FILES_AND_DIRECTORIES, true,
			new ExtensionFileFilter(new String[] { "h" }, "C Header Files"));

		tableListener = e -> {
			ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();
			item.isChanged = true;
			setActionsEnabled();
		};
		tableModel = pathPanel.getTable().getModel();
		tableModel.addTableModelListener(tableListener);

		JPanel optionsPanel = new JPanel(new BorderLayout());
		optionsPanel.setBorder(BorderFactory.createTitledBorder("Parse Options"));

		// create options field
		// initialize it with windows options
		parseOptionsField = new JTextArea(5, 70);
		JScrollPane pane = new JScrollPane(parseOptionsField);
		pane.getViewport().setPreferredSize(new Dimension(300, 200));
		optionsPanel.add(pane, BorderLayout.CENTER);

		// create Parse Button

		parseButton = new JButton("Parse to Program");
		parseButton.addActionListener(ev -> doParse(false));
		parseButton.setToolTipText("Parse files and add data types to current program");
		addButton(parseButton);

		parseToFileButton = new JButton("Parse to File...");
		parseToFileButton.addActionListener(ev -> doParse(true));
		parseToFileButton.setToolTipText("Parse files and output to archive file");
		addButton(parseToFileButton);

		pathPanel.setPreferredSize(new Dimension(pathPanel.getPreferredSize().width, 200));
		JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, pathPanel, optionsPanel);
		splitPane.setResizeWeight(0.50);
		mainPanel.add(comboPanel, BorderLayout.NORTH);
		mainPanel.add(splitPane, BorderLayout.CENTER);

		setHelpLocation(new HelpLocation(plugin.getName(), "Parse_C_Source"));

		loadProfile();

		return mainPanel;
	}

	private void selectionChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.DESELECTED) {
			ComboBoxItem item = (ComboBoxItem) e.getItem();
			if (item.isChanged && !saveAsInProgress) {
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

	private void loadProfile() {
		if (docListener != null) {
			parseOptionsField.getDocument().removeDocumentListener(docListener);
		}
		tableModel.removeTableModelListener(tableListener);
		ComboBoxItem item = (ComboBoxItem) comboBox.getSelectedItem();

		StringBuffer sb = new StringBuffer();
		ArrayList<String> pathList = new ArrayList<>();
		try {
			BufferedReader br =
				new BufferedReader(new InputStreamReader(item.file.getInputStream()));
			String line = null;
			while ((line = br.readLine()) != null) {
				line = line.trim();
				if (line.startsWith("-") || (line.length() == 0 && sb.length() > 0)) {
					// this is a compiler directive
					sb.append(line + "\n");
				}
				else if (line.length() > 0) {
					File f = new File(line);
					pathList.add(f.getPath());
				}
			}
			String[] paths = new String[pathList.size()];
			paths = pathList.toArray(paths);
			pathPanel.setPaths(paths);
			parseOptionsField.setText(sb.toString());

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
			setActionsEnabled();
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
		ImageIcon icon = ResourceManager.loadImage("images/disk.png");
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
		icon = ResourceManager.loadImage("images/disk_save_as.png");
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
		icon = ResourceManager.loadImage("images/erase16.png");
		String clearGroup = "clear";
		clearAction.setMenuBarData(
			new MenuData(new String[] { "Clear Profile" }, icon, clearGroup));
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
		icon = ResourceManager.loadImage("images/edit-delete.png");
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
			saveAsInProgress = true;
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

	private void writeProfile(ResourceFile outputFile) {
		// write the pathnames
		try {
			BufferedWriter writer =
				new BufferedWriter(new OutputStreamWriter(outputFile.getOutputStream()));
			String[] paths = pathPanel.getPaths();
			for (String path : paths) {
				writer.write(path);
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
		String[] paths = pathPanel.getPaths();

		if (paths.length == 0) {
			Msg.showInfo(getClass(), rootPanel, "Source Files Not Specified",
				"Please specify source files to parse.");
			return;
		}

		paths = expandPaths(paths);
		pathPanel.setPaths(paths);

		if (parseToFile) {
			File file = getSaveFile();
			if (file != null) {
				plugin.parse(paths, options, file.getAbsolutePath());
			}
		}
		else {
			plugin.parse(paths, options);
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
		for (ResourceFile resourceFile : children) {
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
		if (fileChooser == null) {
			fileChooser = new GhidraFileChooser(rootPanel);
			String dir = Preferences.getProperty(Preferences.LAST_EXPORT_DIRECTORY);
			if (dir != null) {
				File file = new File(dir);
				fileChooser.setCurrentDirectory(file);
				fileChooser.setTitle("Choose Save Archive File");
				fileChooser.setApproveButtonText("Choose Save Archive File");
				fileChooser.setApproveButtonToolTipText("Choose filename for archive");
			}
		}
		fileChooser.rescanCurrentDirectory();
		File file = fileChooser.getSelectedFile();
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

	private class ComboBoxItem {
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
			final int prime = 31;
			int result = 1;
			result = prime * result + ((file == null) ? 0 : file.hashCode());
			result = prime * result + (isUserDefined ? 1231 : 1237);
			return result;
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
}
