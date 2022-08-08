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
package docking.theme.gui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.theme.*;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.*;
import ghidra.framework.Application;
import ghidra.util.*;
import ghidra.util.filechooser.ExtensionFileFilter;

public class ThemeDialog extends DialogComponentProvider {
	private static ThemeDialog INSTANCE;
	private ThemeColorTableModel colorTableModel;
	private ThemeFontTableModel fontTableModel;
	private ThemeIconTableModel iconTableModel;

	private ColorValueEditor colorEditor = new ColorValueEditor(this::colorValueChanged);
	private FontValueEditor fontEditor = new FontValueEditor(this::fontValueChanged);
	private IconValueEditor iconEditor = new IconValueEditor(this::iconValueChanged);

	// stores the original value for ids whose value has changed
	private GThemeValueMap changedValuesMap = new GThemeValueMap();
	private JButton saveButton;
	private JButton restoreButton;
	private GhidraComboBox<String> combo;
	private ItemListener comboListener = this::themeComboChanged;

	public ThemeDialog() {
		super("Theme Dialog", false);
		addWorkPanel(createMainPanel());

		addDismissButton();
		addButton(createSaveButton());
		addButton(createRestoreButton());

		setPreferredSize(1100, 500);
		setRememberSize(false);
		updateButtons();
		createActions();
	}

	private void createActions() {
		DockingAction importAction =
			new ActionBuilder("Import Theme", getTitle()).toolBarIcon(new GIcon("icon.navigate.in"))
					.onAction(e -> importTheme())
					.build();
		addAction(importAction);

		DockingAction exportAction = new ActionBuilder("Export Theme", getTitle())
				.toolBarIcon(new GIcon("icon.navigate.out"))
				.onAction(e -> exportTheme())
				.build();
		addAction(exportAction);

		DockingAction reloadDefaultsAction = new ActionBuilder("Reload Ghidra Defaults", getTitle())
				.toolBarIcon(new GIcon("icon.refresh"))
				.onAction(e -> reloadDefaultsCallback())
				.build();
		addAction(reloadDefaultsAction);
	}

	@Override
	protected void dismissCallback() {
		if (handleChanges()) {
			INSTANCE = null;
			close();
		}
	}

	private boolean handleChanges() {
		if (hasChanges()) {
			int result = OptionDialog.showYesNoCancelDialog(null, "Close Theme Dialog",
				"You have changed the theme.\n Do you want save your changes?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			if (result == OptionDialog.YES_OPTION) {
				return save();
			}
			Gui.reloadGhidraDefaults();
		}
		return true;
	}

	protected void saveCallback() {
		save();
		reset();
	}

	private void restoreCallback() {
		if (hasChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Restore Theme Values",
				"Are you sure you want to discard all your changes?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		Gui.restoreThemeValues();
		reset();
	}

	private void reloadDefaultsCallback() {
		if (hasChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Reload Ghidra Default Values",
				"This will discard all your theme changes. Continue?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		Gui.reloadGhidraDefaults();
		reset();
	}

	private void reset() {
		changedValuesMap.clear();
		colorTableModel.reloadAll();
		fontTableModel.reloadAll();
		iconTableModel.reloadAll();
		updateButtons();
		updateCombo();
	}

	/**
	 * Saves all current theme changes
	 * @return true if the operation was not cancelled.
	 */
	private boolean save() {
		GTheme activeTheme = Gui.getActiveTheme();

		String name = activeTheme.getName();

		while (!canSaveToName(name)) {
			name = getNameFromUser(name);
			if (name == null) {
				return false;
			}
		}
		return saveCurrentValues(name);
	}

	private String getNameFromUser(String name) {
		InputDialog inputDialog = new InputDialog("Create Theme", "New Theme Name", name);
		DockingWindowManager.showDialog(inputDialog);
		return inputDialog.getValue();
	}

	private boolean canSaveToName(String name) {
		GTheme existing = Gui.getTheme(name);
		if (existing == null) {
			return true;
		}
		if (existing instanceof FileGTheme fileTheme) {
			int result = OptionDialog.showYesNoDialog(null, "Overwrite Existing Theme?",
				"Do you want to overwrite the existing theme file for \"" + name + "\"?");
			if (result == OptionDialog.YES_OPTION) {
				return true;
			}
		}
		return false;
	}

	private boolean saveCurrentValues(String themeName) {
		GTheme activeTheme = Gui.getActiveTheme();
		File file = getSaveFile(themeName);

		FileGTheme newTheme = new FileGTheme(file, themeName, activeTheme.getLookAndFeelType(),
			activeTheme.useDarkDefaults());
		newTheme.load(Gui.getNonDefaultValues());
		try {
			newTheme.save();
			Gui.addTheme(newTheme);
			Gui.setTheme(newTheme);
		}
		catch (IOException e) {
			Msg.showError(this, null, "I/O Error",
				"Error writing theme file: " + newTheme.getFile().getAbsolutePath(), e);
			return false;
		}

		return true;

	}

	private File getSaveFile(String themeName) {
		File dir = Application.getUserSettingsDirectory();
		File themeDir = new File(dir, Gui.THEME_DIR);
		if (!themeDir.exists()) {
			themeDir.mkdir();
		}
		String cleanedName = themeName.replaceAll(" ", "_") + GTheme.FILE_EXTENSION;
		return new File(themeDir, cleanedName);
	}

	private void importTheme() {
		if (!handleChanges()) {
			return;
		}
		GTheme startingTheme = Gui.getActiveTheme();
		GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
		chooser.setTitle("Choose Theme File");
		chooser.setApproveButtonToolTipText("Select File");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setSelectedFileFilter(
			new ExtensionFileFilter("Ghidra Theme Files", GTheme.FILE_EXTENSION));
		File file = chooser.getSelectedFile();
		if (file == null) {
			return;
		}
		try {
			FileGTheme imported = new FileGTheme(file);
			Gui.setTheme(imported);
			if (!save()) {
				Gui.setTheme(startingTheme);
			}
		}
		catch (IOException e) {
			Msg.showError(this, null, "Error Importing Theme File",
				"Error encountered importing file: " + file.getAbsolutePath(), e);
		}
		reset();
	}

	private void exportTheme() {
		ExportThemeDialog dialog = new ExportThemeDialog();
		DockingWindowManager.showDialog(dialog);
	}

	private void themeComboChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.SELECTED) {
			String themeName = (String) e.getItem();

			Swing.runLater(() -> {
				GTheme theme = Gui.getTheme(themeName);
				Gui.setTheme(theme);
				if (theme.getLookAndFeelType() == LafType.GTK) {
					setStatusText(
						"Warning - Themes using the GTK LookAndFeel do not support changing java component colors, fonts or icons. You can still change Ghidra values.",
						MessageType.ERROR, true);
				}
				else if (theme.getLookAndFeelType() == LafType.NIMBUS) {
					setStatusText(
						"Warning - Themes using the Nimbus LookAndFeel do not support changing java component fonts or icons. You can still change Ghidra values.",
						MessageType.ERROR, true);
				}
				else {
					setStatusText("");
				}
				changedValuesMap.clear();
				colorTableModel.reloadAll();
				fontTableModel.reloadAll();
				iconTableModel.reloadAll();
			});
		}
	}

	private boolean hasChanges() {
		return !changedValuesMap.isEmpty();
	}

	protected void editColor(ColorValue value) {
		colorEditor.editValue(value);
	}

	protected void editFont(FontValue value) {
		fontEditor.editValue(value);
	}

	protected void editIcon(IconValue value) {
		iconEditor.editValue(value);
	}

	void colorValueChanged(PropertyChangeEvent event) {
		ColorValue oldValue = (ColorValue) event.getOldValue();
		ColorValue newValue = (ColorValue) event.getNewValue();
		updateChangedValueMap(oldValue, newValue);
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			Gui.setColor(newValue);
			colorTableModel.reloadCurrent();
		});
	}

	void fontValueChanged(PropertyChangeEvent event) {
		FontValue oldValue = (FontValue) event.getOldValue();
		FontValue newValue = (FontValue) event.getNewValue();
		updateChangedValueMap(oldValue, newValue);
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			Gui.setFont(newValue);
			fontTableModel.reloadCurrent();
		});
	}

	void iconValueChanged(PropertyChangeEvent event) {
		IconValue oldValue = (IconValue) event.getOldValue();
		IconValue newValue = (IconValue) event.getNewValue();
		updateChangedValueMap(oldValue, newValue);
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			Gui.setIcon(newValue);
			iconTableModel.reloadCurrent();
		});
	}

	private void updateChangedValueMap(ColorValue oldValue, ColorValue newValue) {
		ColorValue originalValue = changedValuesMap.getColor(oldValue.getId());
		if (originalValue == null) {
			changedValuesMap.addColor(oldValue);
		}
		else if (originalValue.equals(newValue)) {
			// if restoring the original color, remove it from the map of changes
			changedValuesMap.removeColor(oldValue.getId());
		}
		updateButtons();
	}

	private void updateChangedValueMap(FontValue oldValue, FontValue newValue) {
		FontValue originalValue = changedValuesMap.getFont(oldValue.getId());
		if (originalValue == null) {
			changedValuesMap.addFont(oldValue);
		}
		else if (originalValue.equals(newValue)) {
			// if restoring the original color, remove it from the map of changes
			changedValuesMap.removeFont(oldValue.getId());
		}
		updateButtons();
	}

	private void updateChangedValueMap(IconValue oldValue, IconValue newValue) {
		IconValue originalValue = changedValuesMap.getIcon(oldValue.getId());
		if (originalValue == null) {
			changedValuesMap.addIcon(oldValue);
		}
		else if (originalValue.equals(newValue)) {
			// if restoring the original color, remove it from the map of changes
			changedValuesMap.removeFont(oldValue.getId());
		}
		updateButtons();
	}

	private void updateButtons() {
		boolean hasChanges = hasChanges();
		saveButton.setEnabled(hasChanges);
		restoreButton.setEnabled(hasChanges);
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel();

		panel.setLayout(new BorderLayout());
		panel.add(buildControlPanel(), BorderLayout.NORTH);
		panel.add(buildTabedTables());
		return panel;
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildThemeCombo(), BorderLayout.WEST);
		panel.setName("gthemePanel");
		return panel;
	}

	private void updateCombo() {
		Set<GTheme> supportedThemes = Gui.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);
		combo.removeItemListener(comboListener);
		combo.setModel(new DefaultComboBoxModel<String>(new Vector<String>(themeNames)));
		combo.setSelectedItem(Gui.getActiveTheme().getName());
		combo.addItemListener(comboListener);
	}

	private Component buildThemeCombo() {
		JPanel panel = new JPanel();
		Set<GTheme> supportedThemes = Gui.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);

		combo = new GhidraComboBox<>(themeNames);
		combo.setSelectedItem(Gui.getActiveTheme().getName());
		combo.addItemListener(comboListener);

		panel.add(new JLabel("Theme: "), BorderLayout.WEST);
		panel.add(combo);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		return panel;
	}

	private Component buildTabedTables() {
		JTabbedPane tabbedPane = new JTabbedPane();
		tabbedPane.add("Colors", buildColorTable());
		tabbedPane.add("Fonts", buildFontTable());
		tabbedPane.add("Icons", buildIconTable());
		return tabbedPane;
	}

	private JComponent buildFontTable() {
		fontTableModel = new ThemeFontTableModel();
		GFilterTable<FontValue> filterTable = new GFilterTable<>(fontTableModel);
		GTable table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					FontValue fontValue = filterTable.getSelectedRowObject();
					if (fontValue != null) {
						editFont(fontValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					FontValue value = filterTable.getItemAt(e.getPoint());

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Font".equals(identifier) || "Id".equals(identifier)) {
						editFont(value);
					}
				}
			}
		});

		return filterTable;

	}

	private JComponent buildIconTable() {
		iconTableModel = new ThemeIconTableModel();
		GFilterTable<IconValue> filterTable = new GFilterTable<>(iconTableModel);
		GTable table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					IconValue iconValue = filterTable.getSelectedRowObject();
					if (iconValue != null) {
						editIcon(iconValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					IconValue value = filterTable.getItemAt(e.getPoint());

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Icon".equals(identifier) || "Id".equals(identifier)) {
						editIcon(value);
					}
				}
			}
		});

		return filterTable;

	}

	private JComponent buildColorTable() {
		colorTableModel = new ThemeColorTableModel();

		GFilterTable<ColorValue> filterTable = new GFilterTable<>(colorTableModel);
		GTable table = filterTable.getTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

		table.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					ColorValue colorValue = filterTable.getSelectedRowObject();
					if (colorValue != null) {
						editColor(colorValue);
					}
					e.consume();
				}
			}
		});

		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					ColorValue value = filterTable.getItemAt(e.getPoint());

					int col = filterTable.getColumn(e.getPoint());
					TableColumn column = table.getColumnModel().getColumn(col);
					Object identifier = column.getIdentifier();
					if ("Current Color".equals(identifier) || "Id".equals(identifier)) {
						editColor(value);
					}
				}
			}
		});

		return filterTable;
	}

	private JButton createRestoreButton() {
		restoreButton = new JButton("Restore");
		restoreButton.setMnemonic('R');
		restoreButton.setName("Restore");
		restoreButton.addActionListener(e -> restoreCallback());
		restoreButton.setToolTipText("Restores all values to current theme");
		return restoreButton;
	}

	private JButton createSaveButton() {
		saveButton = new JButton("Save");
		saveButton.setMnemonic('S');
		saveButton.setName("Save");
		saveButton.addActionListener(e -> saveCallback());
		saveButton.setToolTipText("Saves changed values to a new Theme");
		return saveButton;
	}

	public static void editTheme() {
		if (INSTANCE != null) {
			INSTANCE.toFront();
			return;
		}
		INSTANCE = new ThemeDialog();
		DockingWindowManager.showDialog(INSTANCE);

	}
}
