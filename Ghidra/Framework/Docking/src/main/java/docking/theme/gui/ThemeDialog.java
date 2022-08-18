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
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.table.GFilterTable;
import docking.widgets.table.GTable;
import generic.theme.*;
import ghidra.util.MessageType;
import ghidra.util.Swing;

public class ThemeDialog extends DialogComponentProvider {
	private static ThemeDialog INSTANCE;
	private ThemeColorTableModel colorTableModel;
	private ThemeFontTableModel fontTableModel;
	private ThemeIconTableModel iconTableModel;

	private ColorValueEditor colorEditor = new ColorValueEditor(this::colorValueChanged);
	private FontValueEditor fontEditor = new FontValueEditor(this::fontValueChanged);
	private IconValueEditor iconEditor = new IconValueEditor(this::iconValueChanged);

	private JButton saveButton;
	private JButton restoreButton;
	private GhidraComboBox<String> combo;
	private ItemListener comboListener = this::themeComboChanged;
	private ThemeListener listener = new DialogThemeListener();

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
		Gui.addThemeListener(listener);
	}

	private void createActions() {
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
		if (Gui.hasThemeChanges()) {
			int result = OptionDialog.showYesNoCancelDialog(null, "Close Theme Dialog",
				"You have changed the theme.\n Do you want save your changes?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			if (result == OptionDialog.YES_OPTION) {
				return ThemeUtils.saveThemeChanges();
			}
			Gui.restoreThemeValues();
		}
		return true;
	}

	protected void saveCallback() {
		ThemeUtils.saveThemeChanges();
	}

	private void restoreCallback() {
		if (Gui.hasThemeChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Restore Theme Values",
				"Are you sure you want to discard all your changes?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		Gui.restoreThemeValues();
	}

	private void reloadDefaultsCallback() {
		if (Gui.hasThemeChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Reload Ghidra Default Values",
				"This will discard all your theme changes. Continue?");
			if (result == OptionDialog.NO_OPTION) {
				return;
			}
		}
		Gui.reloadGhidraDefaults();
	}

	private void reset() {
		colorTableModel.reloadAll();
		fontTableModel.reloadAll();
		iconTableModel.reloadAll();
		updateButtons();
		updateCombo();
	}

	private void themeComboChanged(ItemEvent e) {

		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}

		if (!ThemeUtils.askToSaveThemeChanges()) {
			Swing.runLater(() -> updateCombo());
			return;
		}
		String themeName = (String) e.getItem();

		Swing.runLater(() -> {
			GTheme theme = Gui.getTheme(themeName);
			Gui.setTheme(theme);
			if (theme.getLookAndFeelType() == LafType.GTK) {
				setStatusText(
					"Warning - Themes using the GTK LookAndFeel do not support changing java component colors, fonts or icons.",
					MessageType.ERROR);
			}
			else {
				setStatusText("");
			}
			colorTableModel.reloadAll();
			fontTableModel.reloadAll();
			iconTableModel.reloadAll();
		});
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
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			ColorValue newValue = (ColorValue) event.getNewValue();
			Gui.setColor(newValue);
		});
	}

	void fontValueChanged(PropertyChangeEvent event) {
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			FontValue newValue = (FontValue) event.getNewValue();
			Gui.setFont(newValue);
		});
	}

	void iconValueChanged(PropertyChangeEvent event) {
		// run later - don't rock the boat in the middle of a listener callback
		Swing.runLater(() -> {
			IconValue newValue = (IconValue) event.getNewValue();
			Gui.setIcon(newValue);
		});
	}

	private void updateButtons() {
		boolean hasChanges = Gui.hasThemeChanges();
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

	@Override
	public void close() {
		Gui.removeThemeListener(listener);
		super.close();
	}

	class DialogThemeListener implements ThemeListener {
		@Override
		public void themeChanged(ThemeEvent event) {
			if (event.haveAllValuesChanged()) {
				reset();
				return;
			}
			if (event.hasAnyColorChanged()) {
				colorTableModel.reloadCurrent();
			}
			if (event.hasAnyFontChanged()) {
				fontTableModel.reloadCurrent();
			}
			if (event.hasAnyIconChanged()) {
				iconTableModel.reloadCurrent();
			}
			updateButtons();
		}
	}
}
