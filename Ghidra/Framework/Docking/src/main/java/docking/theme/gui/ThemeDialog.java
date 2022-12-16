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
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.*;

import docking.*;
import docking.action.ActionContextProvider;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import generic.theme.*;
import ghidra.util.*;

/**
 * Primary dialog for editing Themes.
 */
public class ThemeDialog extends DialogComponentProvider {
	private static ThemeDialog INSTANCE;

	private JButton saveButton;
	private JButton restoreButton;
	private GhidraComboBox<String> combo;
	private ItemListener comboListener = this::themeComboChanged;
	private ThemeListener listener = new DialogThemeListener();
	private JTabbedPane tabbedPane;

	private ThemeColorTable colorTable;
	private ThemeFontTable fontTable;
	private ThemeIconTable iconTable;

	private ThemeManager themeManager;

	public ThemeDialog(ThemeManager themeManager) {
		super("Theme Dialog", false);
		this.themeManager = themeManager;
		addWorkPanel(createMainPanel());

		addDismissButton();
		addButton(createSaveButton());
		addButton(createRestoreButton());

		setPreferredSize(1100, 500);
		setRememberSize(false);
		updateButtons();
		createActions();
		Gui.addThemeListener(listener);
		setHelpLocation(new HelpLocation("Theming", "Edit_Theme"));
	}

	private void createActions() {
		DockingAction reloadDefaultsAction = new ActionBuilder("Reload Theme Defaults", getTitle())
				.toolBarIcon(new GIcon("icon.refresh"))
				.helpLocation(new HelpLocation("Theming", "Reload_Ghidra_Defaults"))
				.onAction(e -> reloadDefaultsCallback())
				.build();
		addAction(reloadDefaultsAction);

		DockingAction resetValueAction =
			new ActionBuilder("Restore Value", getTitle()).popupMenuPath("Restore Value")
					.withContext(ThemeTableContext.class)
					.enabledWhen(c -> c.isChanged())
					.popupWhen(c -> true)
					.helpLocation(new HelpLocation("Theming", "Restore_Value"))
					.onAction(c -> c.getThemeValue().installValue(themeManager))
					.build();
		addAction(resetValueAction);
	}

	@Override
	protected void dismissCallback() {
		if (handleChanges()) {
			INSTANCE = null;
			close();
		}
	}

	private boolean handleChanges() {
		if (themeManager.hasThemeChanges()) {
			int result = OptionDialog.showYesNoCancelDialog(null, "Save Theme Changes?",
				"You have changed the theme.\n Do you want to save your changes?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			if (result == OptionDialog.YES_OPTION) {
				return ThemeUtils.saveThemeChanges(themeManager);
			}
			themeManager.restoreThemeValues();
		}
		return true;
	}

	protected void saveCallback() {
		ThemeUtils.saveThemeChanges(themeManager);
	}

	private void restoreCallback() {
		if (themeManager.hasThemeChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Discard Theme Changes?",
				"This will discard all of your theme changes. Continue?");
			if (result != OptionDialog.YES_OPTION) {
				return;
			}
		}
		themeManager.restoreThemeValues();
	}

	private void reloadDefaultsCallback() {
		if (themeManager.hasThemeChanges()) {
			int result = OptionDialog.showYesNoDialog(null, "Reload Default Theme Values?",
				"This will discard all of your theme changes. Continue?");
			if (result != OptionDialog.YES_OPTION) {
				return;
			}
		}
		themeManager.reloadApplicationDefaults();
	}

	private void reset() {
		colorTable.reloadAll();
		fontTable.reloadAll();
		iconTable.reloadAll();
		updateButtons();
		updateCombo();
	}

	private void themeComboChanged(ItemEvent e) {

		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}

		if (!ThemeUtils.askToSaveThemeChanges(themeManager)) {
			Swing.runLater(() -> updateCombo());
			return;
		}

		String themeName = (String) e.getItem();
		Swing.runLater(() -> {
			GTheme theme = themeManager.getTheme(themeName);
			themeManager.setTheme(theme);
			if (theme.getLookAndFeelType() == LafType.GTK) {
				setStatusText(
					"Warning - Themes using the GTK LookAndFeel do not support changing java " +
						"component colors, fonts or icons.",
					MessageType.ERROR);
			}
			else {
				setStatusText("");
			}
			colorTable.reloadAll();
			fontTable.reloadAll();
			iconTable.reloadAll();
		});
	}

	private void updateButtons() {
		boolean hasChanges = themeManager.hasThemeChanges();
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
		Set<GTheme> supportedThemes = themeManager.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);
		combo.removeItemListener(comboListener);
		combo.setModel(new DefaultComboBoxModel<String>(new Vector<String>(themeNames)));
		combo.setSelectedItem(themeManager.getActiveTheme().getName());
		combo.addItemListener(comboListener);
	}

	private Component buildThemeCombo() {
		JPanel panel = new JPanel();
		Set<GTheme> supportedThemes = themeManager.getSupportedThemes();
		List<String> themeNames =
			supportedThemes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);

		combo = new GhidraComboBox<>(themeNames);
		combo.setSelectedItem(themeManager.getActiveTheme().getName());
		combo.addItemListener(comboListener);

		panel.add(new JLabel("Theme: "), BorderLayout.WEST);
		panel.add(combo);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		return panel;
	}

	private Component buildTabedTables() {
		tabbedPane = new JTabbedPane();
		colorTable = new ThemeColorTable(themeManager);
		fontTable = new ThemeFontTable(themeManager);
		iconTable = new ThemeIconTable(themeManager);
		tabbedPane.add("Colors", colorTable);
		tabbedPane.add("Fonts", fontTable);
		tabbedPane.add("Icons", iconTable);
		return tabbedPane;
	}

	private JButton createRestoreButton() {
		restoreButton = new JButton("Restore");
		restoreButton.setMnemonic('R');
		restoreButton.setName("Restore");
		restoreButton.addActionListener(e -> restoreCallback());
		restoreButton.setToolTipText("Restores all previous values to current theme");
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

	/**
	 * Edits the current theme
	 * @param themeManager the application ThemeManager
	 */
	public static void editTheme(ThemeManager themeManager) {
		if (INSTANCE != null) {
			INSTANCE.toFront();
			return;
		}
		INSTANCE = new ThemeDialog(themeManager);
		DockingWindowManager.showDialog(INSTANCE);

	}

	@Override
	public void close() {
		Gui.removeThemeListener(listener);
		super.close();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContextProvider contextProvider =
			(ActionContextProvider) tabbedPane.getSelectedComponent();
		return contextProvider.getActionContext(event);
	}

	private class DialogThemeListener implements ThemeListener {
		@Override
		public void themeChanged(ThemeEvent event) {
			if (event.haveAllValuesChanged()) {
				reset();
				return;
			}
			if (event.hasAnyColorChanged()) {
				colorTable.reloadCurrent();
			}
			if (event.hasAnyFontChanged()) {
				fontTable.reloadCurrent();
			}
			if (event.hasAnyIconChanged()) {
				iconTable.reloadCurrent();
			}
			updateButtons();
		}
	}
}
