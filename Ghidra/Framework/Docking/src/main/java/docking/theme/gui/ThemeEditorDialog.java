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
public class ThemeEditorDialog extends DialogComponentProvider {
	private static ThemeEditorDialog INSTANCE;

	private JButton saveButton;
	private GhidraComboBox<LafType> combo;
	private ItemListener comboListener = this::lafTypeComboChanged;
	private ThemeListener listener = new DialogThemeListener();
	private JTabbedPane tabbedPane;

	private ThemeColorTable colorTable;
	private ThemeFontTable fontTable;
	private ThemeIconTable iconTable;
	private ThemeColorTree colorTree;
	private ThemeColorTable paletteTable;

	private ThemeManager themeManager;
	private GThemeValuesCache valuesCache;

	public ThemeEditorDialog(ThemeManager themeManager) {
		super("Configure Theme: " + themeManager.getActiveTheme().getName(), false);
		this.themeManager = themeManager;
		addWorkPanel(createMainPanel());

		addDismissButton();
		addButton(createSaveButton());

		setPreferredSize(1100, 500);
		setRememberSize(false);
		updateButtons();
		createActions();
		Gui.addThemeListener(listener);
		setHelpLocation(new HelpLocation("Theming", "Edit_Theme"));
	}

	private void createActions() {

		DockingAction incrementFontsAction = new ActionBuilder("Increment All Fonts", getTitle())
				.toolBarIcon(new GIcon("icon.theme.font.increment"))
				.description("Increases all font sizes by 1")
				.helpLocation(new HelpLocation("Theming", "Increment_Fonts"))
				.onAction(e -> adjustFonts(1))
				.build();
		addAction(incrementFontsAction);

		DockingAction decrementFontsAction = new ActionBuilder("Decrement All Fonts", getTitle())
				.toolBarIcon(new GIcon("icon.theme.font.decrement"))
				.toolBarGroup("A")
				.description("Decreases all font sizes by 1")
				.helpLocation(new HelpLocation("Theming", "Decrement_Fonts"))
				.onAction(e -> adjustFonts(-1))
				.build();
		addAction(decrementFontsAction);

		DockingAction reloadDefaultsAction = new ActionBuilder("Restore Theme Values", getTitle())
				.toolBarIcon(new GIcon("icon.refresh"))
				.toolBarGroup("B")
				.description("Reloads default values from the filesystem and restores the " +
					"original theme values.")
				.helpLocation(new HelpLocation("Theming", "Reload_Theme"))
				.onAction(e -> restoreCallback())
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

		DockingAction showSystemValuesAction =
			new ActionBuilder("Toggle Show System Values", getTitle())
					.popupMenuPath("Toggle Show System Values")
					.withContext(ThemeTableContext.class)
					.popupWhen(c -> true)
					.helpLocation(new HelpLocation("Theming", "Toggle_Show_System_Values"))
					.onAction(context -> toggleSystemValues(context))
					.build();
		addAction(showSystemValuesAction);
	}

	private void toggleSystemValues(ThemeTableContext<?> context) {
		ThemeTable themeTable = context.getThemeTable();
		boolean isShowing = themeTable.isShowingSystemValues();
		themeTable.setShowSystemValues(!isShowing);
	}

	private void adjustFonts(int amount) {
		themeManager.adjustFonts(amount);
	}

	@Override
	protected void dismissCallback() {
		if (handleChanges()) {
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
			int result = OptionDialog.showYesNoDialog(null, "Restore Theme Values?",
				"This will discard all of your theme changes. Continue?");
			if (result != OptionDialog.YES_OPTION) {
				return;
			}
		}
		themeManager.restoreThemeValues();
	}

	private void reset() {
		colorTree.rebuild();
		colorTable.reloadAll();
		paletteTable.reloadAll();
		fontTable.reloadAll();
		iconTable.reloadAll();
		updateButtons();
	}

	private void resetSelectedLookAndFeel() {
		Swing.runLater(() -> {

			LafType lafType = themeManager.getLookAndFeelType();
			Object currentItem = combo.getSelectedItem();
			if (lafType == currentItem) {
				return;
			}

			try {
				combo.removeItemListener(comboListener);
				combo.setSelectedItem(lafType);
			}
			finally {
				combo.addItemListener(comboListener);
			}
		});
	}

	private void lafTypeComboChanged(ItemEvent e) {

		if (e.getStateChange() != ItemEvent.SELECTED) {
			return;
		}

		LafType lafType = (LafType) e.getItem();
		LafType currentLafType = themeManager.getLookAndFeelType();
		if (currentLafType == lafType) {
			return;
		}

		if (!themeManager.hasThemeValueChanges()) {
			// This allows the user to toggle the them lafType repeatedly without having to save, as
			// long as they have not changed any other theme values.
			setLookAndFeel(lafType);
			return;
		}

		//@formatter:off
		int result = OptionDialog.showOptionDialog(null, "Discard Changes?",
			"Changing the Look and Feel type will cause you to lose your changes.\n" +
			"If you would like to keep your changes, cancel this dialog and then save the theme\n" +
			"Would you like to continue?",
			"Lose Changes");
		//@formatter:on
		if (result == OptionDialog.CANCEL_OPTION) {
			resetSelectedLookAndFeel();
			return;
		}

		setLookAndFeel(lafType);
	}

	private void setLookAndFeel(LafType lafType) {

		themeManager.setLookAndFeel(lafType, lafType.usesDarkDefaults());
		if (lafType == LafType.GTK) {
			setStatusText(
				"Warning - Themes using the GTK LookAndFeel do not support changing java " +
					"component colors, fonts or icons.",
				MessageType.WARNING);
		}
		else {
			setStatusText("");
		}
		colorTree.rebuild();
		colorTable.reloadAll();
		paletteTable.reloadAll();
		fontTable.reloadAll();
		iconTable.reloadAll();
	}

	private void updateButtons() {
		boolean hasChanges = themeManager.hasThemeChanges();
		saveButton.setEnabled(hasChanges);
	}

	private JComponent createMainPanel() {
		JPanel panel = new JPanel();

		panel.setLayout(new BorderLayout());
		panel.add(buildControlPanel(), BorderLayout.NORTH);
		panel.add(buildTabedTables());
		panel.getAccessibleContext().setAccessibleName("Theme Editor");
		return panel;
	}

	private Component buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		panel.add(buildThemeCombo(), BorderLayout.WEST);
		panel.setName("gthemePanel");
		panel.getAccessibleContext().setAccessibleName("Theme");
		return panel;
	}

	private Component buildThemeCombo() {
		JPanel panel = new JPanel();
		List<LafType> lafs = getSupportedLookAndFeels();
		combo = new GhidraComboBox<>(lafs);
		combo.setSelectedItem(themeManager.getActiveTheme().getLookAndFeelType());
		combo.addItemListener(comboListener);

		panel.add(new JLabel("Look And Feel: "), BorderLayout.WEST);
		panel.add(combo);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 10, 0, 10));
		panel.getAccessibleContext().setAccessibleName("Themes");
		return panel;
	}

	private List<LafType> getSupportedLookAndFeels() {
		LafType[] lafTypes = LafType.values();
		Comparator<LafType> comparator =
			(a, b) -> a.getDisplayString().compareTo(b.getDisplayString());
		return Arrays.stream(lafTypes).filter(laf -> laf.isSupported()).sorted(comparator).toList();
	}

	private Component buildTabedTables() {
		tabbedPane = new JTabbedPane();

		valuesCache = new GThemeValuesCache(themeManager);

		colorTable = new ThemeColorTable(themeManager, valuesCache);
		colorTable.getAccessibleContext().setAccessibleName("Colors");
		iconTable = new ThemeIconTable(themeManager, valuesCache);
		iconTable.getAccessibleContext().setAccessibleName("Icons");
		fontTable = new ThemeFontTable(themeManager, valuesCache);
		fontTable.getAccessibleContext().setAccessibleName("Fonts");
		colorTree = new ThemeColorTree(themeManager);
		colorTree.getAccessibleContext().setAccessibleName("Color");
		paletteTable = new ThemeColorPaletteTable(themeManager, valuesCache);
		paletteTable.getAccessibleContext().setAccessibleName("Color Palette");

		tabbedPane.add("Colors", colorTable);
		tabbedPane.add("Fonts", fontTable);
		tabbedPane.add("Icons", iconTable);
		tabbedPane.add("Color Tree", colorTree);
		tabbedPane.add("Palette", paletteTable);
		tabbedPane.getAccessibleContext().setAccessibleName("Theme Details");
		return tabbedPane;
	}

	private JButton createSaveButton() {
		saveButton = new JButton("Save");
		saveButton.setMnemonic('S');
		saveButton.setName("Save");
		saveButton.getAccessibleContext().setAccessibleName("Save");
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
		INSTANCE = new ThemeEditorDialog(themeManager);
		DockingWindowManager.showDialog(INSTANCE);
	}

	public static ThemeEditorDialog getRunningInstance() {
		return INSTANCE;
	}

	@Override
	public void close() {
		Gui.removeThemeListener(listener);
		super.close();
		INSTANCE = null;
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		ActionContextProvider contextProvider =
			(ActionContextProvider) tabbedPane.getSelectedComponent();
		return contextProvider.getActionContext(event);
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

	private class DialogThemeListener implements ThemeListener {
		@Override
		public void themeChanged(ThemeEvent event) {
			valuesCache.clear();
			if (event.haveAllValuesChanged()) {
				reset();
				return;
			}
			if (event.hasAnyColorChanged()) {
				colorTable.reloadCurrent();
				colorTree.rebuild();
				paletteTable.reloadCurrent();
			}
			if (event.hasAnyFontChanged()) {
				fontTable.reloadCurrent();
			}
			if (event.hasAnyIconChanged()) {
				iconTable.reloadCurrent();
			}

			updateButtons();
			resetSelectedLookAndFeel();
		}
	}
}
