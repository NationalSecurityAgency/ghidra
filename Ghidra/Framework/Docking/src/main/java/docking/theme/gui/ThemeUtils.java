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

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.SelectFromListDialog;
import docking.widgets.dialogs.InputDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import generic.theme.*;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * Some common methods related to saving themes. These are invoked from various places to handle
 * what to do if a change is made that would result in loosing theme changes.
 */
public class ThemeUtils {

	/**
	 * Asks the user if they want to save the current theme changes. If they answer yes, it
	 * will handle several use cases such as whether it gets saved to a new file or
	 * overwrites an existing file.
	 * @param themeManager the theme manager
	 * @return true if the operation was not cancelled
	 */
	public static boolean askToSaveThemeChanges(ThemeManager themeManager) {
		if (themeManager.hasThemeChanges()) {
			int result = OptionDialog.showYesNoCancelDialog(null, "Save Theme Changes?",
				"You have made changes to the theme.\n Do you want to save your changes?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			if (result == OptionDialog.YES_OPTION) {
				return saveThemeChanges(themeManager);
			}
			themeManager.reloadApplicationDefaults();
		}
		return true;
	}

	/**
	 * Saves all current theme changes. Handles several use cases such as requesting a new theme
	 * name and asking to overwrite an existing file.
	 * @param themeManager the theme manager
	 * @return true if the operation was not cancelled
	 */
	public static boolean saveThemeChanges(ThemeManager themeManager) {
		GTheme activeTheme = themeManager.getActiveTheme();
		String name = activeTheme.getName();

		while (!canSaveToName(themeManager, name)) {
			name = getNameFromUser(name);
			if (name == null) {
				return false;
			}
		}
		return saveCurrentValues(themeManager, name);
	}

	/**
	 * Resets the theme to the default, handling the case where the current theme has changes.
	 * @param themeManager the theme manager
	 */
	public static void resetThemeToDefault(ThemeManager themeManager) {
		if (askToSaveThemeChanges(themeManager)) {
			themeManager.setTheme(ThemeManager.getDefaultTheme());
		}
	}

	/**
	 * Imports a theme. Handles the case where there are existing changes to the current theme.
	 * @param themeManager the application ThemeManager
	 */
	public static void importTheme(ThemeManager themeManager) {
		GhidraFileChooser chooser = new GhidraFileChooser(null);
		chooser.setTitle("Choose Theme File");
		chooser.setApproveButtonToolTipText("Select File");
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setFileFilter(ExtensionFileFilter.forExtensions("Ghidra Theme Files",
			GTheme.FILE_EXTENSION, GTheme.ZIP_FILE_EXTENSION));

		File file = chooser.getSelectedFile();
		if (file == null) {
			return;
		}
		importTheme(themeManager, file);
	}

	static void importTheme(ThemeManager themeManager, File themeFile) {
		if (!askToSaveThemeChanges(themeManager)) {
			return;
		}
		GTheme startingTheme = themeManager.getActiveTheme();
		try {
			//
			// By setting the theme, we can let the normal save handle all the edge cases,
			// such as if a theme with that names exists and if so, should it be overwritten?
			// Also, the imported theme may contain default values which we don't want to save. So
			// by going through the usual save mechanism, only values that differ from defaults
			// be saved.
			//
			GTheme imported = GTheme.loadTheme(themeFile);
			themeManager.setTheme(imported);
			if (!saveThemeChanges(themeManager)) {
				themeManager.setTheme(startingTheme);
			}
		}
		catch (IOException e) {
			Msg.showError(ThemeUtils.class, null, "Error Importing Theme File",
				"Error encountered importing file: " + themeFile.getAbsolutePath(), e);
		}

	}

	/**
	 * Exports a theme, prompting the user to pick an file. Also handles dealing with any
	 * existing changes to the current theme.
	 * @param themeManager the ThemeManager that actually does the export
	 */
	public static void exportTheme(ThemeManager themeManager) {
		if (!askToSaveThemeChanges(themeManager)) {
			return;
		}
		boolean hasExternalIcons = !themeManager.getActiveTheme().getExternalIconFiles().isEmpty();
		String message = "Export as zip file? (You are not using any external icons so the zip\n" +
			"file would only contain a single theme file.)";
		if (hasExternalIcons) {
			message =
				"Export as zip file? (You have external icons so a zip file is required if you\n" +
					"want to include the icons in the export.)";
		}
		int result = OptionDialog.showOptionDialog(null, "Export as Zip?", message, "Export Zip",
			"Export File", OptionDialog.QUESTION_MESSAGE);
		if (result == OptionDialog.CANCEL_OPTION) {
			return;
		}
		boolean exportAsZip = result == OptionDialog.OPTION_ONE;

		ExportThemeDialog dialog = new ExportThemeDialog(themeManager, exportAsZip);
		DockingWindowManager.showDialog(dialog);
	}

	/**
	 * Prompts for and deletes a selected theme.
	 * @param themeManager the theme manager
	 */
	public static void deleteTheme(ThemeManager themeManager) {
		List<GTheme> savedThemes = new ArrayList<>(
			themeManager.getAllThemes().stream().filter(t -> t.getFile() != null).toList());
		if (savedThemes.isEmpty()) {
			Msg.showInfo(ThemeUtils.class, null, "Delete Theme", "There are no deletable themes");
			return;
		}

		GTheme selectedTheme = SelectFromListDialog.selectFromList(savedThemes, "Delete Theme",
			"Select theme to delete", t -> t.getName());
		if (selectedTheme == null) {
			return;
		}
		if (themeManager.getActiveTheme().equals(selectedTheme)) {
			Msg.showWarn(ThemeUtils.class, null, "Delete Failed",
				"Cannot delete the active theme.");
			return;
		}

		GTheme fileTheme = selectedTheme;
		int result =
			OptionDialog.showYesNoDialog(null, "Delete Theme: " + fileTheme.getName() + "?",
				"Are you sure you want to delete theme " + fileTheme.getName());
		if (result == OptionDialog.YES_OPTION) {
			themeManager.deleteTheme(fileTheme);
		}
	}

	private static String getNameFromUser(String name) {
		InputDialog inputDialog = new InputDialog("Create Theme", "New Theme Name", name);
		DockingWindowManager.showDialog(inputDialog);
		return inputDialog.getValue();
	}

	private static boolean canSaveToName(ThemeManager themeManager, String name) {
		GTheme existing = themeManager.getTheme(name);
		// if no theme exists with that name, then we are save to save it
		if (existing == null) {
			return true;
		}
		// if the existing theme is a built-in theme, then we definitely can't save to that name
		if (existing instanceof DiscoverableGTheme) {
			return false;
		}
		// if the existing theme with that name has no associated file, we can save it without
		// worrying about overwriting an existing file.
		if (existing.getFile() == null) {
			return true;
		}
		int result = OptionDialog.showYesNoDialog(null, "Overwrite Existing Theme?",
			"Do you want to overwrite the existing theme file for \"" + name + "\"?");
		return result == OptionDialog.YES_OPTION;
	}

	private static boolean saveCurrentValues(ThemeManager themeManager, String themeName) {
		GTheme activeTheme = themeManager.getActiveTheme();
		File file = getSaveFile(themeName);
		if (!file.exists()) {
			Msg.info(ThemeUtils.class, "Saving theme to " + file);
		}

		GTheme newTheme = new GTheme(file, themeName, activeTheme.getLookAndFeelType(),
			activeTheme.useDarkDefaults());
		newTheme.load(themeManager.getNonDefaultValues());
		try {
			newTheme.save();
			themeManager.addTheme(newTheme);
			themeManager.setTheme(newTheme);
		}
		catch (IOException e) {
			Msg.showError(ThemeUtils.class, null, "I/O Error",
				"Error writing theme file: " + newTheme.getFile().getAbsolutePath(), e);
			return false;
		}
		return true;
	}

	private static File getSaveFile(String themeName) {
		File dir = Application.getUserSettingsDirectory();
		File themeDir = new File(dir, ThemeManager.THEME_DIR);
		if (!themeDir.exists()) {
			themeDir.mkdir();
		}
		String cleanedName = themeName.replaceAll(" ", "_") + "." + GTheme.FILE_EXTENSION;
		return new File(themeDir, cleanedName);
	}
}
