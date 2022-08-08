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

public class ThemeUtils {

	public static boolean askToSaveThemeChanges() {
		if (Gui.hasThemeChanges()) {
			int result = OptionDialog.showYesNoCancelDialog(null, "Save Theme Changes?",
				"You have made changes to the theme.\n Do you want save your changes?");
			if (result == OptionDialog.CANCEL_OPTION) {
				return false;
			}
			if (result == OptionDialog.YES_OPTION) {
				return ThemeUtils.saveThemeChanges();
			}
			Gui.reloadGhidraDefaults();
		}
		return true;
	}

	/**
	 * Saves all current theme changes
	 * @return true if the operation was not cancelled.
	 */
	public static boolean saveThemeChanges() {
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

	public static void resetThemeToDefault() {
		if (askToSaveThemeChanges()) {
			Gui.setTheme(Gui.getDefaultTheme());
		}
	}

	public static void importTheme() {
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
		importTheme(file);
	}

	static void importTheme(File themeFile) {
		if (!ThemeUtils.askToSaveThemeChanges()) {
			return;
		}
		GTheme startingTheme = Gui.getActiveTheme();
		try {
			FileGTheme imported;
			if (themeFile.getName().endsWith(GTheme.ZIP_FILE_EXTENSION)) {
				imported = new ZipGTheme(themeFile);
			}
			else if (themeFile.getName().endsWith(GTheme.FILE_EXTENSION)) {
				imported = new FileGTheme(themeFile);
			}
			else {
				Msg.showError(ThemeUtils.class, null, "Error Importing Theme",
					"Imported File must end in either " + GTheme.FILE_EXTENSION + " or " +
						GTheme.ZIP_FILE_EXTENSION);
				return;
			}
			Gui.setTheme(imported);
			if (!ThemeUtils.saveThemeChanges()) {
				Gui.setTheme(startingTheme);
			}
		}
		catch (IOException e) {
			Msg.showError(ThemeUtils.class, null, "Error Importing Theme File",
				"Error encountered importing file: " + themeFile.getAbsolutePath(), e);
		}

	}

	public static void exportTheme() {
		if (!ThemeUtils.askToSaveThemeChanges()) {
			return;
		}
		boolean hasExternalIcons = !Gui.getActiveTheme().getExternalIconFiles().isEmpty();
		String message =
			"Export as zip file? (You are not using any external icons so the zip\n" +
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

		ExportThemeDialog dialog = new ExportThemeDialog(exportAsZip);
		DockingWindowManager.showDialog(dialog);
	}

	public static void deleteTheme() {
		List<GTheme> savedThemes = new ArrayList<>(
			Gui.getAllThemes().stream().filter(t -> t instanceof FileGTheme).toList());
		if (savedThemes.isEmpty()) {
			Msg.showInfo(ThemeUtils.class, null, "Delete Theme", "There are no deletable themes");
			return;
		}

		GTheme selectedTheme = SelectFromListDialog.selectFromList(savedThemes, "Delete Theme",
			"Select theme to delete", t -> t.getName());
		if (selectedTheme == null) {
			return;
		}
		if (Gui.getActiveTheme().equals(selectedTheme)) {
			Msg.showWarn(ThemeUtils.class, null, "Delete Failed",
				"Can't delete the current theme.");
			return;
		}
		FileGTheme fileTheme = (FileGTheme) selectedTheme;
		int result = OptionDialog.showYesNoDialog(null, "Delete Theme: " + fileTheme.getName(),
			"Are you sure you want to delete theme " + fileTheme.getName());
		if (result == OptionDialog.YES_OPTION) {
			Gui.deleteTheme(fileTheme);
		}
	}

	private static String getNameFromUser(String name) {
		InputDialog inputDialog = new InputDialog("Create Theme", "New Theme Name", name);
		DockingWindowManager.showDialog(inputDialog);
		return inputDialog.getValue();
	}

	private static boolean canSaveToName(String name) {
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

	private static boolean saveCurrentValues(String themeName) {
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
			Msg.showError(ThemeUtils.class, null, "I/O Error",
				"Error writing theme file: " + newTheme.getFile().getAbsolutePath(), e);
			return false;
		}

		return true;

	}

	private static File getSaveFile(String themeName) {
		File dir = Application.getUserSettingsDirectory();
		File themeDir = new File(dir, Gui.THEME_DIR);
		if (!themeDir.exists()) {
			themeDir.mkdir();
		}
		String cleanedName = themeName.replaceAll(" ", "_") + "." + GTheme.FILE_EXTENSION;
		return new File(themeDir, cleanedName);
	}
}
