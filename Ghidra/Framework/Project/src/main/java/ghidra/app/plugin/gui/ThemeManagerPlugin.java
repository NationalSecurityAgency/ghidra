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
package ghidra.app.plugin.gui;

import docking.action.builder.ActionBuilder;
import docking.theme.gui.ThemeEditorDialog;
import docking.theme.gui.ThemeUtils;
import generic.theme.GTheme;
import generic.theme.ThemeManager;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.ApplicationLevelOnlyPlugin;
import ghidra.framework.main.UtilityPluginPackage;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = UtilityPluginPackage.NAME,
	category = PluginCategoryNames.FRAMEWORK,
	shortDescription = "Manages themes for the Ghidra GUI",
	description = "Adds actions and options to manage Themes within Ghidra. " +
			"This plugin is available only in the Ghidra Project Window."
)
//@formatter:on
public class ThemeManagerPlugin extends Plugin implements ApplicationLevelOnlyPlugin {

	private ThemeManager themeManager;

	public ThemeManagerPlugin(PluginTool tool) {
		super(tool);
		themeManager = ThemeManager.getInstance();
	}

	@Override
	protected void init() {
		String owner = getName();
		String group = "theme";

		new ActionBuilder("Switch Theme", owner).menuPath("Edit", "Theme", "Switch...")
				.menuGroup(group, "1")
				.helpLocation(new HelpLocation("Theming", "Switch_Theme"))
				.onAction(e -> switchTheme())
				.buildAndInstall(tool);

		new ActionBuilder("Configure", owner).menuPath("Edit", "Theme", "Configure")
				.menuGroup(group, "2")
				.helpLocation(new HelpLocation("Theming", "Edit_Theme"))
				.onAction(e -> configure())
				.buildAndInstall(tool);

		new ActionBuilder("New Theme", owner).menuPath("Edit", "Theme", "New...")
				.menuGroup(group, "3")
				.helpLocation(new HelpLocation("Theming", "New_Theme"))
				.onAction(e -> createNewTheme())
				.buildAndInstall(tool);

		new ActionBuilder("Import Theme", owner).menuPath("Edit", "Theme", "Import...")
				.menuGroup(group, "4")
				.helpLocation(new HelpLocation("Theming", "Import_Theme"))
				.onAction(e -> ThemeUtils.importTheme(themeManager))
				.buildAndInstall(tool);

		new ActionBuilder("Export Theme", owner).menuPath("Edit", "Theme", "Export...")
				.menuGroup(group, "5")
				.helpLocation(new HelpLocation("Theming", "Export_Theme"))
				.onAction(e -> ThemeUtils.exportTheme(themeManager))
				.buildAndInstall(tool);

		new ActionBuilder("Delete Theme", owner).menuPath("Edit", "Theme", "Delete...")
				.menuGroup(group, "6")
				.helpLocation(new HelpLocation("Theming", "Delete_Theme"))
				.onAction(e -> ThemeUtils.deleteTheme(themeManager))
				.buildAndInstall(tool);

	}

	private void switchTheme() {
		ThemeChooserDialog dialog = new ThemeChooserDialog(themeManager);
		tool.showDialog(dialog);
	}

	private void createNewTheme() {
		if (!ThemeUtils.askToSaveThemeChanges(themeManager)) {
			return;  // user cancelled
		}

		CreateThemeDialog dialog = new CreateThemeDialog(themeManager);
		GTheme newTheme = dialog.getNewTheme(tool, "New Theme");
		if (newTheme != null) {
			themeManager.addTheme(newTheme);
			themeManager.setTheme(newTheme);
			configure();
		}
	}

	private void configure() {
		ThemeEditorDialog dialog = ThemeEditorDialog.getRunningInstance();
		if (dialog != null) {
			dialog.toFront();
			return;
		}

		ThemeEditorDialog.editTheme(themeManager);
	}

	@Override
	protected boolean canClose() {
		if (themeManager.hasThemeChanges()) {
			return ThemeUtils.askToSaveThemeChanges(themeManager);
		}
		return true;
	}
}
