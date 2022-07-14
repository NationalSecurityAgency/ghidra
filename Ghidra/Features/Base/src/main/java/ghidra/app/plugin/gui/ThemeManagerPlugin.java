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

import java.util.*;
import java.util.stream.Collectors;

import docking.action.builder.ActionBuilder;
import docking.options.editor.StringWithChoicesEditor;
import docking.theme.GTheme;
import docking.theme.Gui;
import docking.theme.gui.GThemeDialog;
import docking.tool.ToolConstants;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Manages themes for the Ghdira GUI",
	description = "Adds actions and options to manage Themes within Ghidra. " +
			"This plugin is available only in the Ghidra Project Window."
)
//@formatter:on
public class ThemeManagerPlugin extends Plugin implements FrontEndOnly, OptionsChangeListener {

	public final static String THEME_OPTIONS_NAME = "Theme";
	private final static String OPTIONS_TITLE = ToolConstants.TOOL_OPTIONS;

	private boolean issuedRestartNotification;
//	private static boolean issuedPreferredDarkThemeLafNotification;

	public ThemeManagerPlugin(PluginTool tool) {
		super(tool);

		SystemUtilities.assertTrue(tool instanceof FrontEndTool,
			"Plugin added to the wrong type of tool");
		initThemeOptions();
	}

	@Override
	protected void init() {

		new ActionBuilder("Show Properties", getName()).menuPath("Edit", "Theme Properties")
				.onAction(e -> showThemeProperties())
				.buildAndInstall(tool);

	}

	private void showThemeProperties() {
		GThemeDialog dialog = new GThemeDialog();
		tool.showDialog(dialog);
	}

	private void initThemeOptions() {

		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

		GTheme activeTheme = Gui.getActiveTheme();
		Set<GTheme> themes = Gui.getSupportedThemes();
		List<String> themeNames =
			themes.stream().map(t -> t.getName()).collect(Collectors.toList());
		Collections.sort(themeNames);

		opt.registerOption(THEME_OPTIONS_NAME, OptionType.STRING_TYPE, activeTheme.getName(),
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Look_And_Feel"),
			"Set the look and feel for Ghidra.  After you change the " +
				"look and feel, you will have to restart Ghidra to see the effect.",
			new StringWithChoicesEditor(themeNames));

		opt.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(THEME_OPTIONS_NAME)) {
			String newThemeName = (String) newValue;
			if (!newThemeName.equals(Gui.getActiveTheme().getName())) {
				issueRestartNeededMessage();
			}

			saveLookAndFeel((String) newValue);
		}

	}

	private void saveLookAndFeel(String themeName) {
		Set<GTheme> allThemes = Gui.getAllThemes();
		for (GTheme theme : allThemes) {
			if (theme.getName().equals(themeName)) {
				Gui.saveThemeToPreferneces(theme);
			}
		}
	}

	private void issueRestartNeededMessage() {
		if (issuedRestartNotification) {
			return;
		}

		issuedRestartNotification = true;
		Msg.showInfo(getClass(), null, "Look And Feel Updated",
			"The new Look and Feel will take effect \nafter you exit and restart Ghidra.");
	}

	@Override
	public void dispose() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.removeOptionsChangeListener(this);
		super.dispose();
	}
}
