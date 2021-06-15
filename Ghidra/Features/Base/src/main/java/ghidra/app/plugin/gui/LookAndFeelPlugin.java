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

import static ghidra.docking.util.DockingWindowsLookAndFeelUtils.*;

import java.util.List;

import docking.options.editor.StringWithChoicesEditor;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.docking.util.DockingWindowsLookAndFeelUtils;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Sets the GUI look and feel",
	description = "Adds a Tool Option to allow the user to adjust the GUI look and feel settings. " +
			"Ghidra may have to be restarted to see the effect. This plugin is available " +
			"only in the Ghidra Project Window."
)
//@formatter:on
public class LookAndFeelPlugin extends Plugin implements FrontEndOnly, OptionsChangeListener {

	private String selectedLookAndFeel;
	private boolean useInvertedColors;
	public final static String LOOK_AND_FEEL_NAME = "Swing Look And Feel";
	private final static String USE_INVERTED_COLORS_NAME = "Use Inverted Colors";
	private final static String OPTIONS_TITLE = ToolConstants.TOOL_OPTIONS;

	private static boolean issuedLafNotification;
	private static boolean issuedPreferredDarkThemeLafNotification;

	public LookAndFeelPlugin(PluginTool tool) {
		super(tool);

		SystemUtilities.assertTrue(tool instanceof FrontEndTool,
			"Plugin added to the wrong type of tool");
		initLookAndFeelOptions();
	}

	private void initLookAndFeelOptions() {

		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

		selectedLookAndFeel = getInstalledLookAndFeelName();
		List<String> lookAndFeelNames = getLookAndFeelNames();
		opt.registerOption(LOOK_AND_FEEL_NAME, OptionType.STRING_TYPE, selectedLookAndFeel,
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Look_And_Feel"),
			"Set the look and feel for Ghidra.  After you change the " +
				"look and feel, you will have to restart Ghidra to see the effect.",
			new StringWithChoicesEditor(lookAndFeelNames));
		selectedLookAndFeel = opt.getString(LOOK_AND_FEEL_NAME, selectedLookAndFeel);

		useInvertedColors = getUseInvertedColorsPreference();
		opt.registerOption(USE_INVERTED_COLORS_NAME, OptionType.BOOLEAN_TYPE, useInvertedColors,
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Use_Inverted_Colors"),
			"Indicates to invert all drawn colors.   This provides the ability to create an " +
				"effective 'Dark Theme' appearance.  (Note: you may have to change your " +
				"Look and Feel to achieve the best rendering.)\n\n" +
				"<FONT SIZE='7'><B>PROTOTYPE</B></FONT> - This feature is an example prototype " +
				"and contains many known rendering issues that cause some widgets to be " +
				"<U>unreadable</U>.");
		useInvertedColors = opt.getBoolean(USE_INVERTED_COLORS_NAME, useInvertedColors);

		opt.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {

		if (optionName.equals(LOOK_AND_FEEL_NAME)) {
			String newLookAndFeel = (String) newValue;
			if (!newLookAndFeel.equals(selectedLookAndFeel)) {
				issueLaFNotification();
			}

			saveLookAndFeel((String) newValue);
		}

		if (optionName.equals(USE_INVERTED_COLORS_NAME)) {
			boolean newUseInvertedColors = (Boolean) newValue;
			if (newUseInvertedColors != useInvertedColors) {

				issueLaFNotification();
			}

			useInvertedColors = newUseInvertedColors;
			Preferences.setProperty(USE_INVERTED_COLORS_KEY, Boolean.toString(useInvertedColors));
			Preferences.store();

			if (useInvertedColors) {
				issuePreferredDarkThemeLaFNotification();
			}
		}
	}

	private void saveLookAndFeel(String lookAndFeelName) {
		selectedLookAndFeel = lookAndFeelName;
		Preferences.setProperty(LAST_LOOK_AND_FEEL_KEY, selectedLookAndFeel);
		Preferences.store();
	}

	private void issuePreferredDarkThemeLaFNotification() {
		if (issuedPreferredDarkThemeLafNotification) {
			return;
		}

		issuedPreferredDarkThemeLafNotification = true;

		if (DockingWindowsLookAndFeelUtils.METAL_LOOK_AND_FEEL.equals(selectedLookAndFeel)) {
			return;
		}

		int choice = OptionDialog.showYesNoDialog(null, "Change Look and Feel?", "The '" +
			USE_INVERTED_COLORS_NAME + "' setting works best with the " +
			"'Metal' Look and Feel.\nWould you like to switch to that Look and Feel upon restart?");
		if (choice == OptionDialog.YES_OPTION) {
			SystemUtilities.runSwingLater(() -> {

				saveLookAndFeel(DockingWindowsLookAndFeelUtils.METAL_LOOK_AND_FEEL);
			});
		}
	}

	private void issueLaFNotification() {
		if (issuedLafNotification) {
			return;
		}

		issuedLafNotification = true;
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
