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
package ghidra.app.plugin.core.navigation;

import java.util.ArrayList;
import java.util.List;

import ghidra.GhidraOptions;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;

/**
 * Class for managing the options associated with the {@link ProgramStartingLocationPlugin}
 */
public class ProgramStartingLocationOptions implements OptionsChangeListener {

	static final String NAVIGATION_TOPIC = "Navigation";
	public static final String SUB_OPTION = "Starting Program Location";
	public static final String START_LOCATION_TYPE_OPTION = SUB_OPTION + ".Start At: ";
	public static final String START_SYMBOLS_OPTION = SUB_OPTION + ".Start Symbols: ";
	public static final String UNDERSCORE_OPTION = SUB_OPTION + ".Use Underscores:";

	private static final String START_LOCATION_DESCRIPTION =
		"Determines the start location for newly opened programs.\n" +
			"Either lowest address, lowest code address, preferred starting symbol name, or the" +
			"location when last closed.\nEach higher " +
			"option will revert to the next lower option if that option can't be satisfied.";
	private static final String STARTING_SYSMBOLS_DESCRIPTION =
		"A comma separated list of symbol names in preference order. " +
			"(Used when option above is set to \"Preferred Symbol Name\")";
	private static final String SYMBOL_PREFIX_DESCRIPTION =
		"When searching for symbols, also search for the names prepended with \"_\" and \"__\".";

	private static final String DEFAULT_STARTING_SYMBOLS =
		"main, WinMain, libc_start_main, WinMainStartup, start, entry";

	public static enum StartLocationType {
		LOWEST_ADDRESS("Lowest Address"),
		LOWEST_CODE_BLOCK("Lowest Code Block Address"),
		SYMBOL_NAME("Preferred Symbol Name"),
		LAST_LOCATION("Location When Last Closed");

		private String label;

		private StartLocationType(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	private StartLocationType startLocationType;
	private List<String> startSymbols;
	private boolean useUnderscorePrefixes;

	private ToolOptions options;

	public ProgramStartingLocationOptions(PluginTool tool) {
		options = tool.getOptions(GhidraOptions.NAVIGATION_OPTIONS);
		HelpLocation help = new HelpLocation(NAVIGATION_TOPIC, "Starting_Program_Location");

		// set a help location on the group
		Options subOptions = options.getOptions(SUB_OPTION);
		subOptions.setOptionsHelpLocation(help);

		options.registerOption(START_LOCATION_TYPE_OPTION, StartLocationType.LAST_LOCATION, help,
			START_LOCATION_DESCRIPTION);

		options.registerOption(START_SYMBOLS_OPTION, DEFAULT_STARTING_SYMBOLS, help,
			STARTING_SYSMBOLS_DESCRIPTION);

		options.registerOption(UNDERSCORE_OPTION, true, help, SYMBOL_PREFIX_DESCRIPTION);

		startLocationType =
			options.getEnum(START_LOCATION_TYPE_OPTION, StartLocationType.SYMBOL_NAME);

		String symbolNames = options.getString(START_SYMBOLS_OPTION, DEFAULT_STARTING_SYMBOLS);
		startSymbols = parse(symbolNames);

		useUnderscorePrefixes = options.getBoolean(UNDERSCORE_OPTION, true);
		options.addOptionsChangeListener(this);
	}

	private List<String> parse(String symbolNames) {
		List<String> names = new ArrayList<>();
		String[] split = symbolNames.split(",");
		for (String string : split) {
			String trimmed = string.trim();
			if (!trimmed.isBlank()) {
				names.add(trimmed);
			}
		}
		return names;
	}

	/**
	 * Returns the StartLocationType (lowest address, lowest code address, staring symbol, or
	 * last location)
	 * @return the StartLocationType
	 */
	public StartLocationType getStartLocationType() {
		return startLocationType;
	}

	/**
	 * Returns a list of possible starting symbol names. The symbols are returned in order 
	 * of preference.
	 * @return a list of starting symbols. 
	 */
	public List<String> getStartingSymbolNames() {
		return startSymbols;
	}

	/**
	 * Returns true if the list of starting symbol names should also be search for with "_" and
	 * "__" prepended.
	 * @return true if the list of starting symbol names should also be search for with "_" and
	 * "__" prepended.
	 */
	public boolean useUnderscorePrefixes() {
		return useUnderscorePrefixes;
	}

	/**
	 * Removes the options listener
	 */
	public void dispose() {
		options.removeOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions toolOptions, String optionName, Object oldValue,
			Object newValue) {
		if (START_LOCATION_TYPE_OPTION.equals(optionName)) {
			startLocationType = (StartLocationType) newValue;
		}
		else if (START_SYMBOLS_OPTION.equals(optionName)) {
			startSymbols = parse((String) newValue);
		}
		else if (UNDERSCORE_OPTION.equals(optionName)) {
			useUnderscorePrefixes = (Boolean) newValue;
		}
	}
}
