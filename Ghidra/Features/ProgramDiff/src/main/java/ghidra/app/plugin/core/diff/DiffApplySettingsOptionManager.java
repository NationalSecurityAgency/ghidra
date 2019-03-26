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
package ghidra.app.plugin.core.diff;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.util.ProgramMergeFilter;
import ghidra.util.HelpLocation;

/**
 * Manages the options for the Diff apply settings.
 */
class DiffApplySettingsOptionManager {

	public static final String DIFF_OPTIONS = "Diff";
	public static final String DIFF_APPLY_SETTINGS_OPTIONS = "Default Apply Settings";

	private static final int PROGRAM_CONTEXT = 1 << 0;
	private static final int BYTES = 1 << 1;
	private static final int CODE_UNITS = 1 << 2;
	private static final int REFERENCES = 1 << 3;
	private static final int PLATE_COMMENTS = 1 << 4;
	private static final int PRE_COMMENTS = 1 << 5;
	private static final int EOL_COMMENTS = 1 << 6;
	private static final int REPEATABLE_COMMENTS = 1 << 7;
	private static final int POST_COMMENTS = 1 << 8;
	private static final int SYMBOLS = 1 << 9;
	private static final int BOOKMARKS = 1 << 10;
	private static final int PROPERTIES = 1 << 11;
	private static final int FUNCTIONS = 1 << 12;
	private static final int FUNCTION_TAGS = 1 << 13;

	private static final String OPTION_PROGRAM_CONTEXT = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Program Context";
	private static final String OPTION_BYTES = DIFF_APPLY_SETTINGS_OPTIONS + Options.DELIMITER +
		"Bytes";
	private static final String OPTION_CODE_UNITS = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Code Units";
	private static final String OPTION_REFERENCES = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "References";
	private static final String OPTION_PLATE_COMMENTS = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Plate Comments";
	private static final String OPTION_PRE_COMMENTS = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Pre Comments";
	private static final String OPTION_EOL_COMMENTS = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "End Of Line Comments";
	private static final String OPTION_REPEATABLE_COMMENTS = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Repeatable Comments";
	private static final String OPTION_POST_COMMENTS = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Post Comments";
	private static final String OPTION_SYMBOLS = DIFF_APPLY_SETTINGS_OPTIONS + Options.DELIMITER +
		"Labels";
	private static final String OPTION_BOOKMARKS = DIFF_APPLY_SETTINGS_OPTIONS + Options.DELIMITER +
		"Bookmarks";
	private static final String OPTION_PROPERTIES = DIFF_APPLY_SETTINGS_OPTIONS +
		Options.DELIMITER + "Properties";
	private static final String OPTION_FUNCTIONS = DIFF_APPLY_SETTINGS_OPTIONS + Options.DELIMITER +
		"Functions";
	private static final String OPTION_FUNCTION_TAGS =
		DIFF_APPLY_SETTINGS_OPTIONS + Options.DELIMITER + "Function Tags";

//	public static final String MERGE = "Merge";
//	public static final String MERGE_SYMBOLS_1 = "Merge";
//	public static final String MERGE_SYMBOLS_2 = "Merge & Set Primary";

	public static enum REPLACE_CHOICE {
		IGNORE("Ignore"), REPLACE("Replace");
		private String description;

		REPLACE_CHOICE(String description) {
			this.description = description;
		}

		@Override
		public String toString() {
			return description;
		}
	}

	public static enum MERGE_CHOICE {
		IGNORE("Ignore"), REPLACE("Replace"), MERGE("Merge");
		private String description;

		MERGE_CHOICE(String description) {
			this.description = description;
		}

		@Override
		public String toString() {
			return description;
		}
	}

	// Special choice for symbols in that if merged, should the primary attribute be set.
	public static enum SYMBOL_MERGE_CHOICE {
		IGNORE("Ignore"),
		REPLACE("Replace"),
		MERGE_DONT_SET_PRIMARY("Merge"),
		MERGE_AND_SET_PRIMARY("Merge & Set Primary");
		private String description;

		SYMBOL_MERGE_CHOICE(String description) {
			this.description = description;
		}

		@Override
		public String toString() {
			return description;
		}
	}

	private Plugin plugin;
	private HelpLocation help;
	private String HELP_TOPIC = "Diff";

	/**
	 * Creates a new option manager for Diff apply settings.
	 * @param plugin the plugin that owns this options manager.
	 */
	DiffApplySettingsOptionManager(Plugin plugin) {
		this.plugin = plugin;
		init();
	}

	/**
	 * Initializes class variables for this option manager and gets the default options.
	 */
	private void init() {

		help = new HelpLocation(HELP_TOPIC, "DiffApplySettingsToolOptions");
		Options options = plugin.getTool().getOptions(DIFF_OPTIONS);
		options.setOptionsHelpLocation(help);

		// Set the help strings
		options.registerOption(
			OPTION_PROGRAM_CONTEXT,
			REPLACE_CHOICE.REPLACE,
			help,
			getReplaceDescription("program context register value",
				"program context register values"));
		options.registerOption(OPTION_BYTES, REPLACE_CHOICE.REPLACE, help,
			getReplaceDescription("byte", "bytes"));

		options.registerOption(OPTION_CODE_UNITS, REPLACE_CHOICE.REPLACE, help,
			getReplaceDescription("code unit", "code units"));

		options.registerOption(OPTION_REFERENCES, REPLACE_CHOICE.REPLACE, help,
			getReplaceDescription("reference", "references"));
		options.registerOption(OPTION_PLATE_COMMENTS, MERGE_CHOICE.MERGE, help,
			getMergeDescription("plate comment", "plate comments"));
		options.registerOption(OPTION_PRE_COMMENTS, MERGE_CHOICE.MERGE, help,
			getMergeDescription("pre-comment", "pre-comments"));
		options.registerOption(OPTION_EOL_COMMENTS, MERGE_CHOICE.MERGE, help,
			getMergeDescription("end of line comment", "end of line comments"));
		options.registerOption(OPTION_REPEATABLE_COMMENTS, MERGE_CHOICE.MERGE, help,
			getMergeDescription("repeatable comment", "repeatable comments"));
		options.registerOption(OPTION_POST_COMMENTS, MERGE_CHOICE.MERGE, help,
			getMergeDescription("post comment", "post comments"));
		options.registerOption(OPTION_SYMBOLS, SYMBOL_MERGE_CHOICE.MERGE_AND_SET_PRIMARY, help,
			getSymbolDescription());
		options.registerOption(OPTION_BOOKMARKS, REPLACE_CHOICE.REPLACE, help,
			getReplaceDescription("bookmark", "bookmarks"));
		options.registerOption(OPTION_PROPERTIES, REPLACE_CHOICE.REPLACE, help,
			getReplaceDescription("property", "properties"));
		options.registerOption(OPTION_FUNCTIONS, REPLACE_CHOICE.REPLACE, help,
			getReplaceDescription("function", "functions"));
		options.registerOption(OPTION_FUNCTION_TAGS, MERGE_CHOICE.MERGE, help,
			getReplaceDescription("function tag", "function tags"));

		getDefaultApplyFilter();
	}

	/**
	 * Gets the merge filter for the default apply settings.
	 * @return merge filter indicating default apply settings.
	 */
	public ProgramMergeFilter getDefaultApplyFilter() {
		PluginTool tool = plugin.getTool();
		Options options = tool.getOptions(DIFF_OPTIONS);

//		case PROGRAM_CONTEXT:
//		case BYTES:
//		case CODE_UNITS:
//		case REFERENCES:
//		case BOOKMARKS:
//		case PROPERTIES:
//		case FUNCTIONS:

		// Get the current settings as options
		REPLACE_CHOICE programContext =
			options.getEnum(OPTION_PROGRAM_CONTEXT, REPLACE_CHOICE.REPLACE);
		REPLACE_CHOICE bytes = options.getEnum(OPTION_BYTES, REPLACE_CHOICE.REPLACE);
		REPLACE_CHOICE codeUnits = options.getEnum(OPTION_CODE_UNITS, REPLACE_CHOICE.REPLACE);
		REPLACE_CHOICE references = options.getEnum(OPTION_REFERENCES, REPLACE_CHOICE.REPLACE);
		MERGE_CHOICE plateComments = options.getEnum(OPTION_PLATE_COMMENTS, MERGE_CHOICE.MERGE);
		MERGE_CHOICE preComments = options.getEnum(OPTION_PRE_COMMENTS, MERGE_CHOICE.MERGE);
		MERGE_CHOICE eolComments = options.getEnum(OPTION_EOL_COMMENTS, MERGE_CHOICE.MERGE);
		MERGE_CHOICE repeatableComments =
			options.getEnum(OPTION_REPEATABLE_COMMENTS, MERGE_CHOICE.MERGE);
		MERGE_CHOICE postComments = options.getEnum(OPTION_POST_COMMENTS, MERGE_CHOICE.MERGE);
		SYMBOL_MERGE_CHOICE symbols =
			options.getEnum(OPTION_SYMBOLS, SYMBOL_MERGE_CHOICE.MERGE_AND_SET_PRIMARY);
		REPLACE_CHOICE bookmarks = options.getEnum(OPTION_BOOKMARKS, REPLACE_CHOICE.REPLACE);
		REPLACE_CHOICE properties = options.getEnum(OPTION_PROPERTIES, REPLACE_CHOICE.REPLACE);
		REPLACE_CHOICE functions = options.getEnum(OPTION_FUNCTIONS, REPLACE_CHOICE.REPLACE);
		MERGE_CHOICE functionTags = options.getEnum(OPTION_FUNCTION_TAGS, MERGE_CHOICE.MERGE);

		// Convert the options to a merge filter.
		ProgramMergeFilter filter = new ProgramMergeFilter();
		filter.setFilter(ProgramMergeFilter.PROGRAM_CONTEXT, programContext.ordinal());
		filter.setFilter(ProgramMergeFilter.BYTES, bytes.ordinal());
		filter.setFilter(ProgramMergeFilter.CODE_UNITS, codeUnits.ordinal());
		filter.setFilter(ProgramMergeFilter.REFERENCES, references.ordinal());
		filter.setFilter(ProgramMergeFilter.PLATE_COMMENTS, plateComments.ordinal());
		filter.setFilter(ProgramMergeFilter.PRE_COMMENTS, preComments.ordinal());
		filter.setFilter(ProgramMergeFilter.EOL_COMMENTS, eolComments.ordinal());
		filter.setFilter(ProgramMergeFilter.REPEATABLE_COMMENTS, repeatableComments.ordinal());
		filter.setFilter(ProgramMergeFilter.POST_COMMENTS, postComments.ordinal());
		filter.setFilter(ProgramMergeFilter.SYMBOLS,
			convertSymbolMergeChoiceToMergeChoice(symbols).ordinal());
		filter.setFilter(ProgramMergeFilter.BOOKMARKS, bookmarks.ordinal());
		filter.setFilter(ProgramMergeFilter.PROPERTIES, properties.ordinal());
		filter.setFilter(ProgramMergeFilter.FUNCTIONS, functions.ordinal());
		filter.setFilter(ProgramMergeFilter.FUNCTION_TAGS, functionTags.ordinal());
		filter.setFilter(ProgramMergeFilter.PRIMARY_SYMBOL,
			convertSymbolMergeChoiceToReplaceChoiceForPrimay(symbols).ordinal());

		return filter;
	}

	private String getReplaceDescription(String settingName, String pluralName) {
		return getBaseDescription(settingName) + "\n" + getIgnoreDescription(settingName) + "\n" +
			getReplaceDescription(pluralName);
	}

	private String getMergeDescription(String settingName, String pluralName) {
		return getBaseDescription(settingName) + "\n" + getIgnoreDescription(settingName) + "\n" +
			getReplaceDescription(pluralName) + "\n" + getMergeDescription(pluralName);
	}

	private String getBaseDescription(String settingName) {
		return "The default Diff setting for applying " + settingName + " differences.";
	}

	private String getIgnoreDescription(String settingName) {
		return " Ignore - Don't apply " + settingName + " differences.";
	}

	private String getReplaceDescription(String pluralName) {
		return " Replace - Replace " + pluralName + " in the program with those from program 2.";
	}

	private String getMergeDescription(String pluralName) {
		return " Merge - Merge " + pluralName + " from program 2 into the current program.";
	}

	private String getSymbolDescription() {
		String settingName = "label";
		String pluralName = "labels";
		return getBaseDescription(settingName) + "\n" + getIgnoreDescription(settingName) + "\n" +
			getReplaceDescription(pluralName) + "\n" + " " + "Merge" + " - Merge " + pluralName +
			" from program 2 into the current program and don't change which " + settingName +
			" is primary.\n" + " " + "Merge & Set Primary" + " - Merge " + pluralName +
			" from program 2 into the current program and set the primary " + settingName +
			" as it is in program 2, if possible.";
	}

	/**
	 * Saves the indicated merge filter as the default apply settings.
	 * @param defaultApplyFilter merge filter indicating default apply settings.
	 */
	public void saveDefaultApplyFilter(ProgramMergeFilter newDefaultApplyFilter) {
		PluginTool tool = plugin.getTool();
		Options options = tool.getOptions(DIFF_OPTIONS);

		saveReplaceOption(options, newDefaultApplyFilter, PROGRAM_CONTEXT);
		saveReplaceOption(options, newDefaultApplyFilter, BYTES);
		saveReplaceOption(options, newDefaultApplyFilter, REFERENCES);
		saveReplaceOption(options, newDefaultApplyFilter, BOOKMARKS);
		saveReplaceOption(options, newDefaultApplyFilter, PROPERTIES);
		saveReplaceOption(options, newDefaultApplyFilter, FUNCTIONS);

		saveMergeOption(options, newDefaultApplyFilter, PLATE_COMMENTS);
		saveMergeOption(options, newDefaultApplyFilter, PRE_COMMENTS);
		saveMergeOption(options, newDefaultApplyFilter, EOL_COMMENTS);
		saveMergeOption(options, newDefaultApplyFilter, REPEATABLE_COMMENTS);
		saveMergeOption(options, newDefaultApplyFilter, POST_COMMENTS);

		saveMergeOption(options, newDefaultApplyFilter, FUNCTION_TAGS);

		saveCodeUnitReplaceOption(options, newDefaultApplyFilter, CODE_UNITS);
		saveSymbolMergeOption(options, newDefaultApplyFilter, SYMBOLS);

		tool.setConfigChanged(true);
	}

	private void saveCodeUnitReplaceOption(Options options, ProgramMergeFilter defaultApplyFilter,
			int setting) {
		int filter =
			(defaultApplyFilter.getFilter(ProgramMergeFilter.INSTRUCTIONS) >= defaultApplyFilter.getFilter(ProgramMergeFilter.DATA)) ? ProgramMergeFilter.INSTRUCTIONS
					: ProgramMergeFilter.DATA;
		REPLACE_CHOICE defaultSetting = REPLACE_CHOICE.REPLACE;
		REPLACE_CHOICE optionSetting = options.getEnum(getOptionName(setting), defaultSetting);
		REPLACE_CHOICE diffSetting = convertTypeToReplaceEnum(defaultApplyFilter, filter);
		if (!diffSetting.equals(optionSetting)) {
			options.setEnum(getOptionName(setting), diffSetting);
		}
	}

	private void saveReplaceOption(Options options, ProgramMergeFilter defaultApplyFilter,
			int setting) {
		REPLACE_CHOICE defaultSetting = REPLACE_CHOICE.REPLACE;
		REPLACE_CHOICE optionSetting = options.getEnum(getOptionName(setting), defaultSetting);
		REPLACE_CHOICE diffSetting =
			convertTypeToReplaceEnum(defaultApplyFilter, getMergeFilterType(setting));
		if (!diffSetting.equals(optionSetting)) {
			options.setEnum(getOptionName(setting), diffSetting);
		}
	}

	private void saveMergeOption(Options options, ProgramMergeFilter defaultApplyFilter, int setting) {
		MERGE_CHOICE defaultSetting = MERGE_CHOICE.MERGE;
		MERGE_CHOICE optionSetting = options.getEnum(getOptionName(setting), defaultSetting);
		MERGE_CHOICE diffSetting =
			convertTypeToMergeEnum(defaultApplyFilter, getMergeFilterType(setting));
		if (!diffSetting.equals(optionSetting)) {
			options.setEnum(getOptionName(setting), diffSetting);
		}
	}

	private void saveSymbolMergeOption(Options options, ProgramMergeFilter defaultApplyFilter,
			int setting) {
		SYMBOL_MERGE_CHOICE defaultSetting = SYMBOL_MERGE_CHOICE.MERGE_AND_SET_PRIMARY;
		SYMBOL_MERGE_CHOICE optionSetting = options.getEnum(getOptionName(setting), defaultSetting);
		SYMBOL_MERGE_CHOICE diffSetting = getSymbolMergeEnum(defaultApplyFilter);
		if (!diffSetting.equals(optionSetting)) {
			options.setEnum(getOptionName(setting), diffSetting);
		}
	}

	/**
	 * @param applySetting
	 * @return
	 */
	private int getMergeFilterType(int applySetting) {
		switch (applySetting) {
			case PROGRAM_CONTEXT:
				return ProgramMergeFilter.PROGRAM_CONTEXT;
			case BYTES:
				return ProgramMergeFilter.BYTES;
			case CODE_UNITS:
				return ProgramMergeFilter.CODE_UNITS;
			case REFERENCES:
				return ProgramMergeFilter.REFERENCES;
			case BOOKMARKS:
				return ProgramMergeFilter.BOOKMARKS;
			case PROPERTIES:
				return ProgramMergeFilter.PROPERTIES;
			case FUNCTIONS:
				return ProgramMergeFilter.FUNCTIONS;
			case PLATE_COMMENTS:
				return ProgramMergeFilter.PLATE_COMMENTS;
			case PRE_COMMENTS:
				return ProgramMergeFilter.PRE_COMMENTS;
			case EOL_COMMENTS:
				return ProgramMergeFilter.EOL_COMMENTS;
			case REPEATABLE_COMMENTS:
				return ProgramMergeFilter.REPEATABLE_COMMENTS;
			case POST_COMMENTS:
				return ProgramMergeFilter.POST_COMMENTS;
			case SYMBOLS:
				return ProgramMergeFilter.SYMBOLS;
			case FUNCTION_TAGS:
				return ProgramMergeFilter.FUNCTION_TAGS;
			default:
				return 0;
		}
	}

	/**
	 * 
	 * @param applySetting
	 * @return
	 */
	private String getOptionName(int applySetting) {
		switch (applySetting) {
			case PROGRAM_CONTEXT:
				return OPTION_PROGRAM_CONTEXT;
			case BYTES:
				return OPTION_BYTES;
			case CODE_UNITS:
				return OPTION_CODE_UNITS;
			case REFERENCES:
				return OPTION_REFERENCES;
			case BOOKMARKS:
				return OPTION_BOOKMARKS;
			case PROPERTIES:
				return OPTION_PROPERTIES;
			case FUNCTIONS:
				return OPTION_FUNCTIONS;
			case PLATE_COMMENTS:
				return OPTION_PLATE_COMMENTS;
			case PRE_COMMENTS:
				return OPTION_PRE_COMMENTS;
			case EOL_COMMENTS:
				return OPTION_EOL_COMMENTS;
			case REPEATABLE_COMMENTS:
				return OPTION_REPEATABLE_COMMENTS;
			case POST_COMMENTS:
				return OPTION_POST_COMMENTS;
			case SYMBOLS:
				return OPTION_SYMBOLS;
			case FUNCTION_TAGS:
				return OPTION_FUNCTION_TAGS;
			default:
				return null;
		}
	}

//	/**
//	 * Converts the current value of the indicated StringEnum to a ProgramMergeFilter type's individual filter setting.
//	 * @param option The StringEnum with a value to be checked.
//	 * @return the individual filter for the apply setting associated with the StringEnum.
//	 */
//	private int convertOptionToFilter(StringEnum option) {
//		return convertIndexToFilter(option.getSelectedValueIndex());
//	}

	/**
	 * Converts the "combined" option for symbols into just the MERGE_CHOICE which is used
	 * to decide if the symbol should be ignored, replaced, or merged.
	 * @param the SYMBOL_MERGE_CHOICE
	 * @return the MERGE_CHOICE 
	 */
	MERGE_CHOICE convertSymbolMergeChoiceToMergeChoice(SYMBOL_MERGE_CHOICE symbolMergeChoice) {
		switch (symbolMergeChoice) {
			default:
			case IGNORE:
				return MERGE_CHOICE.IGNORE;
			case REPLACE:
				return MERGE_CHOICE.REPLACE;
			case MERGE_DONT_SET_PRIMARY:
			case MERGE_AND_SET_PRIMARY:
				return MERGE_CHOICE.MERGE;
		}
	}

	/**
	 * Converts the "combined" option for symbols into just the REPLACE_CHOICE which is used
	 * to decide if the "primary" attribute should be used.
	 * @param the SYMBOL_MERGE_CHOICE
	 * @return the REPLACE_CHOICE 
	 */
	REPLACE_CHOICE convertSymbolMergeChoiceToReplaceChoiceForPrimay(
			SYMBOL_MERGE_CHOICE symbolMergeChoice) {
		switch (symbolMergeChoice) {
			default:
			case IGNORE:
			case MERGE_DONT_SET_PRIMARY:
				return REPLACE_CHOICE.IGNORE;
			case REPLACE:
			case MERGE_AND_SET_PRIMARY:
				return REPLACE_CHOICE.REPLACE;
		}
	}

	/**
	 * Gets the standard index number of a StringEnum for the "Symbols" option for the indicated 
	 * filter values of the symbols apply filter and primary symbol filter.
	 * @param symbolFilter the ProgramMergeFilter.SYMBOLS filter.
	 * @param primaryFilter the ProgramMergeFilter.PRIMARY_SYMBOL filter.
	 * @return the index for setting the StringEnum to the value associated with the filter values.
	 */
	int convertFiltersToSymbolIndex(int symbolFilter, int primaryFilter) {
		switch (symbolFilter) {
			case ProgramMergeFilter.IGNORE:
			default:
				return 0; // Ignore
			case ProgramMergeFilter.REPLACE:
				return 1; // Replace
			case ProgramMergeFilter.MERGE:
				if (primaryFilter == ProgramMergeFilter.REPLACE) {
					return 3; // Merge 2 (Set Primary as in Program 2)
				}
				return 2; // Merge 1 (Set Primary as in Program 1)
		}
	}

	/**
	 * Creates a standard StringEnum for handling an option of the indicated type that allows Ignore and Replace.
	 * The current selected item will be based on the filter's value.
	 * @param defaultApplyFilter the ProgramMergeFilter value to use to select an item initially.
	 * @param type the ProgramMergeFilter filter type
	 * @return the StringEnum
	 */
	private REPLACE_CHOICE convertTypeToReplaceEnum(ProgramMergeFilter defaultApplyFilter, int type) {
		int filter = defaultApplyFilter.getFilter(type);
		return REPLACE_CHOICE.values()[filter];
	}

	/**
	 * Creates a standard StringEnum for handling an option of the indicated type that allows Ignore, Replace and Merge.
	 * The current selected item will be based on the filter's value.
	 * @param defaultApplyFilter the ProgramMergeFilter value to use to select an item initially.
	 * @param type the ProgramMergeFilter filter type
	 * @return the StringEnum
	 */
	private MERGE_CHOICE convertTypeToMergeEnum(ProgramMergeFilter defaultApplyFilter, int type) {
		int filter = defaultApplyFilter.getFilter(type);
		return MERGE_CHOICE.values()[filter];
	}

	/**
	 * Creates a standard StringEnum for the Symbols option.
	 * The current selected item will be based on the filter's value.
	 * @param defaultApplyFilter the ProgramMergeFilter value to use to select an item initially.
	 * @param type the ProgramMergeFilter filter type
	 * @return the StringEnum
	 */
	private SYMBOL_MERGE_CHOICE getSymbolMergeEnum(ProgramMergeFilter defaultApplyFilter) {
		int symbolsFilter = defaultApplyFilter.getFilter(ProgramMergeFilter.SYMBOLS);
		int primarySymbolFilter = defaultApplyFilter.getFilter(ProgramMergeFilter.PRIMARY_SYMBOL);
		int filter = convertFiltersToSymbolIndex(symbolsFilter, primarySymbolFilter);
		return SYMBOL_MERGE_CHOICE.values()[filter];
	}

	public void dispose() {
		// Don't have any options change listeners to clean up.
	}
}
