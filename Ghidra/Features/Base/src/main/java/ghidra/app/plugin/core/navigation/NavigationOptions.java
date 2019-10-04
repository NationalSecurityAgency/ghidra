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

import ghidra.GhidraOptions;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.util.HelpLocation;

public class NavigationOptions implements OptionsChangeListener {

	static final String NAVIGATION_TOPIC = "Navigation";

	static final String NAVIGATION_OPTIONS = GhidraOptions.NAVIGATION_OPTIONS;

	static final String NAVIGATION_RANGE_OPTION = GhidraOptions.NAVIGATION_RANGE_OPTION;

	static final String NAVIGATION_RANGE_DESCRIPTION = "Determines how navigation of ranges " +
		"(i.e., selection ranges and highlight ranges) takes place.  By default, navigating " +
		"to ranges will place the cursor at the top of the " +
		"next range.  You may use this option to navigate to both the top and the bottom of each " +
		"range being navigated.";

	public static enum RangeNavigationEnum {
		TopOfRangeOnly("Top of Range Only"), TopAndBottomOfRange("Top and Bottom of Range");

		private String label;

		private RangeNavigationEnum(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	static final String EXTERNAL_NAVIGATION_OPTION = GhidraOptions.EXTERNAL_NAVIGATION_OPTION;

	static final String EXTERNAL_NAVIGATION_DESCRIPTION =
		"Determines the behavior for navigation to external symbols and references. " +
			"By default, navigating to an external will attempt to navigate within the " +
			"current program to the first linkage reference (pointer or thunk).  " +
			"Alternatively, if an external program has been associated with an " +
			"import Library, then that program will be opened and positioned to the selected " +
			"external location if found.";

	public static enum ExternalNavigationEnum {
		NavigateToLinkage("Navigate to Linkage"),
		NavigateToExternalProgram("Navigate to External Program");

		private String label;

		private ExternalNavigationEnum(String label) {
			this.label = label;
		}

		@Override
		public String toString() {
			return label;
		}
	}

	static final String FOLLOW_INDIRECTION_NAVIGATION_OPTION =
		GhidraOptions.FOLLOW_INDIRECTION_NAVIGATION_OPTION;

	static final String FOLLOW_INDIRECTION_NAVIGATION_DESCRIPTION =
		"Determines the behavior for navigation on indirect flow references. " +
			"By default, this option is disabled providing navigation to the " +
			"referenced pointer data.  If enabled, the pointer will be followed " +
			"to its referenced destination if contained within the program's memory.";

	static final String ASSUME_CURRENT_ADDRESS_SPACE = "Prefer Current Address Space";
	private static final String ASSUME_CURRENT_ADDRESS_SPACE_DESCRIPTION =
		"Determines if the 'Go To' action prefers the current address space when entering address offsets. " +
			"For example, if your program has multiple address spaces such as 'RAM' or 'DATA' and you  " +
			"enter 1000 into the 'Go To' field, you could mean RAM:1000 or DATA:1000.  If this option " +
			"is on, then it will go to the address with the address space that matches the current " +
			"cursor location.  Otherwise, it will show a list of possible addresses for the given offset. " +
			"The default is on for this option.";

	private final String RESTRICT_GOTO_CURRENT_TAB = "'Go To' in Current Program Only";
	private static final String RESTRICT_GOTO_CURRENT_TAB_DESCRIPTION = "Determines if the " +
		"'Go To' service will only search for and navigate to labels in the current program. " +
		"If this option is off and the search label is not found in the current program, the " +
		"'Go To' action will search other open programs, " +
		"possibly resulting in the listing view switching to a different open program tab. " +
		"By default, this option is on, thereby guaranteeing that the listing view will not " +
		"change to a different program when performing a 'Go To' action.";

	private boolean gotoTopAndBottom;
	private boolean gotoExternalProgram;
	private boolean followIndirectReferences;
	private ToolOptions options;
	private boolean preferCurrentAddressSpace;
	private boolean restrictGotoToCurrentProgram;

	public NavigationOptions(PluginTool tool) {
		this(tool.getOptions(NavigationOptions.NAVIGATION_OPTIONS));
	}

	public NavigationOptions(OptionsService optionsService) {
		this(optionsService.getOptions(NavigationOptions.NAVIGATION_OPTIONS));
	}

	private NavigationOptions(ToolOptions options) {

		this.options = options;

		HelpLocation help = new HelpLocation(NAVIGATION_TOPIC, "Navigation_Options");
		options.registerOption(NavigationOptions.NAVIGATION_RANGE_OPTION,
			RangeNavigationEnum.TopOfRangeOnly, help,
			NavigationOptions.NAVIGATION_RANGE_DESCRIPTION);
		RangeNavigationEnum rangeNavigationOption = options.getEnum(
			NavigationOptions.NAVIGATION_RANGE_OPTION, RangeNavigationEnum.TopOfRangeOnly);
		gotoTopAndBottom = (rangeNavigationOption == RangeNavigationEnum.TopAndBottomOfRange);

		options.registerOption(NavigationOptions.EXTERNAL_NAVIGATION_OPTION,
			ExternalNavigationEnum.NavigateToLinkage, help,
			NavigationOptions.EXTERNAL_NAVIGATION_DESCRIPTION);
		ExternalNavigationEnum externalNavigationOption = options.getEnum(
			NavigationOptions.EXTERNAL_NAVIGATION_OPTION, ExternalNavigationEnum.NavigateToLinkage);
		gotoExternalProgram =
			(externalNavigationOption == ExternalNavigationEnum.NavigateToExternalProgram);

		options.registerOption(NavigationOptions.FOLLOW_INDIRECTION_NAVIGATION_OPTION, false, help,
			NavigationOptions.FOLLOW_INDIRECTION_NAVIGATION_DESCRIPTION);
		followIndirectReferences =
			options.getBoolean(NavigationOptions.FOLLOW_INDIRECTION_NAVIGATION_OPTION, false);

		options.registerOption(ASSUME_CURRENT_ADDRESS_SPACE, true, help,
			ASSUME_CURRENT_ADDRESS_SPACE_DESCRIPTION);

		preferCurrentAddressSpace = options.getBoolean(ASSUME_CURRENT_ADDRESS_SPACE, true);

		options.registerOption(RESTRICT_GOTO_CURRENT_TAB, true, help,
			RESTRICT_GOTO_CURRENT_TAB_DESCRIPTION);

		restrictGotoToCurrentProgram = options.getBoolean(RESTRICT_GOTO_CURRENT_TAB, true);

		options.addOptionsChangeListener(this);
	}

	public void dispose() {
		options.removeOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions toolOptions, String optionName, Object oldValue,
			Object newValue) {
		if (NavigationOptions.NAVIGATION_RANGE_OPTION.equals(optionName)) {
			RangeNavigationEnum rangeNavigationOption = (RangeNavigationEnum) newValue;
			gotoTopAndBottom = (rangeNavigationOption == RangeNavigationEnum.TopAndBottomOfRange);
		}
		else if (EXTERNAL_NAVIGATION_OPTION.equals(optionName)) {
			ExternalNavigationEnum externalNavigationOption = (ExternalNavigationEnum) newValue;
			gotoExternalProgram =
				(externalNavigationOption == ExternalNavigationEnum.NavigateToExternalProgram);
		}
		else if (FOLLOW_INDIRECTION_NAVIGATION_OPTION.equals(optionName)) {
			followIndirectReferences = (Boolean) newValue;
		}
		else if (ASSUME_CURRENT_ADDRESS_SPACE.equals(optionName)) {
			preferCurrentAddressSpace = (Boolean) newValue;
		}
		else if (RESTRICT_GOTO_CURRENT_TAB.contentEquals(optionName)) {
			restrictGotoToCurrentProgram = (Boolean) newValue;
		}
	}

	public boolean isGotoTopAndBottomOfRangeEnabled() {
		return gotoTopAndBottom;
	}

	public boolean isGotoExternalProgramEnabled() {
		return gotoExternalProgram;
	}

	public boolean isFollowIndirectionEnabled() {
		return followIndirectReferences;
	}

	public boolean preferCurrentAddressSpace() {
		return preferCurrentAddressSpace;
	}

	public boolean isGoToRestrictedToCurrentProgram() {
		return restrictGotoToCurrentProgram;
	}
}
