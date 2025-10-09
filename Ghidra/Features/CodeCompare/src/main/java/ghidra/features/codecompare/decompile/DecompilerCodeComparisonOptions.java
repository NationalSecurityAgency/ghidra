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
package ghidra.features.codecompare.decompile;

import java.awt.Color;

import generic.theme.GColor;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.bean.opteditor.OptionsVetoException;
import utility.function.Callback;
import utility.function.Dummy;

/**
 * This class holds the options for the decompiler diff view.
 */
public class DecompilerCodeComparisonOptions implements OptionsChangeListener {

	private static final String MATCHING_TOKEN_HIGHLIGHT_KEY = "Focused Token Match Highlight";
	private static final String UNMATCHED_TOKEN_HIGHLIGHT_KEY = "Focused Token Unmatched Highlight";
	private static final String INELIGIBLE_TOKEN_HIGHLIGHT_KEY =
		"Focused Token Ineligible Highlight";
	private static final String DIFF_HIGHLIGHT_KEY = "Difference Highlight";

	private static final Color DEFAULT_MATCHING_TOKEN_HIGHLIGHT_COLOR =
		new GColor("color.bg.codecompare.highlight.field.diff.matching");
	private static final Color DEFAULT_UNMATCHED_TOKEN_HIGHLIGHT_COLOR =
		new GColor("color.bg.codecompare.highlight.field.diff.not.matching");
	private static final Color DEFAULT_INELIGIBLE_TOKEN_HIGHLIGHT_COLOR =
		new GColor("color.bg.codecompare.highlight.field.diff.other");
	private static final Color DEFAULT_DIFF_HIGHLIGHT_COLOR =
		new GColor("color.bg.codecompare.highlight.diff");

	private static final String MATCHING_TOKEN_HIGHLIGHT_DESCRIPTION =
		"Highlight Color for Focused Token and Match";
	private static final String UNMATCHED_TOKEN_HIGHLIGHT_DESCRIPTION =
		"Highlight Color for a Focused Token with no Match";
	private static final String INELIGIBLE_TOKEN_HIGHLIGHT_DESCRIPTION =
		"Highlight Color for a Focused Token which is ineligible for a match (e.g., whitespace)";
	private static final String DIFF_HIGHLIGHT_DESCRIPTION = "Highlight Color for Differences";

	private Color matchingTokenHighlight;
	private Color unmatchedTokenHighlight;
	private Color ineligibleTokenHighlight;
	private Color diffHighlight;
	private Callback optionsChangedCallback;

	public static final String OPTIONS_CATEGORY_NAME = "Decompiler Code Comparison";
	public static final String HELP_TOPIC = "FunctionComparison";

	public DecompilerCodeComparisonOptions(PluginTool tool, Callback optionsChangedCallback) {
		this.optionsChangedCallback = Dummy.ifNull(optionsChangedCallback);
		ToolOptions options =
			tool.getOptions(DecompilerCodeComparisonOptions.OPTIONS_CATEGORY_NAME);
		options.addOptionsChangeListener(this);
		registerOptions(options);
		loadOptions(options);
	}

	/**
	 * Register the options
	 * @param options options
	 */
	public void registerOptions(ToolOptions options) {
		HelpLocation help = new HelpLocation(HELP_TOPIC, "Decompiler Code Comparison Options");
		options.setOptionsHelpLocation(help);

		options.registerThemeColorBinding(MATCHING_TOKEN_HIGHLIGHT_KEY,
			"color.bg.codecompare.highlight.field.diff.matching", help,
			MATCHING_TOKEN_HIGHLIGHT_DESCRIPTION);

		options.registerThemeColorBinding(UNMATCHED_TOKEN_HIGHLIGHT_KEY,
			"color.bg.codecompare.highlight.field.diff.not.matching", help,
			UNMATCHED_TOKEN_HIGHLIGHT_DESCRIPTION);

		options.registerThemeColorBinding(INELIGIBLE_TOKEN_HIGHLIGHT_KEY,
			"color.bg.codecompare.highlight.field.diff.other", help,
			INELIGIBLE_TOKEN_HIGHLIGHT_DESCRIPTION);

		options.registerThemeColorBinding(DIFF_HIGHLIGHT_KEY, "color.bg.codecompare.highlight.diff",
			help, DIFF_HIGHLIGHT_DESCRIPTION);

	}

	/**
	 * Read the options
	 * @param options options
	 */
	public void loadOptions(ToolOptions options) {
		matchingTokenHighlight =
			options.getColor(MATCHING_TOKEN_HIGHLIGHT_KEY, DEFAULT_MATCHING_TOKEN_HIGHLIGHT_COLOR);
		unmatchedTokenHighlight = options.getColor(UNMATCHED_TOKEN_HIGHLIGHT_KEY,
			DEFAULT_UNMATCHED_TOKEN_HIGHLIGHT_COLOR);
		ineligibleTokenHighlight = options.getColor(INELIGIBLE_TOKEN_HIGHLIGHT_KEY,
			DEFAULT_INELIGIBLE_TOKEN_HIGHLIGHT_COLOR);
		diffHighlight = options.getColor(DIFF_HIGHLIGHT_KEY, DEFAULT_DIFF_HIGHLIGHT_COLOR);
	}

	/**
	 * Returns the color used to highlight matches of the focused token
	 * @return match color
	 */
	public Color getFocusedTokenMatchHighlightColor() {
		return matchingTokenHighlight;
	}

	/**
	 * Returns the color used to highlight the focuses token when it does not have a match
	 * @return unmatched color
	 */
	public Color getFocusedTokenUnmatchedHighlightColor() {
		return unmatchedTokenHighlight;
	}

	/**
	 * Returns the color used to highlight the focused token when it is not eligible for a match
	 * (e.g., a whitespace token)
	 * @return ineligible color
	 */
	public Color getFocusedTokenIneligibleHighlightColor() {
		return ineligibleTokenHighlight;
	}

	/**
	 * Returns the color used to highlight differences between the two decompiled functions
	 * @return difference color
	 */
	public Color getDiffHighlightColor() {
		return diffHighlight;
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		loadOptions(options);
		optionsChangedCallback.call();
	}

	public void dispose(PluginTool tool) {
		ToolOptions options =
			tool.getOptions(DecompilerCodeComparisonOptions.OPTIONS_CATEGORY_NAME);
		options.removeOptionsChangeListener(this);
	}
}
