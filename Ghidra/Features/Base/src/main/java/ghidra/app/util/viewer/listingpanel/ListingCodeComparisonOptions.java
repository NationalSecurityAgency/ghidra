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
package ghidra.app.util.viewer.listingpanel;

import java.awt.Color;

import generic.theme.GColor;
import ghidra.framework.options.ToolOptions;
import ghidra.util.HelpLocation;

public class ListingCodeComparisonOptions {

	public static final String OPTIONS_CATEGORY_NAME = "Listing Code Comparison";
	public static final String HELP_TOPIC = "Listing Code Comparison";

	private static final String BYTE_DIFFS_COLOR_KEY = "Byte Differences Color";
	private static final String MNEMONIC_DIFFS_COLOR_KEY = "Mnemonic Differences Color";
	private static final String OPERAND_DIFFS_COLOR_KEY = "Operand Differences Color";
	private static final String UNMATCHED_CODE_UNITS_COLOR_KEY = "Unmatched Code Units Color";
	private static final String DIFF_CODE_UNITS_COLOR_KEY = "Differing Code Units Color";

	private static final String DEFAULT_BYTE_DIFFS_BACKGROUND_COLOR_DESCRIPTION =
		"The default background color applied to byte differences within the listing code comparison window.";
	private static final String DEFAULT_MNEMONIC_DIFFS_BACKGROUND_COLOR_DESCRIPTION =
		"The default background color applied to mnemonic differences for matched addresses within the listing code comparison window.";
	private static final String DEFAULT_OPERAND_DIFFS_BACKGROUND_COLOR_DESCRIPTION =
		"The default background color applied to operand differences within the listing code comparison window.";
	private static final String DEFAULT_DIFF_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION =
		"The default background color applied to code units with any detected differences within the listing code comparison window.";
	private static final String DEFAULT_UNMATCHED_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION =
		"The default background color applied to code units that are unmatched within the listing code comparison window by the address correlator.";

	private static final Color DEFAULT_BYTE_DIFFS_COLOR =
		new GColor("color.bg.listing.comparison.bytes");
	private static final Color DEFAULT_MNEMONIC_DIFFS_COLOR =
		new GColor("color.bg.listing.comparison.mnemonic");
	private static final Color DEFAULT_OPERAND_DIFFS_COLOR =
		new GColor("color.bg.listing.comparison.operand");
	private static final Color DEFAULT_DIFF_CODE_UNITS_COLOR =
		new GColor("color.bg.listing.comparison.code.units.diff");
	private static final Color DEFAULT_UNMATCHED_CODE_UNITS_COLOR =
		new GColor("color.bg.listing.comparison.code.units.unmatched");

	private Color byteDiffsColor = DEFAULT_BYTE_DIFFS_COLOR;
	private Color mnemonicDiffsColor = DEFAULT_MNEMONIC_DIFFS_COLOR;
	private Color operandDiffsColor = DEFAULT_OPERAND_DIFFS_COLOR;
	private Color diffCodeUnitsColor = DEFAULT_DIFF_CODE_UNITS_COLOR;
	private Color unmatchedCodeUnitsColor = DEFAULT_UNMATCHED_CODE_UNITS_COLOR;

	public Color getDefaultByteDiffsBackgroundColor() {
		return DEFAULT_BYTE_DIFFS_COLOR;
	}

	public Color getDefaultMnemonicDiffsBackgroundColor() {
		return DEFAULT_MNEMONIC_DIFFS_COLOR;
	}

	public Color getDefaultOperandDiffsBackgroundColor() {
		return DEFAULT_OPERAND_DIFFS_COLOR;
	}

	public Color getDefaultDiffCodeUnitsBackgroundColor() {
		return DEFAULT_DIFF_CODE_UNITS_COLOR;
	}

	public Color getDefaultUnmatchedCodeUnitsBackgroundColor() {
		return DEFAULT_UNMATCHED_CODE_UNITS_COLOR;
	}

	public Color getByteDiffsBackgroundColor() {
		return byteDiffsColor;
	}

	public Color getMnemonicDiffsBackgroundColor() {
		return mnemonicDiffsColor;
	}

	public Color getOperandDiffsBackgroundColor() {
		return operandDiffsColor;
	}

	public Color getDiffCodeUnitsBackgroundColor() {
		return diffCodeUnitsColor;
	}

	public Color getUnmatchedCodeUnitsBackgroundColor() {
		return unmatchedCodeUnitsColor;
	}

	public void initializeOptions(ToolOptions options) {
		HelpLocation help = new HelpLocation(HELP_TOPIC, "Options");
		options.setOptionsHelpLocation(help);

		options.registerThemeColorBinding(BYTE_DIFFS_COLOR_KEY, "color.bg.listing.comparison.bytes",
			help, DEFAULT_BYTE_DIFFS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerThemeColorBinding(MNEMONIC_DIFFS_COLOR_KEY,
			"color.bg.listing.comparison.mnemonic",
			help, DEFAULT_MNEMONIC_DIFFS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerThemeColorBinding(OPERAND_DIFFS_COLOR_KEY,
			"color.bg.listing.comparison.operand", help,
			DEFAULT_OPERAND_DIFFS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerThemeColorBinding(DIFF_CODE_UNITS_COLOR_KEY,
			"color.bg.listing.comparison.code.units.diff", help,
			DEFAULT_DIFF_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerThemeColorBinding(UNMATCHED_CODE_UNITS_COLOR_KEY,
			"color.bg.listing.comparison.code.units.unmatched",
			help, DEFAULT_UNMATCHED_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION);
	}

	public void loadOptions(ToolOptions options) {
		byteDiffsColor = options.getColor(BYTE_DIFFS_COLOR_KEY, DEFAULT_BYTE_DIFFS_COLOR);

		mnemonicDiffsColor =
			options.getColor(MNEMONIC_DIFFS_COLOR_KEY, DEFAULT_MNEMONIC_DIFFS_COLOR);

		operandDiffsColor = options.getColor(OPERAND_DIFFS_COLOR_KEY, DEFAULT_OPERAND_DIFFS_COLOR);

		diffCodeUnitsColor =
			options.getColor(DIFF_CODE_UNITS_COLOR_KEY, DEFAULT_DIFF_CODE_UNITS_COLOR);

		unmatchedCodeUnitsColor =
			options.getColor(UNMATCHED_CODE_UNITS_COLOR_KEY, DEFAULT_UNMATCHED_CODE_UNITS_COLOR);
	}
}
