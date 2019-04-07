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

	public static final Color MEDIUM_SKY_BLUE_COLOR = new Color(0x69, 0xcd, 0xe1);
	public static final Color MEDIUM_GRAY_COLOR = new Color(0xb9, 0xb9, 0xb9);
	public static final Color SPRING_GREEN_COLOR = new Color(0xaf, 0xff, 0x69);

	private static final Color DEFAULT_BYTE_DIFFS_COLOR = SPRING_GREEN_COLOR;
	private static final Color DEFAULT_MNEMONIC_DIFFS_COLOR = SPRING_GREEN_COLOR;
	private static final Color DEFAULT_OPERAND_DIFFS_COLOR = SPRING_GREEN_COLOR;
	private static final Color DEFAULT_DIFF_CODE_UNITS_COLOR = MEDIUM_GRAY_COLOR;
	private static final Color DEFAULT_UNMATCHED_CODE_UNITS_COLOR = MEDIUM_SKY_BLUE_COLOR;

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

		options.registerOption(BYTE_DIFFS_COLOR_KEY, DEFAULT_BYTE_DIFFS_COLOR, help,
			DEFAULT_BYTE_DIFFS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerOption(MNEMONIC_DIFFS_COLOR_KEY, DEFAULT_MNEMONIC_DIFFS_COLOR, help,
			DEFAULT_MNEMONIC_DIFFS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerOption(OPERAND_DIFFS_COLOR_KEY, DEFAULT_OPERAND_DIFFS_COLOR, help,
			DEFAULT_OPERAND_DIFFS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerOption(DIFF_CODE_UNITS_COLOR_KEY, DEFAULT_DIFF_CODE_UNITS_COLOR, help,
			DEFAULT_DIFF_CODE_UNITS_BACKGROUND_COLOR_DESCRIPTION);

		options.registerOption(UNMATCHED_CODE_UNITS_COLOR_KEY, DEFAULT_UNMATCHED_CODE_UNITS_COLOR,
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
