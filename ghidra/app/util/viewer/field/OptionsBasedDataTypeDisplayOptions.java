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
package ghidra.app.util.viewer.field;

import ghidra.GhidraOptions;
import ghidra.framework.options.Options;
import ghidra.program.model.data.DataTypeDisplayOptions;

public class OptionsBasedDataTypeDisplayOptions implements DataTypeDisplayOptions {

	/**
	 * Option for controlling the default display options.
	 */
	public static final String DISPLAY_ABBREVIATED_DEFAULT_LABELS =
			GhidraOptions.OPERAND_GROUP_TITLE + Options.DELIMITER +
			"Display Abbreviated Default Label Names";

	public static final String MAXIMUM_DEFAULT_LABEL_LENGTH = GhidraOptions.OPERAND_GROUP_TITLE +
			Options.DELIMITER + "Maximum Length of String in Default Labels";

	private final Options options;

	public OptionsBasedDataTypeDisplayOptions(Options options) {
		this.options = options;

// TODO
//		fieldOptions.setHelpLocation(NAMESPACE_OPTIONS, new HelpLocation("CodeBrowserPlugin",
//				"Operands_Field"));

		// register the options
		options.registerOption(DISPLAY_ABBREVIATED_DEFAULT_LABELS, false, null,
			"Uses a shortened form of the " +
				"label name for dynamic String data types in the display of " +
				"operand references (e.g., STR_01234567)");
		options.registerOption(MAXIMUM_DEFAULT_LABEL_LENGTH,
			DataTypeDisplayOptions.MAX_LABEL_STRING_LENGTH, null,
			"Sets the maximumn number of characters from a String to include in dynamic " +
				"String labels in operand references");
	}

	@Override
	public int getLabelStringLength() {
		return options.getInt(MAXIMUM_DEFAULT_LABEL_LENGTH,
			DataTypeDisplayOptions.MAX_LABEL_STRING_LENGTH);
	}

	@Override
	public boolean useAbbreviatedForm() {
		return options.getBoolean(DISPLAY_ABBREVIATED_DEFAULT_LABELS, false);
	}
}
