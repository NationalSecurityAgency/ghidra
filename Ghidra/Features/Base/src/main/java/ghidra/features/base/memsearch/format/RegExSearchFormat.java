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
package ghidra.features.base.memsearch.format;

import java.util.regex.PatternSyntaxException;

import ghidra.features.base.memsearch.gui.SearchSettings;
import ghidra.features.base.memsearch.matcher.*;

/**
 * {@link SearchFormat} for parsing input as a regular expression. This format can't generate
 * bytes or parse results.
 */
class RegExSearchFormat extends SearchFormat {
	RegExSearchFormat() {
		super("Reg Ex");
	}

	@Override
	public ByteMatcher parse(String input, SearchSettings settings) {
		input = input.trim();
		if (input.isBlank()) {
			return new InvalidByteMatcher("");
		}

		try {
			return new RegExByteMatcher(input, settings);
		}
		catch (PatternSyntaxException e) {
			return new InvalidByteMatcher("RegEx Pattern Error: " + e.getDescription(), true);
		}
	}

	@Override
	public String getToolTip() {
		return "Interpret value as a regular expression.";
	}

	@Override
	public String getValueString(byte[] bytes, SearchSettings settings) {
		return new String(bytes);
	}

	@Override
	public String convertText(String text, SearchSettings oldSettings, SearchSettings newSettings) {
		return isValidText(text, newSettings) ? text : "";
	}

	@Override
	public SearchFormatType getFormatType() {
		return SearchFormatType.STRING_TYPE;
	}
}
