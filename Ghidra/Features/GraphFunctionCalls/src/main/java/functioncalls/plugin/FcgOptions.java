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
package functioncalls.plugin;

import ghidra.framework.options.Options;
import ghidra.graph.viewer.options.VisualGraphOptions;
import ghidra.util.HelpLocation;

public class FcgOptions extends VisualGraphOptions {

	public static final String FUNCTION_NAME_TRUNCATION_KEY = "Truncate Function Name";
	public static final String FUNCTDION_NAME_TRUNCTION_DESCRIPTION =
		"Long function names will be truncated";

	private boolean useTruncatedFunctionNames = true;

	public boolean useTruncatedFunctionNames() {
		return useTruncatedFunctionNames;
	}

	public void setUseTruncatedFunctionNames(boolean b) {
		this.useTruncatedFunctionNames = b;
	}

	@Override
	public void registerOptions(Options options, HelpLocation help) {
		super.registerOptions(options, help);

		options.registerOption(FUNCTION_NAME_TRUNCATION_KEY, useTruncatedFunctionNames(), help,
			FUNCTDION_NAME_TRUNCTION_DESCRIPTION);
	}

	@Override
	public void loadOptions(Options options) {
		useTruncatedFunctionNames =
			options.getBoolean(FUNCTION_NAME_TRUNCATION_KEY, useTruncatedFunctionNames);
	}
}
