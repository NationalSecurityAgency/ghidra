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
package ghidra.app.plugin.core.equate;

import ghidra.docking.settings.FormatSettingsDefinition;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

public class ConvertToSignedHexAction extends AbstractConvertAction {
	public final static String ACTION_NAME = "Convert To Signed Hex";

	public ConvertToSignedHexAction(EquatePlugin plugin) {
		super(plugin, ACTION_NAME, true);
	}

	@Override
	protected String getMenuName(Program program, Scalar scalar, boolean isData) {
		return getStandardLengthString("Signed Hex:") + convertToString(program, scalar, isData);
	}

	@Override
	protected String convertToString(Program program, Scalar scalar, boolean isData) {
		if (isData) {
			return null; // unsupported
		}
		long v = scalar.getSignedValue();
		String valueStr = Long.toString(v, 16).toUpperCase();
		if (v < 0) {
			// use of substring removes '-' prefix for negative value
			return "-0x" + valueStr.substring(1);
		}
		return "0x" + valueStr;
	}

	@Override
	protected int getFormatChoice() {
		return FormatSettingsDefinition.HEX;
	}

}
