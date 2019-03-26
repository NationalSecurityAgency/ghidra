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
import ghidra.util.StringUtilities;

public class ConvertToBinaryAction extends AbstractConvertAction {

	public ConvertToBinaryAction(EquatePlugin plugin) {
		super(plugin, "Convert To Unsigned Binary", false);
	}

	@Override
	protected String getMenuName(Program program, Scalar scalar, boolean isData) {
		return getStandardLengthString("Unsigned Binary:") +
			convertToString(program, scalar, isData);
	}

	@Override
	protected String convertToString(Program program, Scalar scalar, boolean isData) {
		String valueStr = Long.toBinaryString(scalar.getUnsignedValue());
		valueStr = StringUtilities.pad(valueStr, '0', scalar.bitLength());
		return valueStr + "b";
	}

	@Override
	protected int getFormatChoice() {
		return FormatSettingsDefinition.BINARY;
	}
}
