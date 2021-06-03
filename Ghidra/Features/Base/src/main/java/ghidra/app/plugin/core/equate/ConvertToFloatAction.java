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

import java.math.BigDecimal;

import ghidra.pcode.floatformat.*;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;

public class ConvertToFloatAction extends AbstractConvertAction {

	public ConvertToFloatAction(EquatePlugin plugin) {
		super(plugin, "Convert To Float", false);
	}

	@Override
	protected String getMenuName(Program program, Scalar scalar, boolean isData) {
		String valueString = convertToString(program, scalar, isData);
		if (valueString == null) {
			return null;
		}
		return getStandardLengthString("Float:") + valueString;
	}

	private static BigDecimal value(Program program, Scalar s) {
		DataOrganization dataOrganization = program.getDataTypeManager().getDataOrganization();
		try {
			FloatFormat format = FloatFormatFactory.getFloatFormat(dataOrganization.getFloatSize());
			return format.round(format.getHostFloat(s.getBigInteger()));
		}
		catch (UnsupportedFloatFormatException e) {
			return null;
		}
	}

	@Override
	protected String convertToString(Program program, Scalar scalar, boolean isData) {
		if (isData) {
			return null; // unsupported
		}
		BigDecimal value = value(program, scalar);
		return value != null ? value.toString() : null;
	}

	@Override
	protected int getFormatChoice() {
		return -1; // unsupported for data
	}
}
